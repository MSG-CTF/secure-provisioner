# 포트별 공개 지원 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 기존 Runtime 요청을 유지하면서 WEB 컨테이너의 일부 포트만 공개한다.

**Architecture:** HTTP 경계에서 `expose`와 `exposed_ports`를 구분하고 검증한다. 기존 전체 공개 표현과 저장 JSON은 유지하고, 혼합 공개 목록은 Domain·정책·Operation·Binding에 보존한다. 혼합 컨테이너만 내부 Service와 공개 Service로 분리한다.

**Tech Stack:** Go, net/http, client-go, PostgreSQL JSON payload.

**Spec:** 일기장 「Runtime 포트 공개 계약 변경 정리 (2026-09-06)」 및 GitHub #38.

## Global Constraints

- `expose`와 `exposed_ports` 동시 지정은 false/null도 포함해 거절한다.
- `exposed_ports`는 중복 없는 `ports` 부분집합이다. 빈 배열은 private, null은 잘못된 신규 입력이다.
- 기존 expose null/생략은 private인 현재 호환성을 유지한다.
- 공개 목록 순서는 ports 순서로 정규화한다. 전체 공개/전체 private는 기존 Domain 표현으로 정규화해 재전송 호환성을 유지한다.
- PWN 공개 컨테이너의 추가 private 포트는 허용하지 않는다. 기존 보안 제한을 유지한다.
- 기존 bool 저장 필드는 legacy decode와 spec hash 호환성 때문에 유지한다. 모든 공개 판단은 PublicPorts()를 통한다.
- Scheduler 기존 수정본, token, 배포 환경은 변경하지 않는다. Scheduler 신규 필드 송신 전환은 별도 변경이다.
- 실제 K3s 검증과 fake client 테스트 결과를 구분한다.

### Task 1: HTTP·Domain·정책·저장 호환

Files: internal/httpapi/create.go, internal/provisioner/create.go, internal/isolation/{profile,static_resolver}.go, internal/operations/operation.go, internal/runtimebinding/binding.go 및 테스트.

- [x] JSON `ports:[8080,9000], exposed_ports:[8080]`를 받는 실패 테스트를 먼저 작성하고 `go test ./internal/httpapi -run Exposure`로 unknown field 실패를 확인한다.
- [x] RuntimeContainer에 공개 목록과 두 필드의 wire presence 검증을 추가한다.
- [x] WorkloadContainer와 ContainerRequirement에 `ExposedPorts []int`와 `PublicPorts() []int`를 추가한다. 기존 nil 목록은 Expose bool에서 해석한다.
- [x] 부분집합·중복·범위, PWN 제한, command/정책 일치 검증을 추가한다.
- [x] operation/binding deep copy와 idempotency, PostgreSQL JSON round-trip 회귀 테스트를 작성하고 통과시킨다.

### Task 2: 혼합 컨테이너의 K3s 리소스

Files: internal/k3s/{resources,security_resources,network_policies}.go 및 테스트.

- [x] 실제 builder 테스트에서 내부 ClusterIP 8080/9000, 공개 Service 8080만을 요구하고 실패를 확인한다.
- [x] 혼합 컨테이너만 Service를 분리한다. 내부 이름은 기존 컨테이너 이름, 공개 이름은 전체 컨테이너 이름과 충돌하지 않는 결정적 짧은 이름을 사용한다.
- [x] NodePort/Ingress 및 public NetworkPolicy는 공개 포트만 사용한다. 내부 통신은 기존 정책을 유지한다.
- [x] ResourceQuota의 services 수를 실제 생성 수에 맞춘다. NodePort quota는 기존 상한 방식에서 공개 포트 수만 집계한다.
- [x] endpoints·readiness·retry·delete 회귀를 검증한다. legacy spec hash는 변경하지 않는다.

### Task 3: 명세 및 최종 검증

Files: docs/api/runtime-operations.md, docs/api/secure-provisioner.openapi.yaml.

- [x] 신규 필드, 상호 배타성, 혼합 JSON 예시, Provisioner 선배포 및 Scheduler 후속 작업을 설명한다.
- [x] `go test ./...`, `go test -race ./...`, `go vet ./...`, `git diff --check` 실행 결과를 확인한다.
- [x] 코드 리뷰에서 공개 포트 유출, 저장 손실, legacy 재시도 호환성을 확인한다.
- [x] 실제 K3s smoke 미실행과 Scheduler 미변경을 인계한다.

## 실행 결과 — 2026-09-06

- 브랜치: `feat/38-mixed-port-exposure`, 기준 dev `2ed26cb`, 이슈 #38. 최초 구현 검증 시점에는 커밋·push·PR·배포를 하지 않았다.
- `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, `git diff --check` 통과.
- 실제 임시 PostgreSQL 17에서 `PROVISIONER_TEST_DATABASE_URL`을 지정한 `go test -race ./internal/runtimepg -count=1 -v` 통과. 테스트용 컨테이너와 임시 DB는 실행 후 정리했다.
- `npx --yes @redocly/cli@2.0.0 lint --extends minimal docs/api/secure-provisioner.openapi.yaml` 통과, 경고 0개.
- 별도 읽기 전용 코드 리뷰에서 결함 없음. 기존 literal spec hash, 혼합 Service 이름 충돌, 공개 Service 미준비 시 실패·rollback 회귀 포함.
- 추가 Service까지 CREATE readiness가 검사하며 status는 실제 Ingress backend/NodePort Service 목록을 사용한다. DELETE는 기존 Namespace UID 단위 정리를 유지한다.
- 실제 K3s 네트워크·Ingress·NodePort 접근 차단은 미검증이다. DevOps 배포 주소·target_id·token 전달 경로가 여전히 필요하다.
- Scheduler는 수정하지 않았다. 양쪽 연동 완료를 위해 입력 DTO·DB JSON 호환 decode·Runtime DTO의 exposed_ports 전달이 후속 작업이다. Provisioner를 먼저 배포한다.

## PR 제출 준비 — 2026-09-06

- 사용자 요청에 따라 기존 변경을 `dev` 대상 Draft PR로 제출한다. 최신 원격 `dev`가 기준 커밋 `2ed26cb`와 같은 것을 확인했다.
- 공개 2개(8080·9090)와 private 1개(9000)를 가진 동일 WEB 컨테이너의 NodePort·Ingress 회귀 테스트를 추가했다. 두 공개 URL 전체, 컨테이너 이름·내부 포트, private 제외와 Ingress 대표 URL을 검증한다.
- Runtime API 문서에 두 URL을 반환하는 `result.endpoints[]` 예시와 필수 필드·대표 `service_url` 설명을 추가했다.
- 최종 코드의 `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, Go formatting 및 `git diff --check`를 재검증했다.
- 별도 임시 PostgreSQL 17에서 `go test -race ./internal/runtimepg -count=1 -v` 9개 테스트가 통과했다. 운영 DB는 사용하지 않았다.
- OpenAPI lint 및 혼합 생성 요청·다중 URL 결과 예시의 JSON Schema 검증이 통과했다.
- 별도 읽기 전용 코드 리뷰에서 지적사항이 없었다. Scheduler 변경, 실제 K3s smoke, 병합·배포는 이번 PR 제출 범위에 포함하지 않는다.
