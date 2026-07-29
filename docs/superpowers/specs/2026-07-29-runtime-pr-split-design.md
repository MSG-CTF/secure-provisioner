# 비동기 런타임 PR 분할 설계

## 목적

기존 Draft PR #28의 비동기 생성·삭제·상태 조회 변경을 리뷰 가능한 기능 단위로
분리한다. 기능 동작과 Scheduler 계약은 유지하고, 생성·삭제·조회 각각의 변경과
테스트·문서를 해당 PR에서 함께 확인할 수 있게 한다.

## 현재 기준

- 대상 저장소: `MSG-CTF/secure-provisioner`
- 기존 Draft PR: #28 `Feat: 비동기 런타임 작업과 상태 조회 API`
- 기준 브랜치: `dev`
- 선행 구현:
  - #17 Operation Worker 재시도·중복 요청 처리
  - #18 / PR #23 `target_id` 기반 K3s 생성 Adapter
- Scheduler 저장소와 로컬 테스트용 대시보드는 변경하지 않는다.
- 기존 PR #28은 새 Draft PR 세 개를 모두 게시하고 상호 링크를 확인한 뒤 닫는다.

## 선택한 방식

공통 Runtime Binding과 Operation 조회 코드가 생성·삭제·조회에서 공유되므로 세
PR을 stacked 구조로 만든다. 각 PR은 직전 PR 브랜치를 base로 하며, 선행 PR이
`dev`에 병합되면 다음 PR의 base를 `dev`로 변경한다.

```text
dev
 └─ PR A: 비동기 생성·Operation 조회
     └─ PR B: 비동기 삭제
         └─ PR C: 런타임 상태·자원 조회
```

모든 PR을 `dev` 기준의 독립 PR로 만들지 않는다. 그렇게 하면 Runtime Binding,
HTTP handler, Runtime Service, OpenAPI 파일의 공통 변경이 중복되어 병합 순서에
따라 충돌하거나 이미 리뷰한 코드가 다시 나타난다.

## PR A: 비동기 생성·Operation 조회

### 브랜치와 이슈

- 브랜치: `feat/26-async-runtime-create`
- base: `dev`
- 제목: `Feat: 비동기 런타임 생성과 Operation 조회`
- `Closes #26`
- `Refs #17`, `Refs #18`, `Refs #24`

### 포함 범위

- `POST /internal/v1/instances`를 HTTP `202 Accepted` 비동기 접수로 변경
- `GET /internal/v1/operations/{operation_id}` 추가
- `QUEUED`, `RUNNING`, `RETRYING`, `SUCCEEDED`, `FAILED` 응답
- `Location`, `Retry-After`, `created` 응답
- 동일 `request_id` 멱등 처리와 다른 payload 충돌 처리
- 생성 성공 결과의 `runtime_workload_id`, `service_url`
- 생성 성공 후 Instance Runtime Binding 저장
- Registry 설정 파일을 `PROVISIONER_CLUSTER_REGISTRY`로 주입
- `cmd/provisioner`에서 Registry, K3s 생성 Adapter, Operation Worker, HTTP API 연결
- 생성·Operation 오류 envelope와 `last_error_code`
- 생성·Operation OpenAPI, Markdown, README와 회귀 테스트

### 제외 범위

- DELETE API와 실제 Namespace 삭제
- 런타임 상태·자원 조회 API
- Metrics Client
- Scheduler 코드와 DB 상태 전이
- AWS/GCP VM 자체 생성·삭제
- 로컬 대시보드

## PR B: 비동기 삭제

### 브랜치와 이슈

- 브랜치: `feat/16-async-runtime-delete`
- base: `feat/26-async-runtime-create`
- 제목: `Feat: 비동기 런타임 삭제`
- `Closes #16`
- `Refs #17`, `Refs #24`, `Refs #26`

### 포함 범위

- `DELETE /internal/v1/instances/{instance_id}` 추가
- 저장된 Binding과 요청의 `instance_id`, `team_id`, `target_id`,
  `runtime_workload_id` 일치 확인
- 같은 `request_id`의 멱등 삭제와 충돌 거부
- Binding의 `target_id`로 K3s Client 하나만 직접 선택
- Namespace ownership label 검증
- 실제 Namespace Foreground 삭제와 완료 대기
- 이미 없는 Namespace의 성공 수렴
- 일시 오류 재시도와 최종 오류 코드 저장
- 삭제 성공 결과의 `runtime_workload_id`, `status: SUCCESS`
- 삭제 실패 시 Binding 상태 복구와 Worker 종료 안정성
- 삭제 OpenAPI, Markdown, README와 회귀 테스트

### 제외 범위

- 런타임 상태·자원 조회 API
- AWS/GCP VM 자체 삭제
- TTL 감지
- Scheduler 코드와 운영 DB Store

## PR C: 런타임 상태·자원 조회

### 브랜치와 이슈

- 브랜치: `feat/25-runtime-status`
- base: `feat/16-async-runtime-delete`
- 제목: `Feat: 단일 노드 K3s 런타임 상태와 자원 조회`
- `Closes #25`
- `Refs #18`, `Refs #24`, `Refs #26`

### 포함 범위

- `GET /internal/v1/instances/{instance_id}/runtime-status` 추가
- Binding의 `target_id`로 Registry 직접 조회
- Namespace ownership 검증
- Pod·컨테이너의 Running, Waiting, Terminated, Ready, 재시작과 종료 정보
- 컨테이너 requests, limits, CPU·메모리 usage
- 단일 K3s Node의 Ready와 Pressure 상태
- capacity, allocatable, requested, schedulable 계산
- Node Metrics CPU·메모리 usage
- Metrics API 미가용 시 core 상태를 유지하는 부분 성공
- 조회 오류의 HTTP 상태·안정 코드·안전한 메시지
- 상태 조회 OpenAPI, Markdown, README와 회귀 테스트

### 제외 범위

- CloudWatch·Cloud Monitoring 등 Provider별 VM 지표
- VM 전원·네트워크·디스크 I/O
- 멀티노드 K3s
- Scheduler의 대상 선택
- 사용자 UI

## 공통 API와 오류 원칙

- HTTP 접수 실패는 `{"error":{"code":"...","message":"..."}}` 형식이다.
- Worker 실행 뒤 실패는 Operation 조회 HTTP `200`, `status: FAILED`,
  `last_error_code`로 반환한다.
- Kubernetes·클라우드 SDK 원문 오류, kubeconfig 경로, 인증 정보는 외부 응답에
  포함하지 않는다.
- Worker가 retryable 오류를 `max_attempts`까지 처리하므로 최종 `FAILED`를
  Scheduler가 자동 재요청하지 않는다.
- `OPERATION_CANCELLED`은 종료 중 재queue를 위한 내부 경로이며 외부 최종 오류
  계약에 포함하지 않는다.

## 브랜치 작성 방식

- 기존 PR #28 커밋을 범위별로 그대로 cherry-pick하지 않는다. 여러 기능이 같은
  파일을 단계적으로 수정하므로 각 PR의 최종 기능 범위에 맞춰 테스트와 코드를
  다시 구성한다.
- 각 PR은 해당 단계에서 단독으로 빌드되고 모든 테스트가 통과해야 한다.
- 공통 파일은 선행 PR에서 최소 계약을 도입하고 후속 PR에서 호환되게 확장한다.
- unrelated 변경, Scheduler 코드, 로컬 UI 파일을 포함하지 않는다.
- 새 PR은 모두 Draft로 게시한다.

## 검증 기준

각 PR마다 다음을 새로 실행한다.

```powershell
go test -count=1 ./...
go vet -buildvcs=false ./...
go build -buildvcs=false ./...
npx --yes @redocly/cli lint docs/api/secure-provisioner.openapi.yaml
git diff --check <base>...HEAD
```

추가로 다음을 확인한다.

- PR A: 생성 접수, 중복 요청, Operation 폴링, 생성 성공·실패
- PR B: Binding 불일치, 다른 target 미접근, 이미 삭제된 Namespace 성공,
  소유권 불일치 보호, 종료 중 상태 복구
- PR C: 단일 노드 계산, 컨테이너 상태, Metrics 부분 성공, target 직접 조회
- 최종 PR C까지 적용한 트리가 기존 PR #28의 사용자 관찰 동작을 모두 보존
- 각 PR diff에 후속 단계 파일이나 로컬 대시보드가 포함되지 않음

## 게시와 기존 PR 종료

1. PR A, PR B, PR C를 Draft로 게시한다.
2. 각 PR 본문에 base 관계, 포함·제외 범위, 검증 결과와 다음 PR 링크를 기록한다.
3. 기존 PR #28에 세 새 PR 링크와 대체 관계를 댓글로 남긴다.
4. PR #28을 `closed`로 변경한다. 기존 원격 브랜치는 삭제하지 않는다.
5. 선행 PR 병합 후 다음 stacked PR의 base를 `dev`로 변경한다.

## 완료 조건

- 생성·삭제·조회 Draft PR 세 개가 올바른 base 관계로 열려 있다.
- 각 PR의 diff와 문서가 해당 작업 범위만 포함한다.
- 세 PR 모두 테스트·정적 검사·빌드·OpenAPI lint를 통과한다.
- 기존 PR #28에는 대체 PR 링크가 있고 닫힌 상태다.
- Scheduler와 로컬 대시보드에는 변경이 없다.
