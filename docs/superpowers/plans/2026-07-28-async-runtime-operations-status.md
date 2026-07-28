# 비동기 런타임 생성·삭제와 단일 노드 상태 조회 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 스케줄러가 Secure Provisioner에 런타임 생성·삭제를 비동기로 요청하고 Operation을 폴링해 완료 결과를 얻으며, `target_id`로 선택한 단일 K3s VM의 컨테이너 상태와 1차 자원 정보를 조회할 수 있게 한다.

**Architecture:** HTTP 계층은 요청을 Operation Store에 넣고 즉시 `202 Accepted`를 반환한다. Worker는 선택된 `target_id`의 K3s Adapter를 호출하고 성공 결과와 바인딩을 저장한다. 상태 조회는 같은 `target_id`로 Kubernetes/Metrics 클라이언트를 직접 선택해 워크로드 컨테이너 정보와 단일 노드의 capacity·allocatable·requested·schedulable을 계산한다.

**Tech Stack:** Go 1.26, `net/http`, Kubernetes Go client v0.36.2, Metrics API client, 메모리 Operation/Binding Store, `go test`

## Global Constraints

- `instance-scheduler` 코드는 수정하지 않고 요청/응답 계약만 맞춘다.
- CREATE와 DELETE 모두 `202 + operation_id`로 시작하며 `QUEUED/RUNNING/RETRYING/SUCCEEDED/FAILED` 상태를 사용한다.
- CREATE 성공 결과는 `runtime_workload_id`, `service_url`을 포함한다.
- DELETE 성공 결과는 `runtime_workload_id`, `status: SUCCESS`를 포함한다.
- 삭제 요청 JSON 필드는 스케줄러 계약대로 `delete_reason`을 사용한다.
- 상태 조회에서 Metrics API 실패는 전체 실패가 아니며 사용량만 `null`, `metrics_available: false`로 표현한다.
- 상태 조회 대상 K3s 클러스터는 정확히 한 노드여야 한다.
- 로컬 테스트용 상태 UI는 변경하거나 커밋하지 않는다.
- 기능별 테스트가 실패하는 것을 먼저 확인한 뒤 최소 구현으로 통과시킨다.

---

## Task 1: 비동기 CREATE 서비스와 바인딩 생명주기

**Files:**

- Modify: `internal/runtimeops/service.go`
- Modify: `internal/runtimeops/service_test.go`
- Modify: `internal/k3s/executor.go`
- Modify: `internal/k3s/executor_test.go`
- Modify: `internal/operations/operation.go`
- Modify: `internal/operations/memory_store_test.go`

1. `EnqueueCreate`가 request idempotency를 보장하고 QUEUED Operation을 반환하는 테스트를 작성한다.
2. 테스트를 실행해 현재 동기 생성 서비스 때문에 실패함을 확인한다.
3. Worker의 CREATE 실행 성공 시 K3s 결과를 Operation에 저장하고 Runtime Binding을 저장하도록 구현한다.
4. K3s 생성 성공 후 바인딩 저장 실패 시 생성한 Namespace를 정리하고 Operation을 실패 처리하는 테스트와 구현을 추가한다.
5. 관련 패키지 테스트를 실행해 통과시킨다.
6. `Feat: 런타임 생성을 비동기 작업으로 처리` 커밋을 만든다.

## Task 2: 스케줄러 호환 비동기 HTTP 계약

**Files:**

- Modify: `internal/httpapi/http.go`
- Modify: `internal/httpapi/runtime.go`
- Modify: `internal/httpapi/delete.go`
- Modify: `internal/httpapi/http_test.go`
- Modify: `internal/httpapi/runtime_test.go`
- Modify: `internal/httpapi/delete_test.go`
- Modify: `cmd/runtime-dashboard/main.go` (컴파일 호환이 필요한 최소 변경만)

1. POST CREATE가 `202`, Operation 요약, `Location`, `Retry-After`를 반환하는 계약 테스트를 작성한다.
2. DELETE가 `delete_reason`을 받고 같은 형식의 `202` 응답을 반환하는 테스트를 작성한다.
3. GET Operation이 진행 중에는 `Retry-After`를, 성공 시 작업 유형별 결과를 반환하는 테스트를 작성한다.
4. 테스트를 실행해 동기 POST와 현재 응답 DTO 때문에 실패함을 확인한다.
5. HTTP use case와 DTO를 비동기 Operation 계약에 맞춰 구현한다.
6. HTTP 및 전체 컴파일 테스트를 실행한다.
7. `Feat: 비동기 런타임 API 계약 적용` 커밋을 만든다.

## Task 3: 단일 노드 capacity·allocatable·requested·schedulable 계산

**Files:**

- Modify: `internal/k3s/status.go`
- Modify: `internal/k3s/status_test.go`

1. 정확히 한 노드의 조건, capacity, allocatable, requested, schedulable, 선택적 CPU·메모리 사용량을 검증하는 테스트를 작성한다.
2. 일반 컨테이너 요청량 합, init container 최대값, Pod overhead, 종료 Pod 제외, 0 하한을 검증한다.
3. 0개/2개 이상 노드에서 `TARGET_TOPOLOGY_INVALID`를 반환하는 테스트를 작성한다.
4. NodeMetrics가 없어도 핵심 상태가 성공하고 사용량만 비어 있는 테스트를 작성한다.
5. 테스트를 실행해 Node 모델과 계산 부재로 실패함을 확인한다.
6. Reader와 계산 helper를 최소 구현하고 관련 테스트를 통과시킨다.
7. `Feat: 단일 K3s 노드 자원 상태 조회 추가` 커밋을 만든다.

## Task 4: 상태 HTTP 응답에 노드 정보 노출

**Files:**

- Modify: `internal/httpapi/runtime.go`
- Modify: `internal/httpapi/runtime_test.go`
- Modify: `docs/api/runtime-operations.md`
- Modify: `docs/api/secure-provisioner.openapi.yaml`

1. 컨테이너 상태·사용량과 노드 자원 정보를 JSON으로 직렬화하는 계약 테스트를 작성한다.
2. Metrics 비가용 및 단일 노드 위반 오류 매핑 테스트를 작성한다.
3. 테스트 실패를 확인한 후 HTTP DTO와 오류 매핑을 구현한다.
4. 구현과 문서 예시·스키마가 일치하도록 API 명세를 갱신한다.
5. HTTP 테스트와 OpenAPI lint를 실행한다.
6. `Feat: 런타임 상태 API에 노드 자원 정보 제공` 커밋을 만든다.

## Task 5: 실제 서버에 K3s Runtime 서비스 연결

**Files:**

- Modify: `cmd/provisioner/main.go`
- Modify: `cmd/provisioner/main_test.go`
- Modify: `README.md`

1. 환경 설정으로 클러스터 레지스트리 파일, worker 동시성/재시도, 서버 종료를 검증할 수 있는 구성 테스트를 작성한다.
2. 테스트를 실행해 현재 unavailable create use case만 연결된 상태에서 실패함을 확인한다.
3. Registry, Create/Delete/Status Adapter, Store, Runtime Service, Worker를 조립하고 HTTP 서버와 함께 실행·종료하도록 구현한다.
4. 실행에 필요한 환경 변수와 로컬 검증 절차를 README에 기록한다.
5. 명령 패키지와 전체 테스트를 실행한다.
6. `Feat: Provisioner 서버에 K3s 런타임 작업 연결` 커밋을 만든다.

## Task 6: 통합 검증과 커밋 범위 확인

**Files:**

- Verify only unless a defect is found.

1. `gofmt`를 적용한다.
2. `go test -count=1 ./...`를 실행한다.
3. 가능하면 로컬 fake K3s 클라이언트를 이용한 생성→폴링→상태→삭제→폴링 흐름 테스트를 실행한다.
4. OpenAPI lint를 실행한다.
5. `git status`, `git diff`, `git log`로 로컬 UI가 커밋되지 않았고 기능별 커밋이 분리됐는지 확인한다.
6. 구현된 범위, 미검증된 실제 이미지 pull/E2E 범위, 관련 이슈 번호를 사용자에게 보고한다.
