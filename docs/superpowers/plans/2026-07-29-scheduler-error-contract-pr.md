# Scheduler 오류 응답 계약과 후속 PR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Secure Provisioner의 현재 생성·삭제·Operation·상태 조회 오류 응답을 Scheduler가 구현할 수 있는 최소 계약으로 문서화하고, 세부 오류 분류는 별도 이슈로 분리한 뒤 로컬 UI를 제외한 하나의 후속 PR을 만든다.

**Architecture:** HTTP 접수 실패는 `ErrorResponse`의 `error.code`와 `error.message`로 표현하고, 접수된 비동기 작업의 실행 실패는 `OperationResponse.status=FAILED`와 `last_error_code`로 표현한다. 현재 구현에서 실제 반환되는 코드만 API 계약에 넣으며 이미지·용량·DNS·인증·영속 Store 세분화는 별도 이슈의 향후 범위로 둔다. PR은 기존 K3s Adapter PR #23의 head인 `feat/18-k3s-create-adapter`를 base로 하는 stacked PR로 만들어 대시보드 커밋과 파일을 제외한다.

**Tech Stack:** Go 1.26, `net/http`, OpenAPI 3.1, Markdown, Git, GitHub CLI/App

## Global Constraints

- `instance-scheduler` 저장소와 코드는 수정하지 않는다.
- Scheduler가 구현할 현재 계약에는 실제 코드가 반환하는 오류만 포함한다.
- HTTP 접수 실패 응답은 `{"error":{"code":"...","message":"..."}}` 형식이다.
- 비동기 실행 실패는 HTTP `200` Operation 조회 응답의 `status: FAILED`, `last_error_code` 형식이다.
- 이미지 pull·capacity·DNS·인증·영속 Store의 세부 오류 코드는 현재 API 계약에 추가하지 않고 별도 GitHub 이슈로 남긴다.
- 로컬 `cmd/runtime-dashboard`, `internal/dashboard`, 대시보드 설계·계획 파일은 커밋하거나 push하지 않는다.
- 기존 PR #23은 수정하지 않으며 후속 PR의 base로만 사용한다.
- Scheduler 응답 형식, 비동기 생성·삭제, 상태 조회, 운영 wiring 변경을 후속 PR 하나에 포함한다.

---

### Task 1: UI 없는 stacked PR 작업공간 구성

**Files:**

- Reuse linked worktree: `.worktrees/secure-provisioner-issue-18`
- Create branch: `feat/26-async-runtime-operations-status`

**Interfaces:**

- Consumes: `origin/feat/18-k3s-create-adapter`의 head `8fe5192`
- Produces: UI 파일이 없고 비동기 런타임 변경만 포함한 clean branch

- [ ] **Step 1: 현재 저장소가 linked worktree인지 확인**

Run:

```powershell
git rev-parse --git-dir
git rev-parse --git-common-dir
git rev-parse --show-superproject-working-tree
```

Expected: git dir와 common dir가 다르고 superproject 경로는 비어 있다.

- [ ] **Step 2: 기존 로컬 브랜치의 계획 파일 보존**

Run:

```powershell
git add docs/superpowers/plans/2026-07-29-scheduler-error-contract-pr.md
git commit -m "Docs: Scheduler 오류 계약 PR 계획 추가"
```

Expected: 로컬 UI 브랜치에 계획 파일만 별도 커밋되어 새 브랜치 전환 시 유실되지 않는다.

- [ ] **Step 3: PR #23 head에서 clean branch 생성**

Run:

```powershell
git switch -c feat/26-async-runtime-operations-status 8fe5192
```

Expected: 현재 격리 worktree에서 새 브랜치가 `8fe5192`를 가리킨다. 기존 `feat/multicloud-runtime-ops-dashboard` 브랜치와 커밋은 그대로 보존된다.

- [ ] **Step 4: UI를 제외한 런타임 커밋 적용**

Run:

```powershell
git cherry-pick 9d3c8dd 00e9184 8b4cd29 4398e6e cc73335
git cherry-pick 8f93b4a d2ce384 8fb0fed b6a126a
git cherry-pick ac450fa 67ebdb1 fc19cac 6cade49 507deea 3ae6969
```

Expected: 충돌 없이 Runtime Binding, 상태·삭제, 비동기 생성·삭제, 노드 상태, 서버 wiring과 API 문서가 적용된다.

- [ ] **Step 5: UI 파일이 포함되지 않았는지 확인**

Run:

```powershell
git diff --name-only 8fe5192..HEAD
git diff --exit-code 8fe5192..HEAD -- cmd/runtime-dashboard internal/dashboard
```

Expected: 두 번째 명령은 출력 없이 성공하고 첫 번째 목록에도 dashboard 경로가 없다.

- [ ] **Step 6: 의존성과 baseline 검증**

Run:

```powershell
go mod download
go test -count=1 ./...
```

Expected: 모든 Go package 테스트가 통과한다.

### Task 2: Scheduler 오류 응답 회귀 테스트

**Files:**

- Modify: `internal/httpapi/http_test.go`
- Modify: `internal/httpapi/runtime_test.go`

**Interfaces:**

- Consumes: `writeAPIError`, `RuntimeUseCase`, `OperationResponse`
- Produces: endpoint별 HTTP status와 stable error code를 고정하는 characterization tests

- [ ] **Step 1: 생성 접수 오류 테스트 추가**

`internal/httpapi/http_test.go`에 queue 오류의 내부 메시지가 숨겨지고 아래 계약이 유지되는 테스트를 추가한다.

```go
func TestCreateInstanceMapsQueueFailureToStableError(t *testing.T) {
	runtime := &recordingRuntimeUseCase{createErr: errors.New("private operation store detail")}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertErrorCode(t, response, "CREATE_QUEUE_FAILED")
	if strings.Contains(response.Body.String(), "private operation store detail") {
		t.Fatalf("response leaked internal error: %s", response.Body.String())
	}
}
```

- [ ] **Step 2: 삭제 접수 오류 table test 추가**

`internal/httpapi/runtime_test.go`에서 `runtimebinding.ErrNotFound`, `runtimeops.ErrBindingMismatch`, `operations.ErrIdempotencyConflict`, `runtimebinding.ErrInvalidTransition`, 일반 오류가 각각 `404/409/409/409/502`와 `INSTANCE_NOT_FOUND/INSTANCE_BINDING_MISMATCH/REQUEST_ID_CONFLICT/INSTANCE_STATE_CONFLICT/DELETE_QUEUE_FAILED`로 변환되는지 검증한다.

- [ ] **Step 3: Operation 조회 오류 table test 추가**

`operations.ErrOperationNotFound`는 `404 OPERATION_NOT_FOUND`, 일반 Store 오류는 `500 OPERATION_LOOKUP_FAILED`가 되는지 검증한다.

- [ ] **Step 4: HTTP package 테스트 실행**

Run:

```powershell
go test -count=1 ./internal/httpapi
```

Expected: characterization tests와 기존 HTTP 테스트가 모두 통과한다.

- [ ] **Step 5: 테스트 커밋**

Run:

```powershell
git add internal/httpapi/http_test.go internal/httpapi/runtime_test.go
git commit -m "Test: Scheduler 오류 응답 계약 고정"
```

### Task 3: 한글 API 명세를 endpoint별 오류 계약으로 재구성

**Files:**

- Modify: `docs/api/runtime-operations.md`

**Interfaces:**

- Consumes: 현재 HTTP handler와 Operation Worker의 실제 상태·오류 코드
- Produces: Scheduler 구현자가 코드 없이 처리 흐름을 판단할 수 있는 한글 계약

- [ ] **Step 1: 공통 오류 형식과 비동기 실패 구분 추가**

문서의 오류 장 시작 부분에 다음 두 형식을 나란히 설명한다.

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "instance_id must be a UUID"
  }
}
```

```json
{
  "operation_id": "op-create-123",
  "request_id": "runtime-create-018f3f1e",
  "type": "CREATE",
  "status": "FAILED",
  "attempt": 3,
  "max_attempts": 3,
  "last_error_code": "WORKLOAD_NOT_READY"
}
```

첫 번째는 Operation이 생성되지 않은 접수 실패이고, 두 번째는 접수 후 Worker의 최종 실패임을 명시한다.

- [ ] **Step 2: endpoint별 HTTP 오류표 추가**

아래 코드를 정확히 표에 포함한다.

```text
POST create: INVALID_REQUEST, REQUEST_ID_CONFLICT, UNSUPPORTED_MEDIA_TYPE, CREATE_QUEUE_FAILED
DELETE: INVALID_REQUEST, INSTANCE_NOT_FOUND, INSTANCE_BINDING_MISMATCH, REQUEST_ID_CONFLICT, INSTANCE_STATE_CONFLICT, UNSUPPORTED_MEDIA_TYPE, DELETE_QUEUE_FAILED
GET operation: OPERATION_NOT_FOUND, OPERATION_LOOKUP_FAILED
GET runtime-status: INSTANCE_NOT_FOUND, RUNTIME_OWNERSHIP_MISMATCH, TARGET_NOT_FOUND, TARGET_TOPOLOGY_INVALID, TARGET_TEMPORARILY_UNAVAILABLE, K3S_UNAVAILABLE, RUNTIME_STATUS_FAILED
```

- [ ] **Step 3: 현재 Operation 실행 오류와 Scheduler 행동 표 추가**

현재 실제 코드의 `TARGET_NOT_FOUND`, `TARGET_DISABLED`, `K3S_UNAVAILABLE`, `RESOURCE_OWNERSHIP_CONFLICT`, `RESOURCE_APPLY_FAILED`, `WORKLOAD_NOT_READY`, `ROLLBACK_FAILED`, `OPERATION_CANCELLED`, `TARGET_TEMPORARILY_UNAVAILABLE`, `NAMESPACE_DELETE_TIMEOUT`, `RUNTIME_OWNERSHIP_MISMATCH`, `INSTANCE_NOT_FOUND`, `EXECUTION_FAILED`, `INVALID_OPERATION_RESULT`를 생성/삭제 구분과 함께 나열한다. `RETRYING` 중에는 새 요청을 만들지 말고 같은 Operation을 폴링하며, `FAILED`에서만 Scheduler 정책을 적용한다고 명시한다.

- [ ] **Step 4: 미구현 상세 오류가 계약에 없음을 명시**

이미지 pull 세분화, capacity 사전 거절, DNS/외부 URL, 인증, 영속 Store 세분화는 후속 이슈에서 설계하며 현재 Scheduler 필수 처리 코드가 아님을 기록한다.

- [ ] **Step 5: Markdown 명세 커밋**

Run:

```powershell
git add docs/api/runtime-operations.md
git commit -m "Docs: Scheduler 오류 응답 계약 정리"
```

### Task 4: OpenAPI endpoint 오류 응답과 JSON examples 정리

**Files:**

- Modify: `docs/api/secure-provisioner.openapi.yaml`

**Interfaces:**

- Consumes: `ErrorResponse`, `OperationResponse`
- Produces: HTTP endpoint별 status, stable code, response JSON example

- [ ] **Step 1: 누락된 HTTP response status 추가**

```text
POST /instances: 202, 400, 409, 415, 502
DELETE /instances/{id}: 202, 400, 404, 409, 415, 502
GET /operations/{id}: 200, 404, 500
GET /runtime-status: 200, 404, 409, 502, 503
```

- [ ] **Step 2: components examples 추가**

`components.examples`에 `InvalidRequest`, `RequestIDConflict`, `UnsupportedMediaType`, `CreateQueueFailed`, `InstanceNotFound`, `InstanceBindingMismatch`, `InstanceStateConflict`, `DeleteQueueFailed`, `OperationNotFound`, `OperationLookupFailed`, `RuntimeOwnershipMismatch`, `TargetUnavailable`, `TargetNotFound`, `TargetTopologyInvalid`, `RuntimeStatusFailed`, `CreateOperationFailed`, `DeleteOperationFailed`를 만들고 현재 handler의 메시지와 같은 JSON을 사용한다.

- [ ] **Step 3: endpoint별 response에 examples 연결**

같은 HTTP status에 여러 코드가 있으면 OpenAPI `examples` map을 사용해 모두 표시한다. `GET operation`의 `200`에는 처리 중, 생성 성공, 삭제 성공, 생성 실패, 삭제 실패 예시를 제공한다.

- [ ] **Step 4: OpenAPI lint 실행**

Run:

```powershell
npx --yes @redocly/cli lint docs/api/secure-provisioner.openapi.yaml
```

Expected: error와 warning 없이 valid 결과가 나온다.

- [ ] **Step 5: OpenAPI 커밋**

Run:

```powershell
git add docs/api/secure-provisioner.openapi.yaml
git commit -m "Docs: OpenAPI 오류 응답 예시 추가"
```

### Task 5: 세부 런타임 오류 분류 후속 이슈 생성

**Files:**

- No repository files.

**Interfaces:**

- Consumes: 현재 통합 오류 코드와 미구현 상세 원인
- Produces: GitHub issue `[Runtime] 세부 오류 분류와 Scheduler 대응 정책`

- [ ] **Step 1: 이슈 본문 작성**

이슈에 아래 범위를 포함한다.

```text
이미지: IMAGE_NOT_FOUND, IMAGE_PULL_DENIED, IMAGE_PULL_FAILED, IMAGE_ARCHITECTURE_MISMATCH
자원: INSUFFICIENT_CPU, INSUFFICIENT_MEMORY, INSUFFICIENT_EPHEMERAL_STORAGE, TARGET_PRESSURE_DETECTED
네트워크: INGRESS_NOT_READY, DNS_NOT_READY, SERVICE_URL_UNREACHABLE
보안: UNAUTHENTICATED, PERMISSION_DENIED, IMAGE_POLICY_VIOLATION
운영 Store: OPERATION_STORE_UNAVAILABLE, BINDING_STORE_UNAVAILABLE, OPERATION_QUEUE_FULL
삭제: NAMESPACE_FINALIZER_BLOCKED, FORCE_DELETE_REQUIRED
```

각 코드는 제안이며 Scheduler 행동이 달라지는 코드만 최종 API 계약으로 승격한다는 원칙을 적는다.

- [ ] **Step 2: GitHub issue 생성**

GitHub App을 우선 사용하고, connector가 issue creation을 제공하지 않을 때만 아래 fallback을 사용한다.

```powershell
gh issue create --repo MSG-CTF/secure-provisioner --title "[Runtime] 세부 오류 분류와 Scheduler 대응 정책" --body-file <utf8-body-file>
```

Expected: 새 issue URL을 반환한다.

### Task 6: 최종 검증, push, stacked draft PR 생성

**Files:**

- Verify all changed files.

**Interfaces:**

- Consumes: Tasks 1-5의 clean branch와 issue URL
- Produces: PR #23을 base로 하는 draft PR 하나

- [ ] **Step 1: 전체 검증**

Run:

```powershell
go test -count=1 ./...
go vet -buildvcs=false ./...
go build -buildvcs=false ./...
npx --yes @redocly/cli lint docs/api/secure-provisioner.openapi.yaml
git diff --check 8fe5192..HEAD
```

Expected: 모든 명령이 성공한다.

- [ ] **Step 2: UI 제외와 clean status 재확인**

Run:

```powershell
git status --short
git diff --name-only 8fe5192..HEAD
git diff --exit-code 8fe5192..HEAD -- cmd/runtime-dashboard internal/dashboard
```

Expected: status가 clean이고 dashboard diff가 없다.

- [ ] **Step 3: branch push**

Run:

```powershell
git push -u origin feat/26-async-runtime-operations-status
```

- [ ] **Step 4: stacked draft PR 생성**

PR 설정:

```text
base: feat/18-k3s-create-adapter
head: feat/26-async-runtime-operations-status
title: Feat: 비동기 런타임 작업과 상태 조회 API
```

본문에는 생성·삭제 비동기 Operation, `target_id` 상태 조회, 단일 노드 자원, 실제 서버 wiring, Scheduler 오류 응답 계약, 인메모리 Store 제한, 세부 오류 후속 이슈를 설명한다. `Closes #26`, `Refs #16`, `Refs #24`, `Refs #25`와 Task 5 issue를 연결하고 UI가 포함되지 않았음을 적는다.

- [ ] **Step 5: PR 메타데이터 검증**

GitHub App으로 base/head/draft 상태와 변경 파일을 확인한다.

Expected: base가 `feat/18-k3s-create-adapter`, head가 `feat/26-async-runtime-operations-status`, draft이며 dashboard 파일이 없다.
