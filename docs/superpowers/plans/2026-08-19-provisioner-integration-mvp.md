# Provisioner Integration MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 현재 `dev` 구조에 WEB/PWN 격리, 내부 서비스 인증, PostgreSQL lease worker와 runtime binding 영속화를 충돌 없이 결합하여 Scheduler/Broker mock 및 실제 K3s adapter와 상호작용할 수 있는 Provisioner MVP를 만든다.

**Architecture:** `origin/dev`에서 만든 로컬 통합 worktree에 격리 브랜치를 먼저 fast-forward하고 서비스 인증은 파일 단위로 이식한다. 기존 PR #35는 병합하지 않고, 현재 `operations`, `runtimeops`, `runtimebinding` 경계에 맞는 lease-aware store와 PostgreSQL adapter를 TDD로 구현한다. PostgreSQL operation store와 binding store는 같은 DB handle을 공유하며 DELETE enqueue/상태 전환은 coordinator가 한 트랜잭션으로 처리한다.

**Tech Stack:** Go, `net/http`, Kubernetes `client-go`, PostgreSQL, `database/sql`, pgx v5, Docker Compose, OpenAPI 3, PowerShell

**Spec:** `docs/superpowers/specs/2026-08-19-provisioner-integration-mvp-design.md`

## Global Constraints

- 최종 대상 브랜치는 `dev`이며 로컬 통합 브랜치는 검증 전 원격에 push하지 않는다.
- 외부 격리 선택 필드는 필수 `isolation_profile: WEB | PWN` 하나만 사용한다.
- `challenge_ref`, `isolation_ref`, `resource_profile_ref`, 외부 `outbound_mode`를 생성 API에 다시 추가하지 않는다.
- GHCR workload image는 canonical `@sha256:<64 lowercase hex>` digest를 요구한다.
- TTL 만료 판단은 Scheduler 책임이며 Provisioner 내부 TTL scanner를 추가하지 않는다.
- 모든 `/internal/v1/*` 경로는 Bearer 서비스 인증을 요구한다.
- PWN은 `gvisor` RuntimeClass capability가 있는 NodePort target에서만 생성한다.
- PR #35는 merge 또는 전체 cherry-pick하지 않고 lease 및 PostgreSQL 개념만 현재 구조로 이식한다.
- 기존 사용자 변경과 다른 worktree의 미추적 파일은 수정하거나 삭제하지 않는다.
- 각 구현 task는 failing test, 최소 구현, focused test, 전체 관련 package test, 의미 단위 commit 순서로 진행한다.

---

### Task 1: 로컬 통합 worktree와 격리 기준선 준비

**Files:**
- Include from branch: `feat/web-pwn-isolation-profiles`
- Include from docs branch: `docs/superpowers/specs/2026-08-19-provisioner-integration-mvp-design.md`
- Include from docs branch: `docs/superpowers/plans/2026-08-19-provisioner-integration-mvp.md`
- Modify: `internal/k3s/adapter.go`
- Modify: `internal/k3s/resources.go`
- Test: `internal/k3s/adapter_test.go`
- Test: `internal/k3s/resources_test.go`

**Interfaces:**
- Consumes: `origin/dev`, `feat/web-pwn-isolation-profiles`, 로컬 NodePort default 수정
- Produces: `integration/provisioner-mvp` worktree와 현재 API 기준선

- [ ] **Step 1: 별도 worktree를 만든다**

`superpowers:using-git-worktrees`의 안전 점검을 수행한 뒤 저장소 공통 git directory 아래에 worktree를 만든다.

```powershell
git fetch origin
git worktree add ".worktrees/provisioner-mvp-integration" -b "integration/provisioner-mvp" "origin/dev"
```

Expected: 새 worktree가 `origin/dev`의 SHA에서 시작하고 기존 dirty worktree는 변하지 않는다.

- [ ] **Step 2: 격리 브랜치를 fast-forward한다**

```powershell
git merge --ff-only feat/web-pwn-isolation-profiles
```

Expected: conflict 없이 `2f8db4c`까지 이동한다. fast-forward가 불가능하면 merge commit을 만들지 말고 원인을 확인한다.

- [ ] **Step 3: 승인된 통합 spec과 plan 커밋만 가져온다**

docs 전용 브랜치의 기존 두 커밋은 제외하고 그 이후 문서만 cherry-pick한다.

```powershell
git cherry-pick a28b1c1..docs/mvp-contract-designs
```

Expected: 통합 spec과 이 plan 파일만 추가되고 소스 파일은 바뀌지 않는다.

- [ ] **Step 4: NodePort default 회귀 테스트를 먼저 반영한다**

`internal/k3s/adapter_test.go`에 Kubernetes가 빈 값을 `Cluster`로 default한 Service를 동일한 spec으로 인정하는 테스트를 추가한다.

```go
func TestSameServiceSpecAcceptsKubernetesDefaultedExternalTrafficPolicyForNodePort(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	cluster := validCluster("aws-dev")
	cluster.Config.ExposureMode = ExposureModeNodePort
	resources, err := BuildResourceSet(cluster, command)
	if err != nil { t.Fatal(err) }
	desired := resources.Services[0].DeepCopy()
	desired.Spec.ExternalTrafficPolicy = ""
	actual := desired.DeepCopy()
	actual.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
	if !sameServiceSpec(actual, desired) {
		t.Fatal("Kubernetes-defaulted externalTrafficPolicy was rejected")
	}
}
```

`internal/k3s/resources_test.go`에는 NodePort만 `Cluster`이고 ClusterIP Service는 빈 값인지 검증한다.

- [ ] **Step 5: focused test가 실패하는지 확인한다**

Run:

```powershell
go test ./internal/k3s -run "ExternalTrafficPolicy" -count=1
```

Expected: NodePort desired resource에 `externalTrafficPolicy`가 없어 FAIL.

- [ ] **Step 6: NodePort resource와 readback normalization을 구현한다**

`BuildResourceSet`의 NodePort 분기에서 다음 값을 명시한다.

```go
service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
```

`normalizeServiceAPIDefaults`에서도 NodePort의 빈 값을 같은 값으로 정규화한다.

- [ ] **Step 7: K3s package 검증과 커밋을 수행한다**

```powershell
gofmt -w internal/k3s/adapter.go internal/k3s/adapter_test.go internal/k3s/resources.go internal/k3s/resources_test.go
go test ./internal/k3s -count=1
git diff --check
git add internal/k3s/adapter.go internal/k3s/adapter_test.go internal/k3s/resources.go internal/k3s/resources_test.go
git commit -m "Fix: normalize NodePort external traffic policy"
```

Expected: K3s package PASS, staged 범위가 네 파일뿐이다.

### Task 2: 서비스 인증을 현재 격리 API 위에 이식

**Files:**
- Create: `cmd/provisioner/service_auth_config.go`
- Create: `cmd/provisioner/service_auth_config_test.go`
- Create: `internal/httpapi/auth.go`
- Create: `internal/httpapi/auth_config.go`
- Create: `internal/httpapi/auth_test.go`
- Create: `internal/httpapi/openapi_auth_test.go`
- Modify: `cmd/provisioner/main.go`
- Modify: `cmd/provisioner/main_test.go`
- Modify: `internal/httpapi/http.go`
- Modify: `internal/httpapi/http_test.go`
- Modify: `internal/httpapi/runtime_test.go`
- Modify: `docs/api/runtime-operations.md`
- Modify: `docs/api/secure-provisioner.openapi.yaml`
- Modify: `README.md`

**Interfaces:**
- Consumes: `httpapi.NewHandler`, `httpapi.NewHandlerWithRuntime`, `writeAPIError`
- Produces: `httpapi.ServiceAuthConfig`, authenticated handler constructors, `loadServiceAuthConfig(func(string) string)`

- [ ] **Step 1: auth 전용 파일과 테스트를 기존 인증 브랜치에서 파일 단위로 가져온다**

`feat/10-service-auth`의 다음 파일 내용만 현재 worktree에 반영한다. 브랜치 전체 merge와 문서 전체 checkout은 하지 않는다.

```text
cmd/provisioner/service_auth_config.go
cmd/provisioner/service_auth_config_test.go
internal/httpapi/auth.go
internal/httpapi/auth_config.go
internal/httpapi/auth_test.go
internal/httpapi/openapi_auth_test.go
```

- [ ] **Step 2: 인증 테스트가 constructor signature 때문에 실패하는지 확인한다**

Run:

```powershell
go test ./internal/httpapi ./cmd/provisioner -run "ServiceAuth|Authentication" -count=1
```

Expected: `NewHandler` 또는 runtime config에 인증 인수가 없어 compile FAIL.

- [ ] **Step 3: handler 바깥쪽에 인증 middleware를 배치한다**

`internal/httpapi/http.go`의 public constructor를 다음 계약으로 변경한다.

```go
func NewHandler(createWorkload provisioner.CreateWorkloadUseCase, authConfig ServiceAuthConfig) http.Handler
func NewHandlerWithRuntime(createWorkload provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase, authConfig ServiceAuthConfig) http.Handler
```

middleware 순서는 요청 body를 읽기 전에 인증되도록 유지한다.

```go
return newServiceAuthenticator(authConfig).wrap(requestSizeLimit(mux))
```

- [ ] **Step 4: main config에서 token source를 fail closed로 읽는다**

`cmd/provisioner/main.go`의 runtime config에 다음 필드를 추가한다.

```go
ServiceAuth httpapi.ServiceAuthConfig
```

`PROVISIONER_SERVICE_TOKEN` 또는 절대 경로 `PROVISIONER_SERVICE_TOKEN_FILE` 중 정확히 하나를 필수로 읽고, 이전 token은 선택적으로 읽는다. token은 `^[A-Za-z0-9_-]{43,128}$`를 만족해야 한다.

- [ ] **Step 5: 기존 격리 테스트 helper에 테스트 token을 주입한다**

기존 API 요청 body와 `isolation_profile` assertion은 바꾸지 않고 handler 생성 helper에서만 다음 token을 사용한다.

```go
const testServiceToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

모든 정상 요청에는 `Authorization: Bearer <token>`을 추가하고 인증 전 body 미읽기, duplicate Authorization 거부, 현재/이전 token 허용을 검증한다.

- [ ] **Step 6: 현재 OpenAPI 계약에 인증 설명을 수동 병합한다**

OpenAPI의 현재 `isolation_profile`, 다중 container, endpoint 배열을 유지하면서 다음만 추가한다.

```yaml
security:
  - ServiceBearerAuth: []
components:
  securitySchemes:
    ServiceBearerAuth:
      type: http
      scheme: bearer
      bearerFormat: opaque service token
```

- [ ] **Step 7: 인증 관련 검증과 커밋을 수행한다**

```powershell
gofmt -w cmd/provisioner internal/httpapi
go test ./internal/httpapi ./cmd/provisioner -count=1
go test ./... -count=1
git diff --check
git add README.md cmd/provisioner internal/httpapi docs/api
git commit -m "Feat: protect internal runtime APIs with service auth"
```

Expected: 격리 API 테스트를 포함한 전체 Go test PASS.

### Task 3: lease-aware operation contract와 memory worker 전환

**Files:**
- Modify: `internal/operations/operation.go`
- Modify: `internal/operations/store.go`
- Modify: `internal/operations/worker.go`
- Modify: `internal/operations/memory_store.go`
- Modify: `internal/operations/worker_test.go`
- Modify: `internal/operations/memory_store_test.go`
- Create: `internal/operations/lease.go`

**Interfaces:**
- Consumes: `operations.Operation`, `RuntimeExecutor`, existing retry classification
- Produces: `Lease`, `ClaimOptions`, `ClaimedOperation`, lease-aware `Store`, lease-renewing `Worker`

- [ ] **Step 1: lease ownership과 만료 회수 테스트를 작성한다**

```go
func TestMemoryStoreReclaimsExpiredLeaseAndRejectsStaleOwner(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	if _, _, err := store.EnqueueCreate(validCreateCommand("request-1"), 4); err != nil {
		t.Fatal(err)
	}
	first, claimed, err := store.Claim(context.Background(), ClaimOptions{
		WorkerID: "worker-a", Now: time.Unix(100, 0), LeaseDuration: time.Minute,
	})
	if err != nil || !claimed { t.Fatalf("first claim = %#v, %t, %v", first, claimed, err) }
	second, claimed, err := store.Claim(context.Background(), ClaimOptions{
		WorkerID: "worker-b", Now: time.Unix(161, 0), LeaseDuration: time.Minute,
	})
	if err != nil || !claimed { t.Fatalf("reclaim = %#v, %t, %v", second, claimed, err) }
	if _, err := store.MarkSucceeded(first, OperationResult{}, time.Unix(162, 0)); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale completion error = %v", err)
	}
}
```

worker 테스트에는 renewal 실패 시 executor context가 취소되는 경우를 추가한다.

- [ ] **Step 2: 새 테스트가 compile 실패하는지 확인한다**

```powershell
go test ./internal/operations -run "Lease|Reclaim|Renew" -count=1
```

Expected: `ClaimOptions`, `Lease`, `ErrLeaseLost`가 없어 compile FAIL.

- [ ] **Step 3: lease 타입과 store 계약을 정의한다**

`internal/operations/lease.go`:

```go
type Lease struct {
	Owner   string
	Version int64
	Until   time.Time
}

type ClaimOptions struct {
	WorkerID      string
	Now           time.Time
	LeaseDuration time.Duration
}

type ClaimedOperation struct {
	Operation Operation
	Lease     Lease
}

var ErrLeaseLost = errors.New("operation lease lost")
```

`Store`의 `Next`, `MarkRunning`, `Requeue`를 다음 lease-aware 메서드로 교체한다.

```go
Claim(context.Context, ClaimOptions) (ClaimedOperation, bool, error)
RenewLease(context.Context, ClaimedOperation, time.Time) (ClaimedOperation, error)
CheckpointCreateResult(ClaimedOperation, provisioner.CreateWorkloadResult, time.Time) (ClaimedOperation, error)
MarkRetrying(ClaimedOperation, string, time.Time, time.Time) (Operation, error)
Release(ClaimedOperation, time.Time) error
MarkSucceeded(ClaimedOperation, OperationResult, time.Time) (Operation, error)
MarkFailed(ClaimedOperation, string, time.Time) (Operation, error)
```

- [ ] **Step 4: memory store에 동일한 fencing 동작을 구현한다**

claim 때 `Attempt`와 lease version을 증가시키고 owner/version이 맞지 않는 모든 update는 `ErrLeaseLost`를 반환한다. `RETRYING` operation은 `next_retry_at` 이후에만 다시 claim한다.

- [ ] **Step 5: worker가 claim과 renewal context를 사용하도록 변경한다**

`WorkerConfig`에 다음 값을 추가한다.

```go
PollInterval  time.Duration
LeaseDuration time.Duration
RenewInterval time.Duration
WorkerID      string
```

각 실행은 child context를 만들고 renewal goroutine이 실패하면 cancel한다. terminal update는 마지막으로 확인된 `ClaimedOperation`만 사용한다.

- [ ] **Step 6: operation package 검증과 커밋을 수행한다**

```powershell
gofmt -w internal/operations
go test ./internal/operations -count=1
go test ./internal/runtimeops ./internal/httpapi -count=1
git diff --check
git add internal/operations internal/runtimeops internal/httpapi
git commit -m "Refactor: make operation worker lease aware"
```

Expected: 기존 create checkpoint 및 retry 테스트와 새 lease 테스트 PASS.

### Task 4: PostgreSQL schema와 operation store 구현

**Files:**
- Create: `internal/runtimepg/database.go`
- Create: `internal/runtimepg/migrations.go`
- Create: `internal/runtimepg/migrations/001_runtime_state.sql`
- Create: `internal/runtimepg/operation_store.go`
- Create: `internal/runtimepg/operation_codec.go`
- Create: `internal/runtimepg/operation_store_test.go`
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `compose.postgres.yaml`

**Interfaces:**
- Consumes: lease-aware `operations.Store`, immutable create/delete command structs
- Produces: `runtimepg.Open(context.Context, string)`, `(*Database).Operations() operations.Store`

- [ ] **Step 1: migration 및 codec round-trip 테스트를 작성한다**

```go
func TestOperationCodecRoundTripsResolvedCreateCommand(t *testing.T) {
	command := validResolvedPwnCommand(t)
	want, err := operations.NewCreateOperation("op-1", command, 4)
	if err != nil { t.Fatal(err) }
	payload, err := encodeOperationCommand(want)
	if err != nil { t.Fatal(err) }
	got, err := decodeOperationCommand(want.Type, payload)
	if err != nil { t.Fatal(err) }
	if !want.SameRequest(got) { t.Fatalf("round trip mismatch\nwant=%#v\ngot=%#v", want, got) }
}

func validResolvedPwnCommand(t *testing.T) provisioner.CreateWorkloadCommand {
	t.Helper()
	request := isolation.Request{
		WorkloadProfile: isolation.WorkloadProfilePwn,
		Containers: []isolation.ContainerRequirement{{
			Name: "challenge", Ports: []int{31337}, Expose: true, RunAsUser: 10001,
		}},
		ResourceLimits: isolation.ResourceLimits{
			CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128,
		},
	}
	policy, err := isolation.NewStaticResolver().Resolve(request)
	if err != nil { t.Fatal(err) }
	return provisioner.CreateWorkloadCommand{
		RequestID: "request-1", InstanceID: "11111111-1111-4111-8111-111111111111",
		TeamID: 1, RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "aws-k3s-001",
		Containers: []provisioner.WorkloadContainer{{
			Name: "challenge", Image: "ghcr.io/msg-ctf/pwn@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ports: []int{31337}, Expose: true,
		}},
		PolicyRequest: request, Policy: policy,
		ResourceLimits: provisioner.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
	}
}
```

SQL integration tests는 `PROVISIONER_TEST_DATABASE_URL`이 없을 때 명확히 skip하고, 별도 unit test는 malformed JSON과 unknown operation type을 항상 검증한다.

- [ ] **Step 2: codec 테스트가 실패하는지 확인한다**

```powershell
go test ./internal/runtimepg -run "Codec|Migration" -count=1
```

Expected: package 또는 codec 함수가 없어 compile FAIL.

- [ ] **Step 3: operations schema를 작성한다**

핵심 column과 constraint는 다음을 포함한다.

```sql
CREATE TABLE runtime_operations (
  operation_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  operation_type TEXT NOT NULL CHECK (operation_type IN ('CREATE','DELETE')),
  status TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','RETRYING','SUCCEEDED','FAILED')),
  command_snapshot JSONB NOT NULL,
  create_checkpoint JSONB,
  result JSONB,
  attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
  next_retry_at TIMESTAMPTZ,
  lease_owner TEXT,
  lease_until TIMESTAMPTZ,
  lease_version BIGINT NOT NULL DEFAULT 0,
  last_error_code TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);
```

claim용 partial index는 `status`, `next_retry_at`, `lease_until`, priority, `created_at`을 지원한다.

- [ ] **Step 4: PostgreSQL claim을 한 statement로 구현한다**

`FOR UPDATE SKIP LOCKED` candidate와 `UPDATE ... RETURNING`을 같은 statement에서 수행한다. DELETE priority가 CREATE보다 높고, 만료 RUNNING lease와 도래한 RETRYING operation만 claim한다.

- [ ] **Step 5: 모든 mutation에 owner/version fencing을 적용한다**

각 update의 WHERE 절은 다음 조건을 포함한다.

```sql
WHERE operation_id = $1
  AND status = 'RUNNING'
  AND lease_owner = $2
  AND lease_version = $3
```

영향받은 row가 0이면 `operations.ErrLeaseLost`를 반환한다. `max_attempts`는 DB row 값을 사용한다.

- [ ] **Step 6: 실제 PostgreSQL integration test를 실행한다**

```powershell
docker compose -f compose.postgres.yaml up -d
$env:PROVISIONER_TEST_DATABASE_URL = "postgres://provisioner:provisioner@127.0.0.1:54329/provisioner_test?sslmode=disable"
go test ./internal/runtimepg -count=1
```

Expected: duplicate request, payload conflict, SKIP LOCKED 중복 방지, expired lease reclaim, stale owner 거부, DELETE priority 테스트 PASS.

- [ ] **Step 7: PostgreSQL operation store를 커밋한다**

```powershell
gofmt -w internal/runtimepg
go test ./internal/runtimepg ./internal/operations -count=1
git diff --check
git add go.mod go.sum compose.postgres.yaml internal/runtimepg
git commit -m "Feat: persist lease operations in PostgreSQL"
```

### Task 5: PostgreSQL runtime binding과 atomic DELETE coordinator 구현

**Files:**
- Modify: `internal/runtimepg/migrations/001_runtime_state.sql`
- Create: `internal/runtimepg/binding_store.go`
- Create: `internal/runtimepg/binding_codec.go`
- Create: `internal/runtimepg/delete_coordinator.go`
- Create: `internal/runtimepg/binding_store_test.go`
- Create: `internal/runtimepg/delete_coordinator_test.go`
- Modify: `internal/runtimeops/service.go`
- Modify: `internal/runtimeops/service_test.go`
- Modify: `internal/runtimebinding/binding.go`
- Modify: `internal/runtimebinding/memory_store.go`
- Modify: `internal/runtimebinding/memory_store_test.go`

**Interfaces:**
- Consumes: `runtimebinding.Store`, PostgreSQL `Database`, lease-aware operation store
- Produces: `(*Database).Bindings() runtimebinding.Store`, `runtimeops.DeleteCoordinator`

- [ ] **Step 1: binding persistence와 crash-gap 테스트를 작성한다**

```go
func TestBeginDeleteAtomicallyMarksBindingAndEnqueuesOperation(t *testing.T) {
	database := openTestDatabase(t)
	binding := runtimebinding.Binding{
		InstanceID: "11111111-1111-4111-8111-111111111111", TeamID: 1,
		TargetID: "aws-k3s-001", Namespace: "instance-11111111",
		NamespaceUID: "namespace-uid", RuntimeWorkloadID: "aws-k3s-001/instance-11111111",
		State: runtimebinding.StateCreated, CreatedAt: time.Unix(90, 0), UpdatedAt: time.Unix(90, 0),
	}
	if _, _, err := database.Bindings().SaveCreated(binding); err != nil { t.Fatal(err) }
	command := provisioner.DeleteWorkloadCommand{
		RequestID: "delete-1", InstanceID: binding.InstanceID, TeamID: binding.TeamID,
		RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: binding.TargetID,
		RuntimeWorkloadID: binding.RuntimeWorkloadID, Reason: provisioner.DeleteReasonTTLExpired,
	}
	operation, created, err := database.DeleteCoordinator().BeginDelete(
		command, 4, time.Unix(100, 0),
	)
	if err != nil || !created { t.Fatalf("BeginDelete = %#v, %t, %v", operation, created, err) }
	stored, err := database.Bindings().Get(binding.InstanceID)
	if err != nil || stored.State != runtimebinding.StateDeleting {
		t.Fatalf("binding = %#v, %v", stored, err)
	}
}
```

같은 테스트 파일에 실제 PostgreSQL helper를 정의한다. 테스트 package는 `runtimepg`로 두어 내부 DB handle에 접근한다.

```go
func openTestDatabase(t *testing.T) *Database {
	t.Helper()
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" { t.Skip("PROVISIONER_TEST_DATABASE_URL is not set") }
	database, err := Open(context.Background(), dsn)
	if err != nil { t.Fatal(err) }
	if _, err := database.db.ExecContext(
		context.Background(), "TRUNCATE runtime_operations, runtime_bindings",
	); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}
```

트랜잭션 중 operation insert를 강제로 실패시켜 binding이 `CREATED`로 남는 테스트도 추가한다.

- [ ] **Step 2: 새 테스트가 실패하는지 확인한다**

```powershell
go test ./internal/runtimepg ./internal/runtimeops -run "Binding|BeginDelete|Atomic" -count=1
```

Expected: binding store와 coordinator가 없어 compile FAIL.

- [ ] **Step 3: runtime binding schema와 codec을 구현한다**

```sql
CREATE TABLE runtime_bindings (
  instance_id TEXT PRIMARY KEY,
  team_id BIGINT NOT NULL CHECK (team_id > 0),
  target_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  namespace_uid TEXT NOT NULL,
  runtime_workload_id TEXT NOT NULL,
  endpoints JSONB NOT NULL DEFAULT '[]'::jsonb,
  policy_snapshot JSONB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('CREATED','DELETING','DELETED')),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  deleted_at TIMESTAMPTZ
);
```

`SaveCreated`는 같은 placement 재저장을 멱등 성공으로, 다른 placement를 `ErrConflict`로 처리한다.

- [ ] **Step 4: DeleteCoordinator 계약을 runtimeops에 추가한다**

```go
type DeleteCoordinator interface {
	BeginDelete(provisioner.DeleteWorkloadCommand, int, time.Time) (operations.Operation, bool, error)
}
```

`runtimeops.Config`에 `DeleteCoordinator DeleteCoordinator`를 추가한다. `Service.EnqueueDelete`는 coordinator가 있으면 이를 사용하고 memory 모드는 기존 mutex/보상 경로를 사용한다. PostgreSQL coordinator는 binding validation, `DELETING` 전환, DELETE operation insert를 한 transaction에서 수행한다.

- [ ] **Step 5: 삭제 완료 재실행을 멱등하게 만든다**

K3s 삭제 후 binding이 이미 `DELETED`인 경우 `MarkDeleted`를 성공으로 간주한다. 프로세스가 binding update 후 operation terminal update 전에 종료되어도 lease reclaim 후 동일 DELETE가 성공하도록 테스트한다.

- [ ] **Step 6: 관련 package 검증과 커밋을 수행한다**

```powershell
gofmt -w internal/runtimepg internal/runtimeops internal/runtimebinding
go test ./internal/runtimepg ./internal/runtimeops ./internal/runtimebinding -count=1
git diff --check
git add internal/runtimepg internal/runtimeops internal/runtimebinding
git commit -m "Feat: persist runtime bindings and atomic deletes"
```

### Task 6: Provisioner 실행 설정과 PostgreSQL wiring

**Files:**
- Modify: `cmd/provisioner/main.go`
- Modify: `cmd/provisioner/main_test.go`
- Create: `cmd/provisioner/runtime_store_config.go`
- Create: `cmd/provisioner/runtime_store_config_test.go`
- Modify: `.env.example`
- Modify: `README.md`
- Modify: `compose.postgres.yaml`

**Interfaces:**
- Consumes: `runtimepg.Open`, operation/binding stores, target registry, service auth config
- Produces: `PROVISIONER_STORE_MODE=memory|postgres`, worker lease 환경설정

- [ ] **Step 1: config validation 테스트를 작성한다**

```go
func TestLoadRuntimeStoreConfigRequiresDatabaseURLForPostgres(t *testing.T) {
	_, err := loadRuntimeStoreConfig(environment(map[string]string{
		"PROVISIONER_STORE_MODE": "postgres",
	}))
	if err == nil { t.Fatal("missing database URL was accepted") }
}
```

lease duration보다 renew interval이 짧지 않은 설정, 0 이하 worker 수, 알 수 없는 store mode를 거부하는 table test를 추가한다.

- [ ] **Step 2: config 테스트가 실패하는지 확인한다**

```powershell
go test ./cmd/provisioner -run "RuntimeStoreConfig|WorkerConfig" -count=1
```

Expected: loader가 없어 compile FAIL.

- [ ] **Step 3: 실행 환경 계약을 구현한다**

다음 설정을 사용한다.

```text
PROVISIONER_STORE_MODE=memory|postgres
PROVISIONER_DATABASE_URL=<postgres dsn>
PROVISIONER_WORKERS=10
PROVISIONER_POLL_INTERVAL=200ms
PROVISIONER_LEASE_DURATION=3m
PROVISIONER_LEASE_RENEW_INTERVAL=1m
PROVISIONER_MAX_ATTEMPTS=4
PROVISIONER_RETRY_BASE_DELAY=1s
```

PostgreSQL mode에서는 하나의 `runtimepg.Database`에서 operation store, binding store, delete coordinator를 만들어 `runtimeops.Service`에 주입한다. memory mode는 빠른 단위·로컬 개발용으로 유지한다.

- [ ] **Step 4: graceful shutdown 순서를 보장한다**

HTTP server가 새 요청을 받지 않게 한 뒤 worker context를 취소하고 worker 종료를 기다린 다음 DB를 닫는다. worker 종료 전에 DB를 닫지 않는 테스트를 fake closer와 channel로 작성한다.

- [ ] **Step 5: command package와 전체 build를 검증하고 커밋한다**

```powershell
gofmt -w cmd/provisioner
go test ./cmd/provisioner -count=1
go test ./... -count=1
go vet ./...
go build ./...
git diff --check
git add .env.example README.md cmd/provisioner compose.postgres.yaml
git commit -m "Feat: wire PostgreSQL runtime worker"
```

### Task 7: API 문서와 MVP 요청 fixture 정합화

**Files:**
- Modify: `docs/api/runtime-operations.md`
- Modify: `docs/api/secure-provisioner.openapi.yaml`
- Modify: `README.md`
- Modify: `internal/httpapi/create.go`
- Modify: `internal/httpapi/create_test.go`
- Modify: `examples/requests/create-multi-container.json`
- Create: `examples/requests/create-web-digest.json`
- Create: `examples/requests/create-pwn-digest.json`
- Create: `examples/requests/delete-ttl.json`
- Test: `internal/httpapi/openapi_auth_test.go`
- Test: `internal/httpapi/http_test.go`

**Interfaces:**
- Consumes: 최종 create/delete wire contract와 environment config
- Produces: Scheduler mock과 `test_ctf`가 복사해 사용할 canonical fixtures

- [ ] **Step 1: fixture 계약 테스트를 작성한다**

테스트는 세 JSON 파일을 strict decoder로 읽고 다음을 검증한다. 생성 요청 validation table에는 `web:latest`, tag-only image, 대문자 digest, 63자리 digest를 거부하고 lowercase 64자리 SHA-256 digest를 허용하는 경우를 추가한다.

```go
if request.IsolationProfile != "WEB" && request.IsolationProfile != "PWN" {
	t.Fatalf("unexpected isolation_profile %q", request.IsolationProfile)
}
if !strings.Contains(request.Workload.Containers[0].Image, "@sha256:") {
	t.Fatal("fixture image is not digest pinned")
}
```

TTL fixture는 `delete_reason == "TTL_EXPIRED"`를 검증한다.

- [ ] **Step 2: 현재 fixture에서 테스트가 실패하는지 확인한다**

```powershell
go test ./internal/httpapi -run "Documented|OpenAPI|Fixture" -count=1
```

Expected: 새 digest fixture가 없어 FAIL.

- [ ] **Step 3: canonical digest validator를 구현한다**

`internal/httpapi/create.go`에 registry/name과 digest를 분리해 검사하는 함수를 추가한다.

```go
func validImmutableImageReference(value string) bool {
	name, digest, found := strings.Cut(value, "@sha256:")
	if !found || name == "" || digest == "" || strings.Contains(name, "@") {
		return false
	}
	if name != strings.ToLower(name) || len(digest) != 64 {
		return false
	}
	lastSlash := strings.LastIndex(name, "/")
	if strings.Contains(name[lastSlash+1:], ":") {
		return false
	}
	for _, character := range digest {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' { return false }
		}
	}
	return !strings.ContainsAny(name, " \t\r\n")
}
```

legacy single-container 입력과 `containers[]` 입력 모두 같은 validator를 사용한다. invalid image는 `INVALID_REQUEST`로 enqueue 전에 거부한다.

- [ ] **Step 4: 현재 계약만 문서화한다**

예제에서 다음 구형 필드를 제거한다.

```text
challenge_ref
isolation_ref
resource_profile_ref
outbound_mode
```

`isolation_profile`, digest image, containers 배열, internal connections, resource limits와 endpoint 배열만 유지한다.

- [ ] **Step 5: 문서 계약 검증과 커밋을 수행한다**

```powershell
go test ./internal/httpapi ./cmd/provisioner -count=1
git diff --check
git add README.md docs/api examples/requests internal/httpapi
git commit -m "Docs: align MVP runtime integration contract"
```

### Task 8: PostgreSQL 동시 요청과 재시작 검증

**Files:**
- Create: `tests/workerload/postgres_worker_test.go`
- Create: `tests/integration/postgres_runtime_test.go`
- Create: `scripts/test-postgres-runtime.ps1`

**Interfaces:**
- Consumes: 실제 PostgreSQL store와 mock runtime executor
- Produces: 500요청, 멱등성, lease recovery, graceful restart 증거

- [ ] **Step 1: 500개 enqueue와 중복 요청 테스트를 작성한다**

```go
const requestCount = 500
// 500개의 고유 request_id를 동시에 EnqueueCreate하고 모든 호출 완료 후
// runtime_operations의 row 수가 정확히 500인지 검증한다.
```

동일 payload 100개 동시 요청은 operation 한 개, 같은 request id의 다른 payload는 모두 `ErrIdempotencyConflict`인지 검증한다.

- [ ] **Step 2: lease 회수와 재시작 테스트를 작성한다**

첫 store가 operation을 claim한 뒤 terminal update 없이 종료되고, lease 이후 두 번째 store가 같은 operation을 더 높은 version으로 회수하는지 검증한다. stale 첫 claim의 완료 update는 `ErrLeaseLost`여야 한다.

- [ ] **Step 3: 실제 PostgreSQL에서 새 테스트가 통과하는지 확인한다**

```powershell
$env:PROVISIONER_TEST_DATABASE_URL = "postgres://provisioner:provisioner@127.0.0.1:54329/provisioner_test?sslmode=disable"
go test ./tests/workerload ./tests/integration -count=1 -timeout 5m
```

Expected: 500 unique rows, duplicate operation 1개, expired lease recovery PASS.

- [ ] **Step 4: race 및 전체 정적 검증을 수행한다**

```powershell
go test -race ./internal/operations ./internal/runtimeops ./internal/runtimebinding -count=1
go test ./... -count=1
go vet ./...
go build ./...
git diff --check
```

- [ ] **Step 5: load 검증을 커밋한다**

```powershell
git add tests/workerload tests/integration scripts/test-postgres-runtime.ps1
git commit -m "Test: verify PostgreSQL worker load and recovery"
```

### Task 9: mock 상호작용 smoke test와 통합 브랜치 마감

**Files:**
- Create: `tests/integration/mvp_interaction_test.go`
- Create: `scripts/test-mvp-interaction.ps1`
- Modify: `README.md`

**Interfaces:**
- Consumes: authenticated API, PostgreSQL worker, target registry, canonical fixtures
- Produces: Scheduler/Broker mock 생성·조회·삭제·TTL 상호작용 smoke test

- [ ] **Step 1: mock 호출 흐름 테스트를 작성한다**

테스트 순서는 다음과 같이 고정한다.

```text
unauthenticated create -> 401
authenticated WEB create -> 202 QUEUED
operation polling -> SUCCEEDED
runtime status -> binding target/namespace 확인
TTL delete request -> 202 QUEUED
delete operation polling -> SUCCEEDED
runtime status -> TERMINATED
same TTL request retry -> 기존 operation 반환
```

- [ ] **Step 2: fake K3s adapter와 PostgreSQL로 smoke test를 실행한다**

```powershell
$env:PROVISIONER_TEST_DATABASE_URL = "postgres://provisioner:provisioner@127.0.0.1:54329/provisioner_test?sslmode=disable"
go test ./tests/integration -run "MVPInteraction" -count=1 -timeout 3m
```

Expected: 모든 상태 전이와 인증 경계 PASS.

- [ ] **Step 3: 실제 K3s 검증은 환경변수 opt-in으로 유지한다**

실제 AWS/GCP 호출은 기본 `go test ./...`에서 실행하지 않는다. `K3S_INTEGRATION_*` 환경변수가 모두 있을 때만 WEB/PWN live smoke test를 실행하며, 이번 로컬 병합 단계에서는 사용자 요청 전까지 실행하지 않는다.

- [ ] **Step 4: 최종 검증을 새로 실행한다**

```powershell
gofmt -w cmd internal tests
go test ./... -count=1
go test -race ./internal/operations ./internal/runtimeops ./internal/runtimebinding -count=1
go vet ./...
go build ./...
git diff --check
git status --short
```

Expected: 모든 명령 exit 0, 의도하지 않은 untracked 파일 없음.

- [ ] **Step 5: 통합 결과를 커밋하고 원격 전 상태를 보고한다**

```powershell
git add README.md tests/integration/mvp_interaction_test.go scripts/test-mvp-interaction.ps1
git commit -m "Test: cover Provisioner MVP interactions"
git log --oneline origin/dev..HEAD
git diff --stat origin/dev...HEAD
```

원격 push와 Draft PR 생성은 사용자에게 로컬 검증 결과와 변경 범위를 보고한 뒤 별도 승인을 받아 수행한다.
