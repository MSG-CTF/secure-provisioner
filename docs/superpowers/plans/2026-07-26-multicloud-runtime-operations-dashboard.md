# Multicloud Runtime Operations Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local Provisioner dashboard that shows target-routed K3s container status and resource usage, and safely deletes the selected instance through the same runtime service.

**Architecture:** A concurrency-safe binding store maps `instance_id` to `target_id`, Namespace, and runtime workload ID. A K3s runtime service resolves exactly one Cluster Registry entry, reads Pod status and optional Metrics API usage, and performs ownership-checked idempotent Namespace deletion. A loopback-only local dashboard consumes JSON endpoints backed by the same service; the AWS integration test uses the existing `k3s-lab` target without exposing credentials or cluster addresses.

**Tech Stack:** Go 1.26, `net/http`, embedded HTML/CSS/JavaScript, Kubernetes `client-go` v0.36.2, `k8s.io/metrics` v0.36.2, fake clientsets, AWS CLI for read-only target discovery.

## Global Constraints

- Normal lookup and deletion must resolve one stored `target_id`; never fan out across clusters.
- Kubeconfig contents, Kubernetes API URLs, AWS credentials, Pod environment variables, and Secrets must not appear in responses, logs, committed files, or test failure text.
- The dashboard is disabled by default and must bind to loopback for local use.
- Missing Metrics API data is a partial success: return status and configured resources with `usage: null`.
- Deletion is idempotent and must verify Namespace ownership before issuing a delete.
- The in-memory binding store is explicitly local/test-only; the interface must permit a PostgreSQL adapter without API changes.
- AWS integration tests must create a unique Namespace and remove only that Namespace in `t.Cleanup`.

---

## File Structure

- `internal/runtimebinding/binding.go`: binding model, states, errors, and Store interface.
- `internal/runtimebinding/memory_store.go`: concurrency-safe local Store implementation.
- `internal/runtimebinding/memory_store_test.go`: idempotency, conflict, and transition tests.
- `internal/k3s/cluster.go`: add Metrics Client and creation/maintenance lookup semantics.
- `internal/k3s/config.go`: construct Kubernetes and Metrics clients from one REST config.
- `internal/k3s/registry.go`: route create versus maintenance operations.
- `internal/k3s/status.go`: Pod, container, resource, endpoint, and metrics status reader.
- `internal/k3s/status_test.go`: multi-target routing and status/metrics merge tests.
- `internal/k3s/delete_adapter.go`: ownership-checked idempotent Namespace deletion.
- `internal/k3s/delete_adapter_test.go`: routing, ownership, NotFound, and timeout tests.
- `internal/k3s/executor.go`: support DELETE operations.
- `internal/k3s/executor_test.go`: CREATE and DELETE result/error contract tests.
- `internal/runtimeops/service.go`: binding-aware create recording, status lookup, and delete enqueue/execute facade.
- `internal/runtimeops/service_test.go`: binding mismatch and single-target behavior tests.
- `internal/runtimeops/demo.go`: deterministic local sample status used only when demo mode is selected.
- `internal/httpapi/runtime.go`: runtime status and deletion DTOs/handlers.
- `internal/httpapi/runtime_test.go`: HTTP route, validation, and redaction tests.
- `internal/httpapi/http.go`: optional runtime API and dashboard route registration.
- `internal/dashboard/dashboard.go`: embedded dashboard handler.
- `internal/dashboard/web/index.html`: local UI.
- `internal/dashboard/dashboard_test.go`: disabled/default and HTML smoke tests.
- `cmd/runtime-dashboard/main.go`: loopback local server in demo or registry-backed mode.
- `internal/k3s/integration_test.go`: extend opt-in AWS test to create, read, and delete.
- `README.md`: local dashboard run instructions without real credentials or addresses.

---

### Task 1: Instance Runtime Binding Store

**Files:**
- Create: `internal/runtimebinding/binding.go`
- Create: `internal/runtimebinding/memory_store.go`
- Create: `internal/runtimebinding/memory_store_test.go`

**Interfaces:**
- Produces: `runtimebinding.Binding`, `runtimebinding.State`, `runtimebinding.Store`, `runtimebinding.NewMemoryStore()`.
- Consumes: no earlier task interfaces.

- [ ] **Step 1: Write failing Store tests**

Cover these exact cases in `memory_store_test.go`:

```go
func TestMemoryStoreSavesAndReturnsIndependentBinding(t *testing.T)
func TestMemoryStoreAcceptsIdenticalCreateAsIdempotent(t *testing.T)
func TestMemoryStoreRejectsDifferentTargetForSameInstance(t *testing.T)
func TestMemoryStoreTransitionsCreatedDeletingDeleted(t *testing.T)
func TestMemoryStoreRejectsDeletingToCreatedRegression(t *testing.T)
```

Use a UUID instance, `TargetID: "aws-dev"`, `Namespace: "ctf-..."`, and `RuntimeWorkloadID: "aws-dev/ctf-.../challenge"`. Mutate returned values and assert the stored value is unchanged.

- [ ] **Step 2: Run tests and verify RED**

Run:

```text
go test -count=1 ./internal/runtimebinding
```

Expected: compile failure because the package and Store types do not exist.

- [ ] **Step 3: Define model and Store**

Implement:

```go
type State string

const (
    StateCreated  State = "CREATED"
    StateDeleting State = "DELETING"
    StateDeleted  State = "DELETED"
)

type Binding struct {
    InstanceID        string
    TeamID            int64
    TargetID          string
    Namespace         string
    RuntimeWorkloadID string
    State             State
    CreatedAt         time.Time
    UpdatedAt         time.Time
    DeletedAt         *time.Time
}

type Store interface {
    SaveCreated(Binding) (Binding, bool, error)
    Get(string) (Binding, error)
    MarkDeleting(string, time.Time) (Binding, error)
    MarkDeleted(string, time.Time) (Binding, error)
}
```

Define stable errors `ErrNotFound`, `ErrConflict`, `ErrInvalidBinding`, and `ErrInvalidTransition`.

- [ ] **Step 4: Implement the mutex-protected Store**

Validate non-empty identifiers, positive team ID, and `StateCreated` on first save. Identical `SaveCreated` returns the existing value with `created=false`; a different team, target, Namespace, or workload returns `ErrConflict`.

- [ ] **Step 5: Run tests and verify GREEN**

Run:

```text
go test -count=1 ./internal/runtimebinding
```

Expected: PASS.

- [ ] **Step 6: Commit**

```text
git add internal/runtimebinding
git commit -m "Feat: 인스턴스 런타임 위치 저장소 추가"
```

---

### Task 2: Target-Scoped Status and Metrics Reader

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `internal/k3s/cluster.go`
- Modify: `internal/k3s/config.go`
- Modify: `internal/k3s/config_test.go`
- Modify: `internal/k3s/registry.go`
- Modify: `internal/k3s/registry_test.go`
- Create: `internal/k3s/status.go`
- Create: `internal/k3s/status_test.go`

**Interfaces:**
- Consumes: `runtimebinding.Binding`.
- Produces: `k3s.RuntimeStatus`, `k3s.ContainerRuntimeStatus`, `(*StatusReader).Get(context.Context, runtimebinding.Binding)`.

- [ ] **Step 1: Add the metrics dependency**

Run:

```text
go get k8s.io/metrics@v0.36.2
```

Expected: `go.mod` gains direct `k8s.io/metrics v0.36.2` and `go.sum` updates.

- [ ] **Step 2: Write failing Registry client-pair tests**

Add tests proving:

```go
func TestRegistryUsesDistinctKubeAndMetricsClientsPerTarget(t *testing.T)
func TestRegistryMaintenanceLookupAllowsPlacementDisabledTarget(t *testing.T)
func TestRegistryCreateLookupRejectsPlacementDisabledTarget(t *testing.T)
```

Change `ClientFactory` to return:

```go
type ClientSet struct {
    Kubernetes kubernetes.Interface
    Metrics    metricsclient.Interface
}

type ClientFactory interface {
    FromKubeconfig(string) (ClientSet, error)
}
```

- [ ] **Step 3: Run Registry tests and verify RED**

Run:

```text
go test -count=1 ./internal/k3s -run "Registry|Config"
```

Expected: compile failures for the missing ClientSet and lookup methods.

- [ ] **Step 4: Implement paired client construction and Registry lookups**

Build one `*rest.Config` with `clientcmd.BuildConfigFromFlags`, then construct `kubernetes.NewForConfig` and `metricsclient.NewForConfig`. Store both in `Cluster`. Rename existing `Lookup` behavior to `LookupForCreate` and retain `Lookup` as a compatibility alias during this feature. Add `LookupForMaintenance` that returns configured disabled targets with initialized clients.

- [ ] **Step 5: Write failing status mapping tests**

Use fake Kubernetes and Metrics clientsets to cover:

```go
func TestStatusReaderRoutesOnlyToBindingTarget(t *testing.T)
func TestStatusReaderMapsRunningContainerAndResources(t *testing.T)
func TestStatusReaderMapsWaitingAndTerminatedReasons(t *testing.T)
func TestStatusReaderReturnsPartialSuccessWhenMetricsAreMissing(t *testing.T)
func TestStatusReaderRejectsNamespaceOwnershipMismatch(t *testing.T)
func TestStatusReaderReturnsProvisioningWhenNoPodsExist(t *testing.T)
```

The expected model contains:

```go
type RuntimeStatus struct {
    InstanceID        string
    TargetID          string
    RuntimeWorkloadID string
    Phase             string
    EndpointReady     bool
    MetricsAvailable  bool
    ObservedAt        time.Time
    Containers        []ContainerRuntimeStatus
}
```

Each container includes Pod name, container name, state, Ready, restart count, reason, exit code, timestamps, requests, limits, and nullable usage.

- [ ] **Step 6: Run status tests and verify RED**

Run:

```text
go test -count=1 ./internal/k3s -run StatusReader
```

Expected: compile failure because `StatusReader` does not exist.

- [ ] **Step 7: Implement minimal status reader**

Resolve `binding.TargetID` with `LookupForMaintenance`; fetch Namespace and verify `msgctf.io/instance-id`. List Pods with the managed workload labels. Merge `Pod.Status.ContainerStatuses` with `Pod.Spec.Containers` and `PodMetrics.Containers` by Pod and container name. Query EndpointSlices and derive a stable phase without exposing Kubernetes API details.

Metrics `NotFound`, `ServiceUnavailable`, and empty samples set `MetricsAvailable=false` and leave usage nil. Other Kubernetes status failures return a redacted `RuntimeError`.

- [ ] **Step 8: Run status and full K3s tests**

Run:

```text
go test -count=1 ./internal/k3s
```

Expected: PASS.

- [ ] **Step 9: Commit**

```text
git add go.mod go.sum internal/k3s
git commit -m "Feat: target 기반 컨테이너 런타임 상태 조회"
```

---

### Task 3: Idempotent Target-Routed Delete Adapter

**Files:**
- Create: `internal/k3s/delete_adapter.go`
- Create: `internal/k3s/delete_adapter_test.go`
- Modify: `internal/k3s/executor.go`
- Modify: `internal/k3s/executor_test.go`

**Interfaces:**
- Consumes: `runtimebinding.Binding`, existing `operations.Operation`.
- Produces: `(*DeleteAdapter).DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error`.

- [ ] **Step 1: Write failing DeleteAdapter tests**

Cover:

```go
func TestDeleteAdapterUsesOnlyStoredTarget(t *testing.T)
func TestDeleteAdapterTreatsMissingNamespaceAsSuccess(t *testing.T)
func TestDeleteAdapterRejectsForeignInstanceOwnership(t *testing.T)
func TestDeleteAdapterRejectsCommandBindingMismatch(t *testing.T)
func TestDeleteAdapterWaitsUntilNamespaceIsNotFound(t *testing.T)
func TestDeleteAdapterClassifiesAPITimeoutAsRetryable(t *testing.T)
func TestDeleteAdapterSerializesCreateAndDeleteForSameWorkload(t *testing.T)
```

Assert no delete action is recorded for mismatch cases.

- [ ] **Step 2: Run tests and verify RED**

Run:

```text
go test -count=1 ./internal/k3s -run DeleteAdapter
```

Expected: compile failure because `DeleteAdapter` is missing.

- [ ] **Step 3: Implement DeleteAdapter**

Use the existing `workloadLocks` key `(target_id, instance_id)`. Compare command instance, team, target, and runtime workload with Binding before Registry lookup. Verify Namespace labels before `Delete`. Poll until `IsNotFound` using bounded `DeleteTimeout` and `PollInterval`.

- [ ] **Step 4: Extend Executor tests for DELETE**

Add a binding-aware delete facade to Executor and assert:

```go
OperationResult{DeleteCompleted: true}
```

for success. Ensure runtime errors are mapped through their stable code and retryability just as CREATE errors are.

- [ ] **Step 5: Run K3s tests**

Run:

```text
go test -count=1 ./internal/k3s
```

Expected: PASS.

- [ ] **Step 6: Commit**

```text
git add internal/k3s
git commit -m "Feat: 멱등 K3s 인스턴스 삭제 추가"
```

---

### Task 4: Binding-Aware Runtime Service and HTTP API

**Files:**
- Create: `internal/runtimeops/service.go`
- Create: `internal/runtimeops/service_test.go`
- Create: `internal/runtimeops/demo.go`
- Create: `internal/httpapi/runtime.go`
- Create: `internal/httpapi/runtime_test.go`
- Modify: `internal/httpapi/http.go`
- Modify: `internal/httpapi/http_test.go`

**Interfaces:**
- Consumes: `runtimebinding.Store`, K3s create/status/delete interfaces, `operations.Store`.
- Produces: `runtimeops.Service`, `httpapi.RuntimeAPI`, and JSON routes.

- [ ] **Step 1: Write failing runtime service tests**

Cover:

```go
func TestServiceRecordsBindingAfterSuccessfulCreate(t *testing.T)
func TestServiceDoesNotRecordBindingAfterFailedCreate(t *testing.T)
func TestServiceReadsStatusFromStoredTarget(t *testing.T)
func TestServiceRejectsDeleteCommandThatConflictsWithBinding(t *testing.T)
func TestServiceEnqueuesIdempotentDeleteOperation(t *testing.T)
func TestServiceMarksBindingDeletedAfterSuccessfulDelete(t *testing.T)
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```text
go test -count=1 ./internal/runtimeops
```

Expected: compile failure because the package does not exist.

- [ ] **Step 3: Implement the service**

`CreateWorkload` delegates to the existing Create Adapter and records a Binding derived from `TargetID`, `NamespaceForInstance`, and the returned runtime workload ID. `GetRuntimeStatus` loads the Binding and delegates to StatusReader. `EnqueueDelete` validates the request against the Binding and uses the existing Operation Store.

Provide `NewDemoService()` with two deterministic sample containers, one Running and one Waiting, so the dashboard can be shown without AWS credentials. Demo deletion transitions the sample through DELETING to DELETED without touching Kubernetes.

- [ ] **Step 4: Write failing HTTP tests**

Cover:

```go
func TestRuntimeStatusEndpointReturnsContainerRows(t *testing.T)
func TestRuntimeStatusEndpointReturnsNotFound(t *testing.T)
func TestDeleteEndpointValidatesJSONAndEnqueuesOperation(t *testing.T)
func TestOperationEndpointReturnsCurrentState(t *testing.T)
func TestRuntimeErrorsDoNotExposePrivateCause(t *testing.T)
```

Routes:

```text
GET /internal/v1/instances/{instance_id}/runtime-status
DELETE /internal/v1/instances/{instance_id}
GET /internal/v1/operations/{operation_id}
```

- [ ] **Step 5: Run HTTP tests and verify RED**

Run:

```text
go test -count=1 ./internal/httpapi -run "Runtime|Delete|Operation"
```

Expected: route failures because runtime handlers are not registered.

- [ ] **Step 6: Implement optional runtime routes**

Keep `NewHandler(createWorkload)` backward-compatible. Add:

```go
func NewHandlerWithRuntime(create provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase) http.Handler
```

The runtime use case interface exposes status, enqueue delete, and get operation. Map stable domain errors to the exact error contract from the design.

- [ ] **Step 7: Run service and HTTP tests**

Run:

```text
go test -count=1 ./internal/runtimeops ./internal/httpapi
```

Expected: PASS.

- [ ] **Step 8: Commit**

```text
git add internal/runtimeops internal/httpapi
git commit -m "Feat: 런타임 상태 및 삭제 내부 API 추가"
```

---

### Task 5: Loopback Test Dashboard

**Files:**
- Create: `internal/dashboard/dashboard.go`
- Create: `internal/dashboard/dashboard_test.go`
- Create: `internal/dashboard/web/index.html`
- Create: `cmd/runtime-dashboard/main.go`
- Modify: `README.md`

**Interfaces:**
- Consumes: runtime status, delete, and operation JSON routes from Task 4.
- Produces: `dashboard.Handler(api http.Handler) http.Handler` and `cmd/runtime-dashboard`.

- [ ] **Step 1: Write failing dashboard handler tests**

Cover:

```go
func TestHandlerServesDashboardAtRoot(t *testing.T)
func TestDashboardContainsStatusResourceAndDeleteControls(t *testing.T)
func TestHandlerDelegatesInternalAPIRoutes(t *testing.T)
func TestDashboardDoesNotContainCredentialOrClusterAddressFields(t *testing.T)
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```text
go test -count=1 ./internal/dashboard
```

Expected: compile failure because the package does not exist.

- [ ] **Step 3: Implement dashboard HTML**

Create a responsive single-page dashboard with:

- a top bar labeled “Secure Provisioner / Runtime Monitor”;
- instance ID input and refresh control;
- phase, target, endpoint, metrics, and observed-at summary cards;
- container table with state badge, Ready, restarts, reason, requests, limits, and usage;
- deletion confirmation panel;
- operation progress and error banner;
- five-second optional auto-refresh;
- an explicit “Local test dashboard” indicator.

Use only same-origin `fetch()` calls. Render text with `textContent`, not `innerHTML`, for API values. Do not include a field for kubeconfig, API URL, AWS access key, or public IP.

- [ ] **Step 4: Implement the dashboard command**

Support:

```text
go run ./cmd/runtime-dashboard -mode demo -addr 127.0.0.1:18081
go run ./cmd/runtime-dashboard -mode registry -addr 127.0.0.1:18081 -registry <external-json>
```

Reject non-loopback addresses unless `PROVISIONER_ALLOW_REMOTE_TEST_DASHBOARD=true`. Demo mode uses `runtimeops.NewDemoService()`. Registry mode loads external K3s configuration and never prints its contents.

- [ ] **Step 5: Run dashboard and repository tests**

Run:

```text
go test -count=1 ./internal/dashboard ./cmd/runtime-dashboard
go test -count=1 ./...
```

Expected: PASS.

- [ ] **Step 6: Render and inspect the UI**

Run:

```text
go run ./cmd/runtime-dashboard -mode demo -addr 127.0.0.1:18081
```

Open `http://127.0.0.1:18081`, load the seeded instance, verify no horizontal overflow at 1440×900 and 390×844, trigger refresh, and exercise the deletion confirmation without accepting deletion on the first visual pass.

- [ ] **Step 7: Commit**

```text
git add internal/dashboard cmd/runtime-dashboard README.md
git commit -m "Feat: 로컬 런타임 상태 대시보드 추가"
```

---

### Task 6: AWS K3s Create-Read-Delete Integration

**Files:**
- Modify: `internal/k3s/integration_test.go`
- Modify: `README.md`

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces: opt-in AWS K3s create→status→delete integration coverage.

- [ ] **Step 1: Extend the integration test**

After existing create assertions:

1. Save a Binding for the generated instance.
2. Call StatusReader and require at least one Ready Running challenge container.
3. Require configured CPU, memory, and ephemeral-storage values to match the command.
4. Accept either available usage or explicit metrics-unavailable partial success.
5. Call DeleteAdapter.
6. Confirm Namespace `NotFound`.
7. Call DeleteAdapter again and require success.

Keep `t.Cleanup` as a final safety net.

- [ ] **Step 2: Run ordinary tests and confirm AWS test skips without secrets**

Run:

```text
go test -count=1 ./...
```

Expected: PASS with the AWS integration test skipped when its environment variables are absent.

- [ ] **Step 3: Verify the AWS target read-only**

Run AWS CLI queries for caller identity and the running EC2 with tag `Name=k3s-lab` in `ap-northeast-2`. Do not write the account ID, instance ID, public IP, or credentials to repository files.

- [ ] **Step 4: Establish temporary protected K3s access**

Use the existing local private key and a hidden SSH tunnel or a temporary kubeconfig outside the repository. Store temporary files under a generated temporary directory, permission-restrict them, and remove them after the test. Never print kubeconfig content.

- [ ] **Step 5: Run the AWS integration test**

Set the existing `K3S_INTEGRATION_TARGET_ID`, `K3S_INTEGRATION_KUBECONFIG`, `K3S_INTEGRATION_PUBLIC_GATEWAY`, `K3S_INTEGRATION_IMAGE`, and `K3S_INTEGRATION_CONTAINER_PORT` only in the process environment, then run:

```text
go test -count=1 -run TestK3sIntegrationCreateReadyAndCleanup -v ./internal/k3s
```

Expected: PASS.

- [ ] **Step 6: Verify cleanup**

Confirm the generated Namespace is `NotFound`, terminate the SSH tunnel, remove the temporary kubeconfig, and ensure no repository file contains target addresses or credentials.

- [ ] **Step 7: Commit**

```text
git add internal/k3s/integration_test.go README.md
git commit -m "Test: AWS K3s 조회 및 삭제 통합 검증"
```

---

### Task 7: Final Verification and UI Evidence

**Files:**
- No feature files unless verification reveals a defect.

**Interfaces:**
- Consumes: all previous tasks.
- Produces: verified branch and dashboard screenshot.

- [ ] **Step 1: Run full verification**

```text
go test -count=1 ./...
go vet -buildvcs=false ./...
go build -buildvcs=false ./...
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 2: Inspect repository safety**

Search tracked changes for kubeconfig content, AWS access key patterns, private key material, Authorization headers, public addresses, and challenge secrets. Expected: no real sensitive value.

- [ ] **Step 3: Capture the local UI**

Run the demo dashboard, open it in the in-app browser, verify the seeded container status and resource rows, and capture a 1440×900 screenshot for the user.

- [ ] **Step 4: Review branch state**

Confirm only intended feature, test, documentation, design, and plan files differ from `8fe5192`. Confirm the AWS test created no persistent Namespace and no temporary tunnel or kubeconfig remains.

- [ ] **Step 5: Commit verification fixes if necessary**

If verification required code changes, commit each focused fix with a `Fix:` message and rerun Steps 1–4. If no fix was needed, create no empty commit.
