# Simple Isolation Profile API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace externally supplied policy refs with one required `isolation_profile: WEB | PWN`, preserve the multi-container runtime contract, and verify the resolved isolation on the configured AWS K3s target.

**Architecture:** The HTTP boundary accepts a small Scheduler-owned profile label and numeric runtime specification. `isolation.StaticResolver` maps that label to immutable internal `STANDARD@v1 + WEB@v1/PWN@v1 + outbound NONE` decisions, while operations, runtime bindings, and the K3s adapter retain the resolved policy needed for idempotency and deletion. The existing asynchronous worker remains the execution engine; this change alters its immutable command payload, not its queue or retry algorithm.

**Tech Stack:** Go 1.24, `net/http`, Kubernetes `client-go`, K3s, gVisor `RuntimeClass`, OpenAPI 3, AWS CLI, Go test/race/vet/build.

## Global Constraints

- JSON contract field names remain snake_case.
- `isolation_profile` is required and accepts exactly `WEB` or `PWN`; missing or unknown values fail closed.
- `STANDARD@v1` and outbound `NONE` are internal constants and cannot be weakened by callers.
- `challenge_ref`, `isolation_ref`, `workload_profile_ref`, `resource_profile_ref`, and `workload.outbound_mode` are removed from the new wire contract.
- `workload.containers[]`, optional `internal_connections`, and Scheduler-supplied numeric `resource_limits` remain.
- Deprecated `workload.image` plus `workload.container_port` remains one-container compatibility input but still requires `isolation_profile`.
- Pwn requires gVisor, NodePort, exactly one exposed container/port, and writable paths only under `/tmp`.
- Every rendered Kubernetes container uses `imagePullPolicy: IfNotPresent`.
- Production behavior changes must follow a witnessed RED-GREEN TDD cycle.
- The user's dirty main worktree is not modified; all changes stay on `feat/web-pwn-isolation-profiles` in `.worktrees/web-pwn-isolation`.

---

### Task 1: Simplify the isolation domain and resolver

**Files:**
- Modify: `internal/isolation/profile.go`
- Modify: `internal/isolation/static_resolver.go`
- Modify: `internal/isolation/static_resolver_test.go`

**Interfaces:**
- Consumes: `ContainerRequirement`, `InternalConnection`, and Scheduler numeric `ResourceLimits`.
- Produces: `type WorkloadProfile string`, constants `WorkloadProfileWeb` and `WorkloadProfilePwn`, a reduced `isolation.Request`, and the existing canonical `ResolvedPolicy` without challenge/resource-profile identities.

- [ ] **Step 1: Write failing resolver tests for implicit baseline, outbound, and arbitrary positive resource limits**

Replace ref-oriented fixtures with literal requests such as:

```go
request := isolation.Request{
    WorkloadProfile: isolation.WorkloadProfileWeb,
    Containers: []isolation.ContainerRequirement{{
        Name: "web", Ports: []int{8080}, Expose: true, RunAsUser: 10001,
    }},
    ResourceLimits: isolation.ResourceLimits{
        CPUMillicores: 350, MemoryMiB: 384, EphemeralStorageMiB: 700,
    },
}
got, err := isolation.NewStaticResolver().Resolve(request)
if err != nil { t.Fatal(err) }
if got.IsolationRef != (isolation.ProfileRef{Name: "STANDARD", Version: "v1"}) ||
    got.WorkloadProfileRef != (isolation.ProfileRef{Name: "WEB", Version: "v1"}) ||
    got.OutboundMode != isolation.OutboundNone ||
    got.ResourceLimits != request.ResourceLimits {
    t.Fatalf("resolved policy = %#v", got)
}
```

Add literal rejection cases for an empty/unknown profile, zero/negative limits, Web with no exposed container, and existing Pwn constraints.

- [ ] **Step 2: Run the resolver tests and verify RED**

Run: `go test ./internal/isolation -run 'TestStaticResolver' -count=1`

Expected: compile/failure because `WorkloadProfile` and the reduced request do not exist and the old resolver still requires named refs.

- [ ] **Step 3: Implement the reduced domain and static mapping**

Define the external semantic enum in `profile.go`:

```go
type WorkloadProfile string

const (
    WorkloadProfileWeb WorkloadProfile = "WEB"
    WorkloadProfilePwn WorkloadProfile = "PWN"
)

type Request struct {
    WorkloadProfile     WorkloadProfile
    Containers          []ContainerRequirement
    InternalConnections []InternalConnection
    ResourceLimits      ResourceLimits
}
```

Remove `ChallengeID` and `ResourceRef` from `ResolvedPolicy`, retain canonical internal refs and fixed `OutboundMode`, and resolve as:

```go
workloadRef := ProfileRef{Name: string(request.WorkloadProfile), Version: "v1"}
runtimeClass, protocol, exposure, err := resolveWorkloadProfile(workloadRef)
if err != nil {
    return ResolvedPolicy{}, err
}
if request.ResourceLimits.CPUMillicores <= 0 || request.ResourceLimits.MemoryMiB <= 0 ||
    request.ResourceLimits.EphemeralStorageMiB <= 0 {
    return ResolvedPolicy{}, rejected("resource limits must be positive")
}
if err := validateContainers(request.Containers, request.ResourceLimits); err != nil {
    return ResolvedPolicy{}, err
}
if err := validateWorkloadProfile(workloadRef, request.Containers); err != nil {
    return ResolvedPolicy{}, err
}
if err := validateInternalConnections(request.Containers, request.InternalConnections); err != nil {
    return ResolvedPolicy{}, err
}
return ResolvedPolicy{
    IsolationRef: ProfileRef{Name: "STANDARD", Version: "v1"},
    WorkloadProfileRef: workloadRef,
    RuntimeClassName: runtimeClass,
    EndpointProtocol: protocol,
    ExposureRequirement: exposure,
    Baseline: standardBaseline(),
    Containers: cloneContainerRequirements(request.Containers),
    InternalConnections: append([]InternalConnection(nil), request.InternalConnections...),
    OutboundMode: OutboundNone,
    ResourceLimits: request.ResourceLimits,
}, nil
```

- [ ] **Step 4: Run resolver tests and verify GREEN**

Run: `go test ./internal/isolation -count=1`

Expected: PASS.

- [ ] **Step 5: Commit the isolation domain change**

```bash
git add internal/isolation/profile.go internal/isolation/static_resolver.go internal/isolation/static_resolver_test.go
git commit -m "Refactor isolation profiles behind one label"
```

### Task 2: Replace the HTTP create contract and command payload

**Files:**
- Modify: `internal/httpapi/create.go`
- Modify: `internal/httpapi/create_test.go`
- Modify: `internal/httpapi/http_test.go`
- Modify: `internal/provisioner/create.go`
- Modify: `internal/provisioner/create_test.go`

**Interfaces:**
- Consumes: Task 1 `isolation.WorkloadProfile` and reduced `isolation.Request`.
- Produces: `CreateWorkloadRequest.IsolationProfile string` serialized as `isolation_profile`, and `provisioner.CreateWorkloadCommand` without `ChallengeRef`.

- [ ] **Step 1: Write failing API contract tests**

Use a literal valid request containing:

```json
{
  "request_id":"runtime-create-018f3f1e",
  "instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id":"00000000-0000-4000-8000-000000000018",
  "isolation_profile":"WEB",
  "target":{"runtime_type":"KUBERNETES","target_id":"aws-k3s-001"},
  "workload":{
    "containers":[{"name":"web","image":"ghcr.io/msg-ctf/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ports":[8080],"expose":true,"run_as_user":10001}],
    "resource_limits":{"cpu_millicores":350,"memory_mib":384,"ephemeral_storage_mib":700}
  }
}
```

Assert observable results: decode succeeds, `ToCommand()` carries `WorkloadProfileWeb`, the unresolved policy snapshot fixes outbound to `NONE`, and numeric limits survive. Add table cases that reject missing/lowercase/unknown profiles and JSON containing each removed field. Preserve a test proving the deprecated single-container input normalizes to one exposed `challenge` container only when a valid profile is present.

- [ ] **Step 2: Run API tests and verify RED**

Run: `go test ./internal/httpapi ./internal/provisioner -count=1`

Expected: FAIL because the old request still exposes refs/outbound and defaults missing policy fields to Web.

- [ ] **Step 3: Implement the new request and conversion**

Change the wire structs to:

```go
type RuntimeWorkload struct {
    Image               string               `json:"image,omitempty"`
    ContainerPort       int                  `json:"container_port,omitempty"`
    Containers          []RuntimeContainer   `json:"containers,omitempty"`
    InternalConnections []InternalConnection `json:"internal_connections,omitempty"`
    ResourceLimits      ResourceLimits       `json:"resource_limits"`
}

type CreateWorkloadRequest struct {
    RequestID        string          `json:"request_id"`
    InstanceID       string          `json:"instance_id"`
    TeamID           int64           `json:"team_id"`
    IsolationProfile string          `json:"isolation_profile"`
    Target           RuntimeTarget   `json:"target"`
    Workload         RuntimeWorkload `json:"workload"`
}
```

Remove legacy policy-field detection/defaulting. Validate the exact enum and build:

```go
return isolation.Request{
    WorkloadProfile: isolation.WorkloadProfile(request.IsolationProfile),
    Containers: requirements,
    InternalConnections: connections,
    ResourceLimits: isolation.ResourceLimits{
        CPUMillicores: request.Workload.ResourceLimits.CPUMillicores,
        MemoryMiB: request.Workload.ResourceLimits.MemoryMiB,
        EphemeralStorageMiB: request.Workload.ResourceLimits.EphemeralStorageMiB,
    },
}
```

Remove `ChallengeRef` from `CreateWorkloadCommand`. Keep strict duplicate/unknown JSON rejection and existing async handler status/error behavior.

- [ ] **Step 4: Run API tests and verify GREEN**

Run: `go test ./internal/httpapi ./internal/provisioner -count=1`

Expected: PASS.

- [ ] **Step 5: Commit the API contract change**

```bash
git add internal/httpapi/create.go internal/httpapi/create_test.go internal/httpapi/http_test.go internal/provisioner/create.go internal/provisioner/create_test.go
git commit -m "Change create API to isolation profile label"
```

### Task 3: Carry the normalized policy through operations, worker, and bindings

**Files:**
- Modify: `internal/operations/operation.go`
- Modify: `internal/operations/operation_test.go`
- Modify: `internal/operations/executor_test.go`
- Modify: `internal/operations/worker_test.go`
- Modify: `internal/runtimeops/service.go`
- Modify: `internal/runtimeops/service_test.go`
- Modify: `internal/runtimebinding/binding.go`
- Modify: `internal/runtimebinding/memory_store_test.go`

**Interfaces:**
- Consumes: reduced `CreateWorkloadCommand`, `isolation.Request`, and `ResolvedPolicy`.
- Produces: queue-safe immutable copies and bindings with `IsolationProfile`, new `WorkloadProfile`, fixed outbound mode, requirements, connections, and numeric limits.

- [ ] **Step 1: Write failing operation and binding tests**

Update command fixtures to omit challenge/resource refs and assert that a copied queued operation is unaffected when the original profile, ports, writable paths, or connections are mutated. Assert a completed create stores:

```go
runtimebinding.Binding{
    IsolationProfile: "STANDARD@v1",
    WorkloadProfile:  "WEB@v1",
    OutboundMode:      isolation.OutboundNone,
    ResourceLimits:    resolved.ResourceLimits,
}
```

Add an idempotency case where only `WorkloadProfile` changes from WEB to PWN and `SameRequest` returns false.

- [ ] **Step 2: Run operation/runtime tests and verify RED**

Run: `go test ./internal/operations ./internal/runtimeops ./internal/runtimebinding -count=1`

Expected: compile/failure because obsolete challenge/resource fields remain and `Binding.WorkloadProfile` does not exist.

- [ ] **Step 3: Implement normalized operation copying and binding persistence**

Remove comparisons and persistence for `ChallengeRef`, `ChallengeID`, `ChallengeVersion`, and `ResourceProfile`. Add:

```go
type Binding struct {
    InstanceID            string
    TeamID                int64
    TargetID              string
    Namespace             string
    NamespaceUID          string
    RuntimeWorkloadID     string
    IsolationProfile      string
    WorkloadProfile       string
    ContainerRequirements []isolation.ContainerRequirement
    InternalConnections   []isolation.InternalConnection
    OutboundMode          isolation.OutboundMode
    ResourceLimits        isolation.ResourceLimits
    State                 State
    CreatedAt             time.Time
    UpdatedAt             time.Time
    DeletedAt             *time.Time
}
```

In `runtimeops.Service`, persist both canonical identities from the resolved policy. Preserve the worker's bounded queue, retry/backoff, timeout, checkpoint, and per-target concurrency behavior; only its queued command type changes.

- [ ] **Step 4: Run operation/runtime tests and verify GREEN**

Run: `go test ./internal/operations ./internal/runtimeops ./internal/runtimebinding -count=1`

Expected: PASS.

- [ ] **Step 5: Commit operation and binding changes**

```bash
git add internal/operations internal/runtimeops internal/runtimebinding
git commit -m "Persist resolved isolation profile in runtime jobs"
```

### Task 4: Update K3s rendering and integration fixtures

**Files:**
- Modify: `internal/k3s/security_resources.go`
- Modify: `internal/k3s/security_resources_test.go`
- Modify: `internal/k3s/resources.go`
- Modify: `internal/k3s/resources_test.go`
- Modify: `internal/k3s/adapter.go`
- Modify: `internal/k3s/adapter_test.go`
- Modify: `internal/k3s/integration_test.go`

**Interfaces:**
- Consumes: canonical resolved policy from Tasks 1-3.
- Produces: validated Kubernetes resources with fixed outbound isolation, profile-sensitive gVisor/endpoint behavior, stable spec hashing, and `PullIfNotPresent` images.

- [ ] **Step 1: Write failing K3s tests**

Update literal command fixtures to the new isolation request. Add or replace the pull-policy test with an observable rendered Pod assertion:

```go
resources, err := BuildResourceSet(validCluster("aws-dev"), validCreateCommand("aws-dev"))
if err != nil { t.Fatal(err) }
for _, deployment := range resources.Deployments {
    for _, container := range deployment.Spec.Template.Spec.Containers {
        if container.ImagePullPolicy != corev1.PullIfNotPresent {
            t.Fatalf("container %q pull policy = %q", container.Name, container.ImagePullPolicy)
        }
    }
}
```

Retain literal tests proving Pwn renders gVisor on every Deployment, Web omits RuntimeClass, DNS/internal-only NetworkPolicies are generated, and changing WEB to PWN changes the spec hash.

Add `TestK3sIntegrationPwnCreateReadyAndCleanup` behind the existing five
`K3S_INTEGRATION_*` environment variables. It constructs a NodePort Target with
`RuntimeClasses: []string{"gvisor"}`, resolves `WorkloadProfilePwn`, creates one
exposed port, and asserts all of these observable results before owned Namespace
cleanup:

```go
if len(result.Endpoints) != 1 || result.Endpoints[0].Protocol != isolation.EndpointProtocolTCP {
    t.Fatalf("Pwn endpoints = %#v", result.Endpoints)
}
deployment, err := cluster.Client.AppsV1().Deployments(namespace).Get(testCtx, resourceName, metav1.GetOptions{})
if err != nil { t.Fatal(err) }
if deployment.Spec.Template.Spec.RuntimeClassName == nil ||
    *deployment.Spec.Template.Spec.RuntimeClassName != "gvisor" {
    t.Fatalf("runtimeClassName = %#v", deployment.Spec.Template.Spec.RuntimeClassName)
}
service, err := cluster.Client.CoreV1().Services(namespace).Get(testCtx, resourceName, metav1.GetOptions{})
if err != nil { t.Fatal(err) }
if service.Spec.Type != corev1.ServiceTypeNodePort || service.Spec.Ports[0].NodePort == 0 {
    t.Fatalf("Pwn service = %#v", service.Spec)
}
```

- [ ] **Step 2: Run K3s tests and verify RED**

Run: `go test ./internal/k3s -count=1`

Expected: compile/failure from removed policy fields and tagged `:latest` images still rendering `PullAlways`.

- [ ] **Step 3: Implement K3s policy validation and pull behavior**

Remove the obsolete `ChallengeID` and `ResourceRef` checks/hash fields. Continue requiring canonical `STANDARD@v1`, `WEB@v1` or `PWN@v1`, fixed `NONE`, a secure baseline, positive limits, and profile constraints. Render every container with:

```go
if container.ImagePullPolicy == "" {
    container.ImagePullPolicy = corev1.PullIfNotPresent
}
```

Preserve an explicitly set policy only for internal tests/helpers; external create requests cannot supply one. Update live integration command construction to accept `isolation.WorkloadProfile` and raw limits rather than named refs.

- [ ] **Step 4: Run K3s tests and verify GREEN**

Run: `go test ./internal/k3s -count=1`

Expected: PASS, with live integration tests skipped unless their environment variables are present.

- [ ] **Step 5: Commit K3s rendering changes**

```bash
git add internal/k3s
git commit -m "Render simplified isolation policy on K3s"
```

### Task 5: Synchronize OpenAPI and runtime documentation

**Files:**
- Modify: `docs/api/secure-provisioner.openapi.yaml`
- Modify: `docs/api/runtime-operations.md`

**Interfaces:**
- Consumes: the tested HTTP contract from Task 2.
- Produces: Scheduler-facing schema and examples that match the handler exactly.

- [ ] **Step 1: Update OpenAPI schemas and examples**

Make `isolation_profile` required:

```yaml
IsolationProfile:
  type: string
  enum: [WEB, PWN]

CreateWorkloadRequest:
  type: object
  additionalProperties: false
  required: [request_id, instance_id, team_id, isolation_profile, target, workload]
  properties:
    isolation_profile:
      $ref: '#/components/schemas/IsolationProfile'
```

Remove the five retired request fields/schemas where unused, retain `containers`, optional `internal_connections`, numeric `resource_limits`, and deprecated annotations for `image` and `container_port`. Replace Web/Pwn examples with the approved snake_case contract.

- [ ] **Step 2: Update the runtime operations guide**

Document Scheduler/Provisioner responsibility, exact WEB/PWN validation, implicit `STANDARD@v1` and outbound `NONE`, `IfNotPresent` lazy-pull behavior, optional explicit internal connections, async polling, and the temporary single-container compatibility path.

- [ ] **Step 3: Validate documentation mechanically**

Run:

```powershell
go test ./internal/httpapi -count=1
git diff --check
rg -n 'challenge_ref|workload_profile_ref|resource_profile_ref|outbound_mode' docs/api
```

Expected: tests PASS, `git diff --check` has no output, and the final search returns only migration/removal prose rather than active request schemas or examples.

- [ ] **Step 4: Commit documentation**

```bash
git add docs/api/secure-provisioner.openapi.yaml docs/api/runtime-operations.md
git commit -m "Docs: publish simplified isolation API"
```

### Task 6: Full verification and AWS K3s smoke test

**Files:**
- Modify only if a witnessed failure requires a TDD fix: the smallest relevant file and its test.
- No committed production manifest is required; the integration test owns and cleans its generated Namespace.

**Interfaces:**
- Consumes: completed implementation, local AWS CLI credentials, target metadata, kubeconfig, public gateway, and a pullable test image.
- Produces: command evidence for local regression safety and real K3s Web/Pwn capability status.

- [ ] **Step 1: Run the complete local verification suite**

Run:

```powershell
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./...
git diff --check origin/dev...HEAD
```

Expected: every command exits 0.

- [ ] **Step 2: Inspect AWS identity and running target without mutating it**

Run:

```powershell
aws sts get-caller-identity
aws ec2 describe-instances --filters Name=instance-state-name,Values=running --query 'Reservations[].Instances[].{id:InstanceId,public_ip:PublicIpAddress,private_ip:PrivateIpAddress,name:Tags[?Key==`Name`]|[0].Value}' --output table
```

Expected: authenticated account/ARN and the intended K3s EC2 instance are visible. Resolve the exact target before any deployment or namespace creation.

- [ ] **Step 3: Verify K3s API and target capabilities**

Resolve the kubeconfig path from the secure local location or tunnel setup without printing its client key, then run:

```powershell
$kubeconfigPath = (Resolve-Path (Read-Host 'Absolute kubeconfig path')).Path
kubectl --kubeconfig $kubeconfigPath get nodes -o wide
kubectl --kubeconfig $kubeconfigPath get runtimeclass
kubectl --kubeconfig $kubeconfigPath -n kube-system get pods
```

Expected: node is Ready; NetworkPolicy provider/DNS are present; `RuntimeClass/gvisor` is present for a Pwn test. If gVisor is absent, record Pwn as a verified capability rejection instead of weakening the profile.

- [ ] **Step 4: Run the owned Web integration smoke test**

Assign the values resolved in Steps 2-3 without echoing credentials, then run:

```powershell
$targetID = Read-Host 'Target Registry target_id'
$publicGateway = Read-Host 'Public gateway URL'
$testImage = Read-Host 'Pullable test image'
$containerPort = Read-Host 'Container port'
$env:K3S_INTEGRATION_TARGET_ID=$targetID
$env:K3S_INTEGRATION_KUBECONFIG=$kubeconfigPath
$env:K3S_INTEGRATION_PUBLIC_GATEWAY=$publicGateway
$env:K3S_INTEGRATION_IMAGE=$testImage
$env:K3S_INTEGRATION_CONTAINER_PORT=$containerPort
go test ./internal/k3s -run '^TestK3sIntegrationCreateReadyAndCleanup$' -count=1 -v
```

Expected: the test creates an instance-owned Namespace, verifies Deployment/Service/Ingress/readiness and exact ownership, then deletes the Namespace in cleanup.

- [ ] **Step 5: Verify Pwn behavior according to real capability**

If `RuntimeClass/gvisor` exists, run:

```powershell
go test ./internal/k3s -run '^TestK3sIntegrationPwnCreateReadyAndCleanup$' -count=1 -v
```

Expected: NodePort service, TCP endpoint, gVisor Deployment/Pod readiness,
default-deny policies, and owned Namespace cleanup are verified. If gVisor does
not exist, run the local fail-closed boundary instead:

```powershell
go test ./internal/k3s -run '^TestIntegrationPwnRejectsUnsupportedTargetWithoutCreatingNamespace$' -count=1 -v
```

Expected: `TARGET_CAPABILITY_MISMATCH` is observed before any Namespace action.
Do not install gVisor without separate Broker/bootstrap authority.

- [ ] **Step 6: Record final evidence and working-tree state**

Run:

```powershell
git status --short
git log --oneline --decorate -10
```

Expected: no unintended files, secrets, kubeconfigs, generated manifests, or unrelated user changes are committed. Report the exact tests, AWS target, created/deleted Namespace, Web result, Pwn result, worker changes, isolation changes, and any remaining operational prerequisite.
