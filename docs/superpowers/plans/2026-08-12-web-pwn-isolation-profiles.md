# Web/Pwn Isolation Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Always apply `STANDARD@v1`, then compose either `WEB@v1` or `PWN@v1`, with gVisor and NodePort enforced for Pwn workloads.

**Architecture:** Extend the isolation resolver so it produces an execution-ready composed policy; the Kubernetes adapter must never reinterpret raw profile names. Add a snake_case workload selector at the HTTP boundary, validate Target capabilities before resource creation, and render RuntimeClass, exposure, endpoint protocol, and spec hashes from the resolved policy.

**Tech Stack:** Go, net/http, Kubernetes client-go API types, fake clientset, Go standard `testing`

## Global Constraints

- Execute on a clean branch/worktree from the latest `origin/dev`; preserve the dirty `feature/1-provisioner-mvp` workspace.
- Keep every external JSON field snake_case.
- `STANDARD@v1` is mandatory and cannot be weakened.
- Support only `WEB@v1` and `PWN@v1` workload additions.
- Pwn requires `runtimeClassName: gvisor`, `NODE_PORT`, one exposed container, one exposed TCP port, and writable paths under `/tmp`.
- Web uses the Target default runtime and supports `INGRESS_PATH` or `NODE_PORT`.
- Public internet outbound, root UID, privileged execution, added capabilities, host namespaces, hostPath, arbitrary RBAC, and caller-selected RuntimeClass remain forbidden.
- gVisor installation and Catalog challenge-to-profile binding are outside this implementation.
- Follow test-driven development: every new behavior starts with an observed failing test.

---

## File Structure

- `internal/isolation/profile.go`: composition inputs and resolved execution decisions.
- `internal/isolation/static_resolver.go`: `STANDARD + WEB/PWN` resolution and policy validation.
- `internal/httpapi/create.go`: `workload_profile_ref` parsing, legacy normalization, and mapping.
- `internal/provisioner/create.go`: endpoint protocol in runtime results.
- `internal/operations/*`: idempotent copy/equality and result preservation.
- `internal/httpapi/runtime.go`: endpoint `protocol` response.
- `internal/k3s/cluster.go`, `config.go`, `registry.go`: RuntimeClass capability declaration and validation.
- `internal/k3s/resources.go`, `security_resources.go`, `adapter.go`: RuntimeClass/exposure rendering, endpoints, and hashing.
- matching `*_test.go` files: unit, fake-client, failure, and integration coverage.
- `docs/api/runtime-operations.md`: final request, Target, and response contract examples.

### Task 1: Isolation policy composition

**Files:**
- Modify: `internal/isolation/profile.go`
- Modify: `internal/isolation/static_resolver.go`
- Test: `internal/isolation/static_resolver_test.go`

**Interfaces:**
- Consumes: existing `ProfileRef`, `Baseline`, `ContainerRequirement`, `Request`, and `ResolvedPolicy`.
- Produces: `EndpointProtocol`, `ExposureRequirement`, `Request.WorkloadProfileRef`, `ContainerRequirement.Expose`, and execution decisions on `ResolvedPolicy`.

- [ ] **Step 1: Write failing Web/Pwn composition tests**

Add exact profile tests:

```go
func TestStaticResolverComposesWebOnStandard(t *testing.T) {
    request := validRequest()
    request.WorkloadProfileRef = isolation.ProfileRef{Name: "WEB", Version: "v1"}
    request.Containers[0].Expose = true
    got, err := isolation.NewStaticResolver().Resolve(request)
    if err != nil { t.Fatal(err) }
    if got.RuntimeClassName != "" || got.EndpointProtocol != isolation.EndpointProtocolHTTP ||
        got.ExposureRequirement != isolation.ExposureAnySupported {
        t.Fatalf("resolved Web policy = %#v", got)
    }
}

func TestStaticResolverComposesPwnOnStandard(t *testing.T) {
    got, err := isolation.NewStaticResolver().Resolve(validPwnRequest())
    if err != nil { t.Fatal(err) }
    if got.RuntimeClassName != "gvisor" || got.EndpointProtocol != isolation.EndpointProtocolTCP ||
        got.ExposureRequirement != isolation.ExposureNodePortOnly {
        t.Fatalf("resolved Pwn policy = %#v", got)
    }
}
```

Add rejection cases for unknown workload profiles, non-`STANDARD@v1` baselines, Pwn with zero/multiple exposed containers, Pwn with multiple exposed ports, and Pwn writable paths outside `/tmp`.

- [ ] **Step 2: Run tests and verify failure**

```powershell
go test ./internal/isolation -run 'TestStaticResolver(Composes|Rejects)' -count=1
```

Expected: compilation fails because the new fields/constants do not exist.

- [ ] **Step 3: Add execution-ready policy types**

```go
type EndpointProtocol string
const (
    EndpointProtocolHTTP EndpointProtocol = "HTTP"
    EndpointProtocolTCP EndpointProtocol = "TCP"
)

type ExposureRequirement string
const (
    ExposureAnySupported ExposureRequirement = "ANY_SUPPORTED"
    ExposureNodePortOnly ExposureRequirement = "NODE_PORT_ONLY"
)
```

Add `Expose bool` to `ContainerRequirement`; add `WorkloadProfileRef ProfileRef` to `Request`; and add `WorkloadProfileRef`, `RuntimeClassName`, `EndpointProtocol`, and `ExposureRequirement` to `ResolvedPolicy`.

- [ ] **Step 4: Implement minimal composition and Pwn validation**

```go
func resolveWorkloadProfile(ref ProfileRef) (string, EndpointProtocol, ExposureRequirement, error) {
    switch ref {
    case ProfileRef{Name: "WEB", Version: "v1"}:
        return "", EndpointProtocolHTTP, ExposureAnySupported, nil
    case ProfileRef{Name: "PWN", Version: "v1"}:
        return "gvisor", EndpointProtocolTCP, ExposureNodePortOnly, nil
    default:
        return "", "", "", rejected("unsupported workload profile")
    }
}
```

Require `STANDARD@v1`, construct the common baseline once, and apply Pwn-only constraints without changing baseline booleans. Extend reserved writable paths with `/dev`; for Pwn accept only `path == "/tmp" || strings.HasPrefix(path, "/tmp/")`.

- [ ] **Step 5: Verify and commit**

```powershell
go test ./internal/isolation -count=1
git add internal/isolation/profile.go internal/isolation/static_resolver.go internal/isolation/static_resolver_test.go
git commit -m "Feat: Web Pwn 격리 정책 합성 추가"
```

Expected: tests pass and one policy-domain commit is created.

### Task 2: HTTP contract, operation identity, and endpoint protocol

**Files:**
- Modify: `internal/httpapi/create.go`
- Modify: `internal/httpapi/create_test.go`
- Modify: `internal/httpapi/http_test.go`
- Modify: `internal/provisioner/create.go`
- Modify: `internal/operations/operation_test.go`
- Modify: `internal/operations/memory_store_test.go`
- Modify: `internal/httpapi/runtime.go`
- Modify: `internal/httpapi/runtime_test.go`

**Interfaces:**
- Consumes: Task 1 policy types.
- Produces: snake_case `workload_profile_ref`, preserved operation identity, and endpoint response `protocol`.

- [ ] **Step 1: Write failing contract tests**

Set `request.WorkloadProfileRef = ProfileRef{Name: "WEB", Version: "v1"}` in modern fixtures. Assert `ToCommand` preserves that ref and each container's `Expose` in `PolicyRequest` and unresolved `Policy`. Add tests that modern omission fails while a fully legacy request normalizes to `WEB@v1`.

Add endpoint serialization coverage:

```go
endpoint := provisioner.WorkloadEndpoint{
    ContainerName: "challenge", Port: 31337,
    Protocol: isolation.EndpointProtocolTCP,
    ServiceURL: "tcp://203.0.113.10:31042",
}
if got := newWorkloadEndpointResponse(endpoint); got.Protocol != "TCP" {
    t.Fatalf("protocol = %q", got.Protocol)
}
```

Add operation tests proving profile/protocol changes affect request/result identity and copies retain the new scalar fields.

- [ ] **Step 2: Run tests and verify failure**

```powershell
go test ./internal/httpapi ./internal/operations -run 'WorkloadProfile|EndpointProtocol|Legacy' -count=1
```

Expected: compilation or assertion failure for missing fields/mapping.

- [ ] **Step 3: Implement strict request mapping**

Add:

```go
WorkloadProfileRef ProfileRef `json:"workload_profile_ref"`
```

Include it in policy-field presence detection and `usesLegacyPolicyContract`. Set it to `WEB@v1` only inside the complete legacy normalization path. Modern requests require both name and version. Map the profile and `Expose` through `toPolicyRequest` and `unresolvedPolicy`.

- [ ] **Step 4: Carry endpoint protocol through results**

```go
type WorkloadEndpoint struct {
    ContainerName string
    Port int
    Protocol isolation.EndpointProtocol
    ServiceURL string
}

type WorkloadEndpointResponse struct {
    ContainerName string `json:"container_name"`
    Port int `json:"port"`
    Protocol string `json:"protocol"`
    ServiceURL string `json:"service_url"`
}
```

Map `string(endpoint.Protocol)` in `newWorkloadEndpointResponse`. Existing operation struct copies retain scalar profile/runtime/protocol values; extend tests so future changes cannot drop them.

- [ ] **Step 5: Verify and commit**

```powershell
go test ./internal/httpapi ./internal/operations -count=1
git add internal/httpapi/create.go internal/httpapi/create_test.go internal/httpapi/http_test.go internal/httpapi/runtime.go internal/httpapi/runtime_test.go internal/provisioner/create.go internal/operations/operation_test.go internal/operations/memory_store_test.go
git commit -m "Feat: 문제 유형 및 endpoint protocol 계약 추가"
```

Expected: API and operation tests pass.

### Task 3: Target RuntimeClass capability and fail-closed checks

**Files:**
- Modify: `internal/k3s/cluster.go`
- Modify: `internal/k3s/config.go`
- Modify: `internal/k3s/registry.go`
- Modify: `internal/k3s/config_test.go`
- Modify: `internal/k3s/registry_test.go`
- Modify: `internal/k3s/adapter_test.go`

**Interfaces:**
- Consumes: Task 1 `RuntimeClassName` and `ExposureRequirement`.
- Produces: `SecurityCapabilities.RuntimeClasses []string`, fail-closed
  `PodPIDLimitEnforced`, and policy-aware `Cluster.Supports`.

- [ ] **Step 1: Write failing capability tests**

Extend the complete registry JSON fixture with `"pod_pid_limit_enforced":true` and
`"runtime_classes":["gvisor"]`. Test missing/null/explicit-false PID capability,
defensive copying, duplicate/empty/invalid RuntimeClass names, and unknown-field rejection. Add:

```go
func TestClusterSupportsPwnOnlyWithGVisorAndNodePort(t *testing.T) {
    policy := resolvedPwnPolicy()
    cluster := validCluster("aws-dev")
    if err := cluster.Supports(policy); err == nil { t.Fatal("unexpected support") }
    cluster.Config.SecurityCapabilities.RuntimeClasses = []string{"gvisor"}
    cluster.Config.ExposureMode = ExposureModeNodePort
    if err := cluster.Supports(policy); err != nil { t.Fatal(err) }
}
```

Add a fake-client adapter test proving mismatch returns `TARGET_CAPABILITY_MISMATCH` before any Namespace create action.

- [ ] **Step 2: Run tests and verify failure**

```powershell
go test ./internal/k3s -run 'RuntimeClass|SupportsPwn|CapabilityMismatch' -count=1
```

Expected: missing capability fields or failed assertions.

- [ ] **Step 3: Implement registry capability handling**

Add required `PodPIDLimitEnforced` (pointer in decoded registry config, boolean in the
domain config) and `RuntimeClasses []string` with `json:"runtime_classes,omitempty"` to
registry and cluster capability structs. A missing PID declaration makes the registry
invalid; explicit false remains loadable but `Cluster.Supports` rejects all workload
creation before Kubernetes calls. Copy the runtime slice in `clusterCapabilities` and
`copySecurityCapabilities`. Validate every entry with `validation.IsDNS1123Label`, reject
duplicates, and permit an empty list for Web-only targets.

- [ ] **Step 4: Make `Cluster.Supports` policy-aware**

```go
if policy.RuntimeClassName != "" && !slices.Contains(capabilities.RuntimeClasses, policy.RuntimeClassName) {
    return newRuntimeError("TARGET_CAPABILITY_MISMATCH", false, nil)
}
if policy.ExposureRequirement == isolation.ExposureNodePortOnly && c.Config.ExposureMode != ExposureModeNodePort {
    return newRuntimeError("TARGET_CAPABILITY_MISMATCH", false, nil)
}
```

Retain all common capability checks and do not perform Kubernetes API discovery in the request path.

- [ ] **Step 5: Verify and commit**

```powershell
go test ./internal/k3s -count=1
git add internal/k3s/cluster.go internal/k3s/config.go internal/k3s/registry.go internal/k3s/config_test.go internal/k3s/registry_test.go internal/k3s/adapter_test.go
git commit -m "Feat: gVisor Target capability 검증 추가"
```

Expected: all K3s package tests pass.

### Task 4: Kubernetes runtime, exposure, endpoints, and spec hash

**Files:**
- Modify: `internal/k3s/resources.go`
- Modify: `internal/k3s/security_resources.go`
- Modify: `internal/k3s/security_resources_test.go`
- Modify: `internal/k3s/resources_test.go`
- Modify: `internal/k3s/adapter.go`
- Modify: `internal/k3s/adapter_test.go`

**Interfaces:**
- Consumes: resolved RuntimeClass, endpoint protocol, exposure requirement, and Target capabilities.
- Produces: Web default-runtime manifests, Pwn gVisor manifests, protocol-correct endpoints, and profile-sensitive hashes.

- [ ] **Step 1: Write failing manifest and endpoint tests**

```go
webResources, _ := BuildResourceSet(validCluster("aws-dev"), validCreateCommand("aws-dev"))
if webResources.Deployments[0].Spec.Template.Spec.RuntimeClassName != nil {
    t.Fatal("Web must use the default runtime")
}

pwnResources, _ := BuildResourceSet(nodePortGVisorCluster("aws-dev"), validPwnCreateCommand("aws-dev"))
for _, deployment := range pwnResources.Deployments {
    if deployment.Spec.Template.Spec.RuntimeClassName == nil || *deployment.Spec.Template.Spec.RuntimeClassName != "gvisor" {
        t.Fatalf("runtime class = %#v", deployment.Spec.Template.Spec.RuntimeClassName)
    }
}
```

Test one Pwn NodePort, Web `HTTP` endpoints, allocated Pwn `TCP`/`tcp://` endpoints, and spec-hash changes for workload profile/runtime/exposure/protocol changes. Add unsafe-policy cases for invalid canonical combinations.

- [ ] **Step 2: Run tests and verify failure**

```powershell
go test ./internal/k3s -run 'RuntimeClass|Pwn|EndpointProtocol|SpecHash' -count=1
```

Expected: manifest and endpoint assertions fail.

- [ ] **Step 3: Render and revalidate execution decisions**

After applying the common security baseline:

```go
if command.Policy.RuntimeClassName != "" {
    runtimeClassName := command.Policy.RuntimeClassName
    podSpec.RuntimeClassName = &runtimeClassName
}
```

Make `validateResolvedPolicy` accept only these combinations:

```text
WEB@v1 => runtime="", protocol=HTTP, exposure=ANY_SUPPORTED
PWN@v1 => runtime=gvisor, protocol=TCP, exposure=NODE_PORT_ONLY
```

Continue validating every baseline bit so a forged pre-resolved command cannot bypass the resolver.

- [ ] **Step 4: Build protocol-aware endpoints**

Set `HTTP` on Ingress endpoints. Change the NodePort helper to:

```go
func BuildNodePortEndpoints(publicGateway string, protocol isolation.EndpointProtocol, services []*corev1.Service) ([]provisioner.WorkloadEndpoint, error)
```

Accept only `HTTP`/`TCP`; for TCP clone the parsed gateway URL and set `Scheme = "tcp"` before replacing its host port. Pass `command.Policy.EndpointProtocol` after Service read-back.

- [ ] **Step 5: Make spec hashes profile-sensitive**

Add `IsolationRef`, `WorkloadProfileRef`, `RuntimeClassName`, `EndpointProtocol`, and `ExposureRequirement` to the object serialized by `createContainerSpecHash` and populate them from `command.Policy`.

- [ ] **Step 6: Verify and commit**

```powershell
go test ./internal/k3s -count=1
git add internal/k3s/resources.go internal/k3s/security_resources.go internal/k3s/security_resources_test.go internal/k3s/resources_test.go internal/k3s/adapter.go internal/k3s/adapter_test.go
git commit -m "Feat: Web Pwn Kubernetes 실행 정책 적용"
```

Expected: K3s tests pass with gVisor and endpoint coverage.

### Task 5: Integration, documentation, and full verification

**Files:**
- Modify: `internal/k3s/integration_test.go`
- Modify: `docs/api/runtime-operations.md`

**Interfaces:**
- Consumes: all previous tasks.
- Produces: end-to-end regression evidence and final contract documentation.

- [ ] **Step 1: Write failing integration tests**

Extend the integration fixture helper to accept a workload profile. Add a Web test that resolves and renders an Ingress workload without RuntimeClass; add a Pwn test using a NodePort/gVisor Target that renders `runtimeClassName: gvisor`, one NodePort Service, `TCP`, and a `tcp://` endpoint after fake allocation. Add a negative test proving an unsupported Target returns `TARGET_CAPABILITY_MISMATCH` without creating a Namespace.

- [ ] **Step 2: Run integration tests and verify failure**

```powershell
go test ./internal/k3s -run 'TestIntegration.*(Web|Pwn)' -count=1
```

Expected: failure until fixtures and the full composed flow are connected.

- [ ] **Step 3: Complete fixtures and API documentation**

Document a modern Web request, a Pwn request, required Target
`pod_pid_limit_enforced`, Target `runtime_classes`, `HTTP` and `TCP` endpoint responses,
the Pwn gVisor/NodePort requirement, and the fact that only fully legacy payloads
normalize to Web.

- [ ] **Step 4: Run formatting and complete verification**

```powershell
gofmt -w internal/isolation/profile.go internal/isolation/static_resolver.go internal/isolation/static_resolver_test.go internal/httpapi/create.go internal/httpapi/create_test.go internal/httpapi/http_test.go internal/httpapi/runtime.go internal/httpapi/runtime_test.go internal/provisioner/create.go internal/operations/operation_test.go internal/operations/memory_store_test.go internal/k3s/cluster.go internal/k3s/config.go internal/k3s/registry.go internal/k3s/config_test.go internal/k3s/registry_test.go internal/k3s/resources.go internal/k3s/security_resources.go internal/k3s/security_resources_test.go internal/k3s/resources_test.go internal/k3s/adapter.go internal/k3s/adapter_test.go internal/k3s/integration_test.go
go test ./... -count=1
go vet ./...
git diff --check
```

Expected: every command exits with status 0.

- [ ] **Step 5: Commit and record final evidence**

```powershell
git add internal/k3s/integration_test.go docs/api/runtime-operations.md
git commit -m "Test: Web Pwn 격리 통합 검증 추가"
git status --short --branch
git log --oneline --decorate -6
go test ./... -count=1
go vet ./...
```

Expected: the feature worktree is clean, commits are visible, and both verification commands pass.
