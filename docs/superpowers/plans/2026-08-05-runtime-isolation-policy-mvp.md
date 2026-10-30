# Runtime Isolation Policy MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Secure Provisioner가 해제 불가능한 공통 격리 baseline과 제한된 문제별 요구사항을 K3s 리소스로 강제하고, `test_ctf`의 세 문제에 플랫폼 승인 정책 파일을 추가해 CI가 이미지 digest와 결합한 resolved challenge config를 게시하도록 한다.

**Architecture:** `test_ctf`의 `deployment-policy.yaml`은 raw Kubernetes 설정이 아니라 profile name/version, non-root UID, sized writable path, 내부 연결과 outbound mode만 선언한다. CI는 `info.yaml`, 승인 정책과 image digest artifact를 검증·결합하고, Scheduler 역할의 테스트 요청 JSON을 생성한다. Provisioner의 MVP `PolicyResolver`는 trusted static profile을 해석하고 허용 필드만 검증한 뒤 ServiceAccount, ResourceQuota, LimitRange, deny-first NetworkPolicy와 hardened Deployment를 K3s API에 보호 리소스 우선 순서로 적용한다.

**Tech Stack:** Go 1.24, `net/http`, `client-go`, Kubernetes core/apps/networking APIs, Go `testing`, Python 3, PyYAML, pytest, Docker, GitHub Actions, GHCR

## Global Constraints

- Provisioner 작업 루트는 `C:/Users/RYZEN1/Desktop/cloud_study/.worktrees/secure-provisioner-issue-19`이고 브랜치는 `feat/19-runtime-isolation`이다.
- Provisioner 브랜치는 `feat/29-multi-container-runtime` 위에 쌓여 있으며 `#29` 병합 후 최신 `dev`로 재배치한다.
- `test_ctf` 실행 작업은 현재 `agent/test-challenge-images`에서 분기한 별도 worktree와 `agent/isolation-policy-mvp` 브랜치에서 수행한다.
- 공통 baseline은 문제별 정책으로 해제할 수 없다.
- 문제 파일에서 raw Kubernetes YAML, SecurityContext, ServiceAccount, RBAC, RuntimeClass, privileged, host namespace 또는 hostPath를 받지 않는다.
- MVP에서 허용하는 문제별 입력은 non-root UID, sized writable path, 내부 container/port 연결, outbound mode와 resource profile뿐이다.
- MVP profile ref는 `name`과 `version`을 사용한다. caller-supplied immutable digest와 Catalog assignment authority는 설계의 다음 마이그레이션 단계로 남기며 production 완료로 간주하지 않는다.
- MVP target capability는 NetworkPolicy enforcement 선언, DNS selector와 Ingress selector를 검증한다. resident-node/metadata host-boundary의 실제 attestation은 `#32` 전까지 production 완료로 간주하지 않는다.
- MVP 기본 outbound mode는 `NONE`이며 세 `test_ctf` 문제 모두 public egress를 허용하지 않는다.
- ServiceAccount token, privileged, privilege escalation, host namespace, hostPath, capabilities, seccomp, non-root와 read-only root filesystem은 모든 MVP profile에서 강제한다.
- 모든 production 코드 변경은 실패하는 테스트를 먼저 작성하고 예상 원인으로 실패하는 것을 확인한 후 구현한다.
- fake client 테스트는 manifest와 적용 순서만 증명하며 실제 네트워크 enforcement의 근거로 사용하지 않는다.
- 실제 K3s 격리 효과는 `#11`, node/metadata host-boundary는 `#32`, Admission 최종 강제는 `#13`에서 완료한다.
- GHCR token, kubeconfig, ServiceAccount token, flag와 node 관리 주소를 저장소·API 오류·일반 로그에 기록하지 않는다.

---

### Task 1: MVP 정책 Domain과 생성 API 계약

**Files:**
- Create: `internal/isolation/profile.go`
- Create: `internal/isolation/resolver.go`
- Create: `internal/isolation/static_resolver.go`
- Create: `internal/isolation/static_resolver_test.go`
- Modify: `internal/provisioner/create.go`
- Modify: `internal/provisioner/create_test.go`
- Modify: `internal/httpapi/create.go`
- Modify: `internal/httpapi/create_test.go`
- Modify: `internal/httpapi/http.go`
- Modify: `internal/httpapi/http_test.go`
- Modify: `internal/operations/operation.go`
- Modify: `internal/operations/operation_test.go`
- Modify: `internal/runtimeops/service.go`
- Modify: `internal/runtimeops/service_test.go`
- Modify: `cmd/provisioner/main.go`
- Modify: `cmd/provisioner/main_test.go`

**Interfaces:**
- Consumes: `challenge_ref`, `isolation_ref`, `resource_profile_ref`, container runtime requirements와 `internal_connections`가 포함된 Scheduler create request.
- Produces: `isolation.Resolver.Resolve(isolation.Request) (isolation.ResolvedPolicy, error)`와 Kubernetes 독립적인 `CreateWorkloadCommand.Policy`.

- [ ] **Step 1: 지원하는 profile과 안전한 추가 요구사항을 표현하는 실패 테스트 작성**

```go
func TestStaticResolverResolvesStandardPolicyWithoutAllowingBaselineOverrides(t *testing.T) {
    resolver := isolation.NewStaticResolver()
    got, err := resolver.Resolve(isolation.Request{
        ChallengeID: "web-chall2",
        IsolationRef: isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
        ResourceRef: isolation.ProfileRef{Name: "SMALL_MULTI", Version: "v1"},
        Containers: []isolation.ContainerRequirement{
            {Name: "web", RunAsUser: 101, WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}}},
            {Name: "api", RunAsUser: 10001},
        },
        InternalConnections: []isolation.InternalConnection{{
            SourceContainer: "web", DestinationContainer: "api", Protocol: isolation.ProtocolTCP, Port: 8080,
        }},
        OutboundMode: isolation.OutboundNone,
        ResourceLimits: isolation.ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256},
    })
    if err != nil { t.Fatal(err) }
    if !got.Baseline.RunAsNonRoot || !got.Baseline.ReadOnlyRootFilesystem || !got.Baseline.DropAllCapabilities {
        t.Fatalf("baseline = %#v", got.Baseline)
    }
}
```

같은 파일에 unknown profile, resource profile 숫자 불일치, UID 0, `/proc`·`/sys`·`/var/run/secrets` writable path, 중첩 path, 존재하지 않는 container와 port를 참조하는 internal connection, `PUBLIC_INTERNET` 요청을 거부하는 개별 테스트를 작성한다.

- [ ] **Step 2: resolver 테스트를 실행해 RED 확인**

Run: `go test ./internal/isolation -run TestStaticResolver -count=1`

Expected: FAIL because `internal/isolation` package and `NewStaticResolver` do not exist.

- [ ] **Step 3: 최소 Domain과 static resolver 구현**

```go
type ProfileRef struct { Name, Version string }

type Baseline struct {
    AutomountServiceAccountToken bool
    RunAsNonRoot                 bool
    ReadOnlyRootFilesystem       bool
    AllowPrivilegeEscalation     bool
    Privileged                   bool
    DropAllCapabilities          bool
    SeccompRuntimeDefault        bool
}

type WritablePath struct { Path string; SizeMiB int }
type ContainerRequirement struct { Name string; Ports []int; RunAsUser int64; WritablePaths []WritablePath }
type InternalConnection struct { SourceContainer, DestinationContainer string; Protocol Protocol; Port int }

type Resolver interface {
    Resolve(Request) (ResolvedPolicy, error)
}
```

`NewStaticResolver`는 `STANDARD@v1`, `SMALL_SINGLE@v1=100m/128MiB/128MiB`, `SMALL_MULTI@v1=200m/256MiB/256MiB`만 등록한다. `STANDARD@v1`은 baseline 값을 상수로 강제하고 `OutboundNone`만 허용한다.

- [ ] **Step 4: resolver GREEN 확인**

Run: `go test ./internal/isolation -run TestStaticResolver -count=1`

Expected: PASS.

- [ ] **Step 5: HTTP DTO가 정책 필드를 Domain으로 손실 없이 변환하는 실패 테스트 작성**

```go
func TestCreateWorkloadRequestConvertsApprovedIsolationRequirements(t *testing.T) {
    request := validMultiContainerRequest()
    request.ChallengeRef = ChallengeRef{ChallengeID: "web-chall2", Version: "2026.08.1"}
    request.IsolationRef = ProfileRef{Name: "STANDARD", Version: "v1"}
    request.ResourceProfileRef = ProfileRef{Name: "SMALL_MULTI", Version: "v1"}
    request.Workload.Containers[0].RunAsUser = 101
    request.Workload.Containers[0].WritablePaths = []WritablePath{{Path: "/tmp", SizeMiB: 64}}
    request.Workload.Containers[1].RunAsUser = 10001
    request.Workload.InternalConnections = []InternalConnection{{
        SourceContainer: "web", DestinationContainer: "api", Protocol: "TCP", Port: 8080,
    }}
    request.Workload.OutboundMode = "NONE"

    if err := request.Validate(); err != nil { t.Fatal(err) }
    command := request.ToCommand()
    if command.ChallengeRef.ChallengeID != "web-chall2" || command.Policy.IsolationRef.Name != "STANDARD" {
        t.Fatalf("command = %#v", command)
    }
}
```

- [ ] **Step 6: HTTP 테스트 RED 확인**

Run: `go test ./internal/httpapi -run 'TestCreateWorkloadRequestConvertsApprovedIsolationRequirements|TestCreateWorkloadRequestRejectsInvalidIsolation' -count=1`

Expected: FAIL because the request and command do not contain policy fields.

- [ ] **Step 7: DTO, Domain command와 validation 최소 구현**

Top-level DTO에 `challenge_ref`, `isolation_ref`, `resource_profile_ref`를 추가하고 `workload.containers[]`에 `run_as_user`, `writable_paths[]`, workload에 `internal_connections[]`, `outbound_mode`를 추가한다. `Validate`는 형식과 container/port 참조를 검사하고 resolver가 승인 정책과 profile 숫자를 최종 검사한다.

- [ ] **Step 8: API와 Domain 전체 테스트 GREEN 확인**

Run: `go test ./internal/httpapi ./internal/provisioner ./internal/isolation -count=1`

Expected: PASS.

- [ ] **Step 9: enqueue 경계에서 profile을 resolve하는 실패 테스트 작성**

```go
func TestEnqueueCreateResolvesPolicyBeforePersistingOperation(t *testing.T) {
    resolver := &recordingResolver{resolved: validResolvedPolicy()}
    service := newTestServiceWithResolver(t, resolver)
    operation, _, err := service.EnqueueCreate(validUnresolvedPolicyCommand())
    if err != nil { t.Fatal(err) }
    if resolver.calls != 1 || operation.CreateCommand == nil || operation.CreateCommand.Policy.IsolationRef.Name != "STANDARD" {
        t.Fatalf("resolver calls = %d; operation = %#v", resolver.calls, operation)
    }
}
```

resolver rejection이 Operation을 만들지 않고 HTTP 422 `ISOLATION_POLICY_REJECTED`로 반환되는 테스트도 작성한다. `operations.copyCreateCommand`와 `sameCreateCommand`가 policy의 ports, writable paths와 internal connections를 깊은 복사·비교하는 테스트를 추가한다.

- [ ] **Step 10: runtime wiring RED 확인**

Run: `go test ./internal/runtimeops ./internal/operations ./internal/httpapi ./cmd/provisioner -run 'TestEnqueueCreateResolvesPolicy|TestCreateRejectsIsolationPolicy|TestCreateOperationCopiesPolicy' -count=1`

Expected: FAIL because Runtime Service has no resolver and Operation copy/equality ignores policy.

- [ ] **Step 11: resolver 주입, error mapping과 command copy 구현**

`runtimeops.NewService`에 `isolation.Resolver`를 주입한다. `EnqueueCreate`가 raw `PolicyRequest`를 resolve해 `command.Policy`에 저장한 뒤 Operation Store를 호출하게 한다. `cmd/provisioner.newApplication`은 `isolation.NewStaticResolver()`를 생성해 전달한다. unsupported profile, resource mismatch와 unsafe requirement는 stable sentinel error로 감싸 HTTP 422 `ISOLATION_POLICY_REJECTED`로 매핑한다. Operation은 resolved policy의 모든 slice를 깊은 복사하고 idempotency 비교에 포함한다.

- [ ] **Step 12: runtime wiring GREEN 확인**

Run: `go test ./internal/runtimeops ./internal/operations ./internal/httpapi ./cmd/provisioner -count=1`

Expected: PASS.

- [ ] **Step 13: 커밋**

```powershell
git add internal/httpapi internal/provisioner internal/isolation internal/operations internal/runtimeops cmd/provisioner
git commit -m "Feat: 격리 정책 MVP 생성 계약 추가"
```

### Task 2: target의 최소 security capability 계약

**Files:**
- Modify: `internal/k3s/cluster.go`
- Modify: `internal/k3s/config.go`
- Modify: `internal/k3s/config_test.go`
- Modify: `internal/k3s/registry_test.go`
- Modify: `internal/k3s/adapter.go`
- Modify: `internal/k3s/adapter_test.go`
- Modify: `cmd/provisioner/main_test.go`

**Interfaces:**
- Consumes: Cluster Registry JSON의 `security_capabilities`.
- Produces: resolver 결과를 실제 target에서 실행할 수 있는지 검사하는 `Cluster.Supports(policy isolation.ResolvedPolicy) error`.

- [ ] **Step 1: NetworkPolicy와 selector가 없는 target을 거부하는 실패 테스트 작성**

```go
func TestLoadClusterConfigsRejectsIncompleteIsolationCapability(t *testing.T) {
    path := writeClusterRegistry(t, `[{"target_id":"lab","provider":"AWS","region":"ap-northeast-2","architecture":"amd64","kubeconfig_path":"lab.yaml","public_gateway":"https://lab.example","enabled":true,"security_capabilities":{"network_policy_enforced":true}}]`)
    _, err := LoadClusterConfigs(path)
    if err == nil { t.Fatal("expected incomplete capability to be rejected") }
}
```

정상 fixture는 다음 필드를 모두 포함한다.

```json
"security_capabilities": {
  "network_policy_enforced": true,
  "network_policy_provider": "kube-router",
  "dns_namespace": "kube-system",
  "dns_pod_selector": {"k8s-app": "kube-dns"},
  "ingress_namespace": "kube-system",
  "ingress_pod_selector": {"app.kubernetes.io/name": "traefik"}
}
```

- [ ] **Step 2: config 테스트 RED 확인**

Run: `go test ./internal/k3s ./cmd/provisioner -run 'TestLoadClusterConfigsRejectsIncompleteIsolationCapability|TestLoadClusterConfigs' -count=1`

Expected: FAIL because `security_capabilities` is not modeled or validated.

- [ ] **Step 3: capability 타입과 fail-closed validation 구현**

```go
type SecurityCapabilities struct {
    NetworkPolicyEnforced bool              `json:"network_policy_enforced"`
    NetworkPolicyProvider string            `json:"network_policy_provider"`
    DNSNamespace          string            `json:"dns_namespace"`
    DNSPodSelector        map[string]string `json:"dns_pod_selector"`
    IngressNamespace      string            `json:"ingress_namespace"`
    IngressPodSelector    map[string]string `json:"ingress_pod_selector"`
}
```

enabled target에서 필드가 누락되면 config load를 실패시킨다. selector key/value는 Kubernetes label validation을 통과해야 한다. 이 MVP 값은 lab 선언이며 `#11/#32` attestation 전에는 production 검증으로 간주하지 않는다.

- [ ] **Step 4: Adapter가 capability 없는 target을 workload 생성 전에 거부하는 테스트 작성**

```go
func TestAdapterRejectsTargetWithoutRequiredIsolationCapability(t *testing.T) {
    cluster := validCluster("aws-dev")
    cluster.Config.SecurityCapabilities.NetworkPolicyEnforced = false
    adapter := adapterWithCluster(t, cluster)
    _, err := adapter.CreateWorkload(context.Background(), validPolicyCommand())
    assertRuntimeErrorCode(t, err, "TARGET_CAPABILITY_MISMATCH")
    assertNoDeploymentActions(t, cluster.Client)
}
```

- [ ] **Step 5: capability enforcement RED 확인**

Run: `go test ./internal/k3s -run TestAdapterRejectsTargetWithoutRequiredIsolationCapability -count=1`

Expected: FAIL because the Adapter does not inspect capabilities.

- [ ] **Step 6: capability enforcement와 GREEN 구현**

Registry lookup 직후 ResourceSet 생성 전에 `cluster.ValidateIsolationCapability(command.Policy)`를 호출한다. NetworkPolicy가 false이거나 DNS/Ingress selector가 비어 있으면 non-retryable `TARGET_CAPABILITY_MISMATCH`를 반환한다.

Run: `go test ./internal/k3s ./cmd/provisioner -count=1`

Expected: PASS.

- [ ] **Step 7: capability 테스트 GREEN 확인**

Run: `go test ./internal/k3s ./cmd/provisioner -count=1`

Expected: PASS.

- [ ] **Step 8: 커밋**

```powershell
git add internal/k3s/cluster.go internal/k3s/config.go internal/k3s/config_test.go internal/k3s/registry_test.go cmd/provisioner/main_test.go
git commit -m "Feat: K3s 격리 capability 계약 추가"
```

### Task 3: ServiceAccount, SecurityContext와 writable path baseline

**Files:**
- Create: `internal/k3s/security_resources.go`
- Create: `internal/k3s/security_resources_test.go`
- Modify: `internal/k3s/resources.go`
- Modify: `internal/k3s/resources_test.go`

**Interfaces:**
- Consumes: `provisioner.CreateWorkloadCommand.Policy`의 resolved baseline과 container requirements.
- Produces: `ResourceSet.ServiceAccount`, hardened Deployment PodSpecs와 sized `emptyDir` volume.

- [ ] **Step 1: hardened Pod manifest 실패 테스트 작성**

```go
func TestBuildResourceSetAppliesNonNegotiablePodBaseline(t *testing.T) {
    command := validPolicyCommand()
    resources, err := BuildResourceSet(validCluster("aws-dev"), command)
    if err != nil { t.Fatal(err) }
    if resources.ServiceAccount.AutomountServiceAccountToken == nil || *resources.ServiceAccount.AutomountServiceAccountToken {
        t.Fatal("service account token automount must be false")
    }
    pod := resources.Deployments[0].Spec.Template.Spec
    if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken { t.Fatal("pod token automount must be false") }
    if pod.HostNetwork || pod.HostPID || pod.HostIPC { t.Fatal("host namespaces must be false") }
    if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
        t.Fatal("runAsNonRoot must be true")
    }
    c := pod.Containers[0].SecurityContext
    if c == nil || c.Privileged == nil || *c.Privileged || c.AllowPrivilegeEscalation == nil || *c.AllowPrivilegeEscalation {
        t.Fatalf("container security context = %#v", c)
    }
}
```

별도 테스트에서 seccomp `RuntimeDefault`, `readOnlyRootFilesystem=true`, `runAsUser`, `capabilities.drop=[ALL]`, `/tmp` sized emptyDir와 ServiceAccount 이름을 검사한다.

- [ ] **Step 2: security resource 테스트 RED 확인**

Run: `go test ./internal/k3s -run 'TestBuildResourceSetAppliesNonNegotiablePodBaseline|TestBuildResourceSetCreatesSizedWritablePaths' -count=1`

Expected: FAIL because the current ResourceSet has no ServiceAccount or SecurityContext.

- [ ] **Step 3: 보안 manifest builder 최소 구현**

`security_resources.go`에서 pointer helper와 container별 volume 이름 생성기를 구현한다. `emptyDir.SizeLimit`에는 `size_mib`를 BinarySI quantity로 변환한다. Deployment는 `ServiceAccountName: "challenge-runtime"`, token false, host namespace false, Pod seccomp와 container baseline을 갖는다.

- [ ] **Step 4: baseline manifest GREEN 확인**

Run: `go test ./internal/k3s -run 'TestBuildResourceSetAppliesNonNegotiablePodBaseline|TestBuildResourceSetCreatesSizedWritablePaths' -count=1`

Expected: PASS.

- [ ] **Step 5: 기존 ResourceSet 회귀 테스트 확인**

Run: `go test ./internal/k3s -run TestBuildResourceSet -count=1`

Expected: PASS after legacy test commands are updated to include valid MVP policy fixtures.

- [ ] **Step 6: 커밋**

```powershell
git add internal/k3s/security_resources.go internal/k3s/security_resources_test.go internal/k3s/resources.go internal/k3s/resources_test.go
git commit -m "Feat: Pod 공통 보안 baseline 적용"
```

### Task 4: ResourceQuota와 LimitRange

**Files:**
- Modify: `internal/k3s/security_resources.go`
- Modify: `internal/k3s/security_resources_test.go`
- Modify: `internal/k3s/resources.go`

**Interfaces:**
- Consumes: 승인된 resource profile과 container 수.
- Produces: `ResourceSet.ResourceQuota`, `ResourceSet.LimitRange`.

- [ ] **Step 1: Namespace 합계와 object count 실패 테스트 작성**

```go
func TestBuildResourceSetCreatesQuotaAndLimitRangeFromApprovedProfile(t *testing.T) {
    resources, err := BuildResourceSet(validCluster("aws-dev"), validPolicyCommand())
    if err != nil { t.Fatal(err) }
    hard := resources.ResourceQuota.Spec.Hard
    assertQuantity(t, hard[corev1.ResourceLimitsCPU], "200m")
    assertQuantity(t, hard[corev1.ResourceLimitsMemory], "256Mi")
    assertQuantity(t, hard[corev1.ResourceLimitsEphemeralStorage], "256Mi")
    assertQuantity(t, hard[corev1.ResourcePods], "2")
    assertQuantity(t, hard[corev1.ResourceServicesLoadBalancers], "0")
    assertQuantity(t, hard[corev1.ResourceServicesNodePorts], "0")
    assertQuantity(t, hard[corev1.ResourceName("count/persistentvolumeclaims")], "0")
    if len(resources.LimitRange.Spec.Limits) != 1 { t.Fatalf("limit range = %#v", resources.LimitRange.Spec) }
}
```

- [ ] **Step 2: quota 테스트 RED 확인**

Run: `go test ./internal/k3s -run TestBuildResourceSetCreatesQuotaAndLimitRangeFromApprovedProfile -count=1`

Expected: FAIL because quota and limit range are nil.

- [ ] **Step 3: Quota와 LimitRange builder 구현**

Quota는 requests/limits CPU·memory·ephemeral storage, `pods=containerCount`, `services=containerCount`, `services.loadbalancers=0`, `services.nodeports=0`, deployments/replicasets object count, secrets/configmaps와 PVC 0을 포함한다. 각 Deployment는 instance config가 immutable인 특성에 맞춰 `Recreate` strategy와 `revisionHistoryLimit=1`을 사용해 quota를 넘는 surge를 만들지 않는다. ReplicaSet quota는 현재와 직전 revision을 수용하도록 `2*containerCount`로 둔다. LimitRange는 container resource의 default/defaultRequest와 profile maximum을 설정한다.

- [ ] **Step 4: quota GREEN과 합계 회귀 확인**

Run: `go test ./internal/k3s -run 'TestBuildResourceSetCreatesQuota|TestBuildResourceSetDistributesAggregateLimitsExactly' -count=1`

Expected: PASS.

- [ ] **Step 5: 커밋**

```powershell
git add internal/k3s/security_resources.go internal/k3s/security_resources_test.go internal/k3s/resources.go
git commit -m "Feat: Namespace 자원과 객체 quota 적용"
```

### Task 5: deny-first NetworkPolicy와 내부 연결 allowlist

**Files:**
- Create: `internal/k3s/network_policies.go`
- Create: `internal/k3s/network_policies_test.go`
- Modify: `internal/k3s/resources.go`

**Interfaces:**
- Consumes: target DNS/Ingress selectors, expose ports와 resolved `internal_connections`.
- Produces: 결정적 이름과 순서를 가진 `ResourceSet.NetworkPolicies`.

- [ ] **Step 1: default-deny, DNS, Ingress와 internal connection 실패 테스트 작성**

```go
func TestBuildNetworkPoliciesAllowsOnlyDeclaredPaths(t *testing.T) {
    resources, err := BuildResourceSet(validCluster("aws-dev"), validPolicyCommand())
    if err != nil { t.Fatal(err) }
    byName := policiesByName(resources.NetworkPolicies)
    deny := byName["default-deny-all"]
    if len(deny.Spec.PodSelector.MatchLabels) != 0 || len(deny.Spec.Ingress) != 0 || len(deny.Spec.Egress) != 0 {
        t.Fatalf("deny policy = %#v", deny.Spec)
    }
    assertDNSOnly(t, byName["allow-dns"], "kube-system", map[string]string{"k8s-app":"kube-dns"})
    assertIngressOnly(t, byName["allow-public-ingress-web"], "kube-system", map[string]string{"app.kubernetes.io/name":"traefik"}, 8080)
    assertInternalConnection(t, byName, "web", "api", 8080)
}
```

별도 테스트에서 다른 container, 다른 port와 public egress rule이 생성되지 않는 것을 확인한다.

- [ ] **Step 2: NetworkPolicy RED 확인**

Run: `go test ./internal/k3s -run 'TestBuildNetworkPoliciesAllowsOnlyDeclaredPaths|TestBuildNetworkPoliciesDoesNotAllowPublicEgress' -count=1`

Expected: FAIL because NetworkPolicies are not part of ResourceSet.

- [ ] **Step 3: 결정적 NetworkPolicy builder 구현**

`default-deny-all`, `allow-dns`, expose container별 `allow-public-ingress-<name>`, source/destination별 internal allow 정책을 생성한다. Namespace selector는 immutable `kubernetes.io/metadata.name` label을 사용하며 Ingress peer는 Namespace와 Pod selector를 동시에 만족해야 한다. MVP는 `OutboundNone`만 허용한다.

- [ ] **Step 4: NetworkPolicy GREEN 확인**

Run: `go test ./internal/k3s -run TestBuildNetworkPolicies -count=1`

Expected: PASS.

- [ ] **Step 5: 커밋**

```powershell
git add internal/k3s/network_policies.go internal/k3s/network_policies_test.go internal/k3s/resources.go
git commit -m "Feat: 인스턴스 네트워크 allowlist 적용"
```

### Task 6: 보호 리소스 우선 적용과 fail-closed rollback

**Files:**
- Modify: `internal/k3s/adapter.go`
- Modify: `internal/k3s/adapter_test.go`

**Interfaces:**
- Consumes: 확장된 `ResourceSet`.
- Produces: 보호 리소스가 read-back 검증된 후에만 Deployment를 생성하는 apply 순서.

- [ ] **Step 1: 보호 리소스 적용 실패 시 Deployment 미생성 테스트 작성**

```go
func TestAdapterDoesNotCreateDeploymentWhenNetworkPolicyApplyFails(t *testing.T) {
    client := fake.NewSimpleClientset()
    deploymentCreated := false
    client.PrependReactor("create", "networkpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
        return true, nil, errors.New("network policy unavailable")
    })
    client.PrependReactor("create", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
        deploymentCreated = true
        return false, nil, nil
    })
    adapter := adapterWithClient(t, client)
    _, err := adapter.CreateWorkload(context.Background(), validPolicyCommand())
    if err == nil { t.Fatal("expected create failure") }
    if deploymentCreated { t.Fatal("deployment must not be created before protection") }
}
```

ServiceAccount, Quota, LimitRange와 policy ownership conflict 및 read-back spec hash 불일치 테스트도 각각 작성한다.

- [ ] **Step 2: adapter RED 확인**

Run: `go test ./internal/k3s -run 'TestAdapterDoesNotCreateDeploymentWhen|TestAdapterRollsBackOwnedNamespaceWhenProtection' -count=1`

Expected: FAIL because the Adapter does not apply protection resources.

- [ ] **Step 3: preflight와 upsert 구현**

전체 리소스 ownership을 먼저 preflight한다. Namespace 이후 ServiceAccount → ResourceQuota → LimitRange → NetworkPolicies 순서로 upsert하고 각 객체를 GET해 ownership과 policy spec hash를 확인한다. 그 후 Deployments → Services → Ingress를 적용한다. 보호 리소스 실패는 기존 `failWithRollback`을 사용한다.

- [ ] **Step 4: adapter GREEN 확인**

Run: `go test ./internal/k3s -run 'TestAdapterDoesNotCreateDeploymentWhen|TestAdapterRollsBackOwnedNamespaceWhenProtection|TestAdapterCreates' -count=1`

Expected: PASS.

- [ ] **Step 5: K3s package 전체 회귀 확인**

Run: `go test ./internal/k3s -count=1`

Expected: PASS; environment가 없는 실제 K3s tests만 명시적으로 SKIP.

- [ ] **Step 6: 커밋**

```powershell
git add internal/k3s/adapter.go internal/k3s/adapter_test.go
git commit -m "Feat: 격리 리소스 우선 적용과 롤백 보장"
```

### Task 7: Runtime Binding, OpenAPI와 Provisioner 예제

**Files:**
- Modify: `internal/runtimebinding/binding.go`
- Modify: `internal/runtimebinding/memory_store_test.go`
- Modify: `internal/runtimeops/service.go`
- Modify: `internal/runtimeops/service_test.go`
- Modify: `docs/api/secure-provisioner.openapi.yaml`
- Modify: `docs/api/runtime-operations.md`
- Modify: `examples/requests/create-multi-container.json`
- Modify: `README.md`

**Interfaces:**
- Consumes: 성공한 resolved policy와 immutable workload 결과.
- Produces: 적용 profile과 요구사항을 추적할 수 있는 Binding과 문서화된 API.

- [ ] **Step 1: Binding이 정책 정보를 보존하는 실패 테스트 작성**

```go
func TestCreateOperationStoresAppliedIsolationPolicy(t *testing.T) {
    service, bindings := readyRuntimeService(t)
    command := validPolicyCommand()
    result, err := service.CreateWorkload(context.Background(), command)
    if err != nil { t.Fatal(err) }
    binding, err := bindings.Get(command.InstanceID)
    if err != nil { t.Fatal(err) }
    if binding.ChallengeID != "web-chall2" || binding.IsolationProfile != "STANDARD@v1" || binding.ResourceProfile != "SMALL_MULTI@v1" {
        t.Fatalf("binding = %#v; result = %#v", binding, result)
    }
}
```

- [ ] **Step 2: Binding RED 확인**

Run: `go test ./internal/runtimeops ./internal/runtimebinding -run 'TestCreateOperationStoresAppliedIsolationPolicy|TestBinding' -count=1`

Expected: FAIL because Binding does not contain policy identity.

- [ ] **Step 3: Binding 필드와 방어적 복사 구현**

Binding에 challenge ID/version, isolation profile, resource profile, container requirements, internal connections와 outbound mode를 추가한다. slice는 저장·조회할 때 깊은 복사를 수행한다.

- [ ] **Step 4: Binding GREEN 확인**

Run: `go test ./internal/runtimeops ./internal/runtimebinding -count=1`

Expected: PASS.

- [ ] **Step 5: OpenAPI, Markdown와 예제 갱신**

새 필드와 production 이전 MVP 제한을 문서화한다. 예제는 `web -> api:8080`, `OutboundMode=NONE`, non-root UID와 `/tmp` writable path를 포함하고 raw Kubernetes 설정을 포함하지 않는다.

- [ ] **Step 6: 문서 계약 테스트와 전체 Go 검증**

Run: `go test ./...`

Run: `go vet ./...`

Run: `go build ./...`

Expected: all commands exit 0.

- [ ] **Step 7: 커밋**

```powershell
git add internal/runtimebinding internal/runtimeops docs/api examples README.md
git commit -m "Docs: 격리 정책 API와 적용 정보 기록"
```

### Task 8: test_ctf 정책 파일 계약과 승인 파일

**Files:**
- Create: `test_ctf/.github/CODEOWNERS`
- Create: `test_ctf/tests/test_policy_contract.py`
- Create: `test_ctf/web-chall1/deployment-policy.yaml`
- Create: `test_ctf/web-chall2/deployment-policy.yaml`
- Create: `test_ctf/pwn-chall1/deployment-policy.yaml`
- Modify: `test_ctf/web-chall1/info.yaml`
- Modify: `test_ctf/web-chall2/info.yaml`
- Modify: `test_ctf/pwn-chall1/info.yaml`

**Interfaces:**
- Consumes: 문제별 `info.yaml`의 stable ID, version, container/port와 resource 합계.
- Produces: 플랫폼 소유 `deployment-policy.yaml` 세 개와 drift를 거부하는 pytest 계약.

- [ ] **Step 1: 정책 파일 부재와 raw 설정을 거부하는 실패 테스트 작성**

```python
ALLOWED_POLICY_KEYS = {
    "schema_version", "challenge_id", "isolation_profile", "resource_profile",
    "approved_requirements", "approval",
}
FORBIDDEN_TEXT = {
    "securityContext", "privileged", "hostNetwork", "hostPID", "hostIPC",
    "hostPath", "serviceAccountName", "networkPolicy",
}

def test_every_challenge_has_platform_owned_policy_matching_info():
    for challenge in ("web-chall1", "web-chall2", "pwn-chall1"):
        info = load_yaml(f"{challenge}/info.yaml")
        policy = load_yaml(f"{challenge}/deployment-policy.yaml")
        assert set(policy) == ALLOWED_POLICY_KEYS
        assert policy["challenge_id"] == info["id"]
        assert policy["schema_version"] == "v1"
        assert not FORBIDDEN_TEXT.intersection(policy.keys())
```

추가 테스트는 requirement container가 info container와 일치하는지, internal destination port가 선언됐는지, UID가 양수인지, writable path가 절대 경로이며 크기가 양수인지, outbound mode가 `NONE`인지 검사한다.

- [ ] **Step 2: policy contract RED 확인**

Run from `test_ctf`: `python -m pytest -q tests/test_policy_contract.py`

Expected: FAIL because `deployment-policy.yaml` and stable `info.id/version` do not exist.

- [ ] **Step 3: stable ID/version과 승인 정책 파일 작성**

세 info 파일에 다음 ID와 version을 추가한다.

```yaml
id: web-chall1
version: 2026.08.1
```

`web-chall2/deployment-policy.yaml`의 핵심 내용은 다음과 같다.

```yaml
schema_version: v1
challenge_id: web-chall2
isolation_profile: {name: STANDARD, version: v1}
resource_profile: {name: SMALL_MULTI, version: v1}
approved_requirements:
  containers:
    - name: web
      run_as_user: 101
      writable_paths:
        - {path: /tmp, size_mib: 64}
    - name: api
      run_as_user: 10001
      writable_paths: []
  internal_connections:
    - {source_container: web, destination_container: api, protocol: TCP, port: 8080}
  outbound_mode: NONE
approval:
  approved_by: goldsimchoi
  approved_at: "2026-08-05"
  reason: "nginx 임시 경로와 web에서 내부 API로 향하는 연결만 허용"
```

`web-chall1`은 `SMALL_SINGLE`, UID 101, `/tmp` 64MiB, 내부 연결 없음이고 `pwn-chall1`은 `SMALL_SINGLE`, UID 10001, writable path와 내부 연결 없음으로 작성한다. `.github/CODEOWNERS`에는 `**/deployment-policy.yaml @goldsimchoi`를 추가한다.

- [ ] **Step 4: policy contract GREEN 확인**

Run: `python -m pytest -q tests/test_policy_contract.py tests/test_layout.py`

Expected: PASS.

- [ ] **Step 5: test_ctf 커밋**

```powershell
git add .github/CODEOWNERS tests/test_policy_contract.py web-chall1/info.yaml web-chall1/deployment-policy.yaml web-chall2/info.yaml web-chall2/deployment-policy.yaml pwn-chall1/info.yaml pwn-chall1/deployment-policy.yaml
git commit -m "격리 정책 테스트 계약 추가"
```

### Task 9: test_ctf 이미지를 강한 baseline과 호환

**Files:**
- Modify: `test_ctf/web-chall1/prob/for_organizer/web/Dockerfile`
- Modify: `test_ctf/web-chall1/info.yaml`
- Modify: `test_ctf/web-chall2/prob/for_organizer/web/Dockerfile`
- Modify: `test_ctf/web-chall2/prob/for_organizer/web/nginx.conf`
- Modify: `test_ctf/web-chall2/prob/for_organizer/api/Dockerfile`
- Modify: `test_ctf/web-chall2/info.yaml`
- Modify: `test_ctf/pwn-chall1/prob/for_organizer/challenge/Dockerfile`
- Modify: `test_ctf/tests/test_web_single.py`
- Modify: `test_ctf/tests/test_web_multi.py`
- Modify: `test_ctf/tests/test_pwn_single.py`
- Modify: `test_ctf/tests/test_layout.py`
- Modify: `test_ctf/tests/test_publish_manifest.py`
- Modify: `test_ctf/tests/docker_helpers.py`

**Interfaces:**
- Consumes: policy에 승인된 UID와 writable path.
- Produces: non-root, port 8080, read-only root filesystem과 `/tmp` emptyDir에서 실행 가능한 이미지 세트.

- [ ] **Step 1: 이미지가 선언된 UID와 포트로 실행되는지 검사하는 실패 테스트 작성**

`tests/test_web_single.py`와 `test_web_multi.py`의 nginx internal port 기대값을 8080으로 변경한다. Docker 검사 helper로 image config의 User가 비어 있거나 `0`이 아닌지 확인하고, read-only container 실행 시 `/tmp` tmpfs만 writable로 제공해 health/flag 테스트를 수행한다.

```python
def assert_non_root_image(image: str) -> None:
    config = json.loads(subprocess.check_output(["docker", "image", "inspect", image], text=True))[0]["Config"]
    assert config["User"] not in ("", "0", "root")
```

- [ ] **Step 2: 호환성 테스트 RED 확인**

Run: `python -m pytest -q tests/test_web_single.py tests/test_web_multi.py tests/test_pwn_single.py -s`

Expected: FAIL because nginx images expose/run on 80 as root and Python image has no non-root User.

- [ ] **Step 3: non-root Dockerfile과 deterministic UID 구현**

- nginx 이미지는 `nginxinc/nginx-unprivileged:1.27-alpine`로 변경하고 8080을 expose한다.
- `web-chall2/nginx.conf`는 `listen 8080`을 사용한다.
- Python image는 UID/GID 10001 사용자를 생성하고 `USER 10001:10001`로 실행한다.
- Pwn image는 `useradd --uid 10001`로 UID를 고정하고 `USER 10001:10001`로 실행한다.
- 모든 해당 `info.yaml`, 테스트와 Provisioner 요청 기대 port를 8080으로 맞춘다.

- [ ] **Step 4: Docker 기능과 policy contract GREEN 확인**

Run: `python -m pytest -q -s`

Expected: 모든 Docker 사용 가능 환경 테스트가 PASS하고 컨테이너 cleanup이 성공한다.

- [ ] **Step 5: test_ctf 커밋**

```powershell
git add web-chall1 web-chall2 pwn-chall1 tests
git commit -m "테스트 이미지를 공통 격리 baseline에 맞춤"
```

### Task 10: test_ctf policy resolver와 resolved create 요청

**Files:**
- Create: `test_ctf/tools/resolve_challenge_policy.py`
- Create: `test_ctf/tests/test_policy_resolver.py`
- Modify: `test_ctf/deploy/create-web-chall1.json`
- Modify: `test_ctf/deploy/create-web-chall2.json`
- Modify: `test_ctf/deploy/create-pwn-chall1.json`
- Modify: `test_ctf/tests/test_publish_manifest.py`
- Modify: `test_ctf/README.md`

**Interfaces:**
- Consumes: challenge directory, `info.yaml`, `deployment-policy.yaml`, image mapping과 request metadata.
- Produces: Provisioner `POST /internal/v1/instances`와 일치하는 deterministic JSON.

- [ ] **Step 1: resolver의 wished-for CLI와 실패 테스트 작성**

```python
def test_resolver_merges_info_policy_and_images_without_raw_kubernetes(tmp_path):
    output = tmp_path / "create.json"
    run_resolver(
        challenge="web-chall2",
        images={
            "web-chall2/web": "ghcr.io/goldsimchoi/test-ctf-web-chall2-web@sha256:" + "a" * 64,
            "web-chall2/api": "ghcr.io/goldsimchoi/test-ctf-web-chall2-api@sha256:" + "b" * 64,
        },
        output=output,
    )
    request = json.loads(output.read_text())
    assert request["challenge_ref"] == {"challenge_id":"web-chall2", "version":"2026.08.1"}
    assert request["isolation_ref"] == {"name":"STANDARD", "version":"v1"}
    assert request["resource_profile_ref"] == {"name":"SMALL_MULTI", "version":"v1"}
    assert request["workload"]["internal_connections"] == [
        {"source_container":"web", "destination_container":"api", "protocol":"TCP", "port":8080}
    ]
```

별도 테스트에서 info/policy container drift, resource profile mismatch, tag-only image in `--require-digests` mode와 unknown extra policy key를 거부한다.

- [ ] **Step 2: resolver RED 확인**

Run: `python -m pytest -q tests/test_policy_resolver.py`

Expected: FAIL because `tools/resolve_challenge_policy.py` does not exist.

- [ ] **Step 3: deterministic resolver CLI 구현**

CLI 인자는 다음과 같이 고정한다.

```powershell
python tools/resolve_challenge_policy.py --challenge web-chall2 --images deploy/images.json --target-id aws-k3s-lab --request-id test-create-web-chall2-001 --instance-id 22222222-2222-4222-8222-222222222222 --team-id 1002 --output deploy/create-web-chall2.json
```

local `deploy/images.json` 값에 digest가 없으면 `:latest`를 붙이고 경고 없이 테스트 예제를 생성한다. CI의 `--require-digests`에서는 `image@sha256:...`가 아니면 exit 1로 실패한다. JSON은 UTF-8, sorted keys와 2-space indent로 작성한다.

- [ ] **Step 4: resolver GREEN과 checked-in example drift 확인**

Run: `python -m pytest -q tests/test_policy_resolver.py tests/test_publish_manifest.py`

Expected: PASS and rerunning the three resolver commands produces no git diff.

- [ ] **Step 5: README에 책임과 사용법 문서화**

README에 `info.yaml`은 제작자, `deployment-policy.yaml`은 플랫폼/보안 담당자, resolved JSON은 CI artifact라는 책임을 기록한다. raw Kubernetes 정책과 credential을 policy 파일에 넣지 않는다고 명시한다.

- [ ] **Step 6: test_ctf 커밋**

```powershell
git add tools tests deploy README.md
git commit -m "승인 정책 resolved 요청 생성기 추가"
```

### Task 11: GitHub Actions에서 정책 검증과 resolved config 게시

**Files:**
- Modify: `test_ctf/.github/workflows/publish-images.yml`
- Modify: `test_ctf/tests/test_publish_manifest.py`
- Modify: `test_ctf/README.md`

**Interfaces:**
- Consumes: 세 `deployment-policy.yaml`, 네 image digest artifact.
- Produces: `resolved-challenge-configs` GitHub Actions artifact; 정책 YAML은 container image layer에 포함되지 않는다.

- [ ] **Step 1: workflow validation과 resolve job 실패 테스트 작성**

```python
def test_publish_workflow_validates_policy_before_build_and_uploads_resolved_configs():
    workflow = load_workflow()
    assert "validate-policy" in workflow["jobs"]
    assert workflow["jobs"]["publish"]["needs"] == ["validate-policy"]
    resolve = workflow["jobs"]["resolve-policy"]
    assert resolve["needs"] == ["validate-policy", "publish"]
    assert any(step.get("uses", "").startswith("actions/download-artifact@") for step in resolve["steps"])
    assert any(step.get("with", {}).get("name") == "resolved-challenge-configs" for step in resolve["steps"])
```

- [ ] **Step 2: workflow RED 확인**

Run: `python -m pytest -q tests/test_publish_manifest.py -k policy`

Expected: FAIL because the workflow has only the publish job.

- [ ] **Step 3: validate-policy와 resolve-policy job 구현**

`validate-policy`는 Python/PyYAML을 설치하고 policy/resolver tests를 실행한다. `publish`는 이를 needs로 둔다. `resolve-policy`는 모든 `image-digest-*` artifact를 내려받아 `key -> image@digest` JSON을 만들고 세 challenge resolver를 `--require-digests`로 실행한 뒤 `resolved-challenge-configs` artifact를 업로드한다.

workflow path filter에 다음을 추가한다.

```yaml
- "**/info.yaml"
- "**/deployment-policy.yaml"
- "tools/**"
- "tests/test_policy_*.py"
```

- [ ] **Step 4: workflow GREEN과 전체 test_ctf 검증**

Run: `python -m pytest -q`

Expected: PASS.

- [ ] **Step 5: test_ctf 커밋**

```powershell
git add .github/workflows/publish-images.yml tests/test_publish_manifest.py README.md
git commit -m "정책 검증과 resolved config 게시 자동화"
```

### Task 12: 교차 저장소 계약과 최종 검증

**Files:**
- No new repository files. Contract mismatch가 발견되면 Task 7 또는 Task 10으로 돌아가 해당 테스트를 먼저 수정하고 다시 실행한다.

**Interfaces:**
- Consumes: Provisioner OpenAPI와 `test_ctf` generated requests.
- Produces: 동일 JSON 계약과 재현 가능한 로컬 검증 결과.

- [ ] **Step 1: test_ctf 세 요청을 Provisioner DTO contract test fixture로 로드**

Provisioner test에서 저장소 외부 절대 경로를 하드코딩하지 않는다. `test_ctf` resolver 결과를 `internal/httpapi/testdata/`에 복사하지도 않는다. 대신 OpenAPI 필드와 동일한 최소 JSON을 Provisioner 내부 fixture로 유지하고, 실행 단계에서 PowerShell로 세 JSON을 로컬 Provisioner에 POST해 실제 decode/validation을 확인한다.

- [ ] **Step 2: Provisioner 정적 검증**

Run from Provisioner:

```powershell
gofmt -w cmd internal
go test ./...
go vet ./...
go build ./...
git diff --check
```

Expected: all commands exit 0 and only environment-dependent K3s integration tests skip.

- [ ] **Step 3: test_ctf 정적·Docker 검증**

Run from `test_ctf` worktree:

```powershell
python -m pytest -q -s
git diff --check
```

Expected: policy, resolver, workflow and challenge functionality tests pass; Docker 환경이 있으면 four image builds and challenge checks pass.

- [ ] **Step 4: 로컬 Provisioner API decode 검증**

lab Cluster Registry에 MVP `security_capabilities`를 추가해 Provisioner를 시작한다. 세 `deploy/create-*.json`을 `POST /internal/v1/instances`로 보내 HTTP 202와 CREATE Operation을 확인한다. K3s가 연결되지 않은 contract-only 환경이면 접수와 validation까지만 검증하고 실제 isolation success를 주장하지 않는다.

- [ ] **Step 5: 실제 K3s smoke test 범위 제한 기록**

개발 K3s가 사용 가능하면 세 Namespace에 ServiceAccount, ResourceQuota, LimitRange, NetworkPolicy와 hardened Deployment가 생성되는지 조회한다. 실제 cross-instance/host 공격 차단 완료 주장은 `#11/#32` suite 전까지 하지 않는다.

- [ ] **Step 6: 최종 상태와 커밋 확인**

Run both repositories: `git status --short --branch` and `git log --oneline -5`.

Expected: 계획한 파일만 변경되고 각 Task 커밋이 존재하며 working tree가 clean하다.

## Execution Order and Review Gates

1. Provisioner Task 1~2 후 API/profile 계약 리뷰
2. Provisioner Task 3~6 후 manifest/apply-order 보안 리뷰
3. Provisioner Task 7 후 API 문서 리뷰
4. `test_ctf` Task 8~9 후 문제 이미지 호환성 리뷰
5. `test_ctf` Task 10~11 후 CI artifact 계약 리뷰
6. Task 12에서 두 저장소 전체 검증

각 gate에서 범위 밖 refactor를 포함하지 않았는지, baseline을 끄는 필드가 생기지 않았는지, fake test 결과를 실제 K3s enforcement로 오인하지 않았는지 확인한다.
