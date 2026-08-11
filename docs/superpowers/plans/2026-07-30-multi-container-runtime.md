# Multi-Container Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 팀별 Namespace 하나에 단일 또는 다중 컨테이너 문제를 비동기 생성·조회 결과·삭제할 수 있게 한다.

**Architecture:** HTTP 계층은 기존 단일 컨테이너 요청을 `containers[]` Domain Command로 정규화한다. K3s Builder는 문제 전체 합산 리소스를 컨테이너 수로 정확히 분배하고 컨테이너별 Deployment·Service와 공개 포트용 Ingress를 만든다. 기존 Operation 흐름은 slice를 안전하게 복사·비교하고 모든 workload가 준비된 뒤 공개 Endpoint 목록을 최종 결과로 반환한다.

**Tech Stack:** Go 1.26, `net/http`, Kubernetes `client-go` v0.36, fake clientset, OpenAPI 3.1

## Global Constraints

- Scheduler와 Broker 저장소는 수정하지 않는다.
- 테스트용 GHCR 주소를 코드 상수나 기본값으로 넣지 않는다.
- `containers[].image`는 요청값을 그대로 사용하며 이번 단계에서는 tag와 digest를 모두 허용한다.
- `containers[].ports`는 한 개 이상의 서로 다른 `1..65535` 정수를 허용한다.
- `resource_limits`는 문제 인스턴스 전체 합산값이며 요청 순서대로 몫과 나머지를 분배한다.
- 격리 정책, Registry 자격 증명 공급, `info.yaml` 파싱은 구현하지 않는다.
- 기존 단일 컨테이너 요청과 첫 번째 `service_url` 계약을 유지한다.
- 새 동작은 실패 테스트를 먼저 확인한 뒤 최소 구현한다.

---

### Task 1: 다중 컨테이너 HTTP 계약과 Domain Command

**Files:**
- Modify: `internal/httpapi/create.go`
- Modify: `internal/httpapi/create_test.go`
- Modify: `internal/httpapi/http_test.go`
- Modify: `internal/provisioner/create.go`
- Modify: `internal/provisioner/model_test.go`
- Modify: `internal/operations/operation.go`
- Modify: `internal/operations/operation_test.go`
- Modify: `internal/operations/memory_store.go`
- Modify: `internal/operations/memory_store_test.go`
- Modify: 기존 `CreateWorkloadCommand` fixture를 만드는 `internal/**/_test.go`

**Interfaces:**
- Consumes: 기존 `CreateWorkloadRequest`, `RuntimeWorkload`, `ResourceLimits`
- Produces: `provisioner.WorkloadContainer`, `CreateWorkloadCommand.Containers`, `CreateWorkloadRequest.ToCommand()`

- [ ] **Step 1: 다중 요청 변환 실패 테스트 작성**

`internal/httpapi/create_test.go`에 실제 JSON을 decode하고 다음 literal을 검증하는
테스트를 추가한다.

```go
func TestCreateWorkloadRequestDecodesMultipleContainers(t *testing.T) {
	var request CreateWorkloadRequest
	err := json.Unmarshal([]byte(`{
	  "request_id":"req-multi",
	  "instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
	  "team_id":18,
	  "target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
	  "workload":{
	    "containers":[
	      {"name":"web","image":"ghcr.io/msg-ctf/challenges/oob-test/web:latest","ports":[8080],"expose":true},
	      {"name":"internal","image":"ghcr.io/msg-ctf/challenges/oob-test/web:latest","ports":[8080,9090],"expose":false}
	    ],
	    "resource_limits":{"cpu_millicores":501,"memory_mib":513,"ephemeral_storage_mib":1025}
	  }
	}`), &request)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	if len(command.Containers) != 2 {
		t.Fatalf("containers = %#v", command.Containers)
	}
	if command.Containers[1].Name != "internal" ||
		!reflect.DeepEqual(command.Containers[1].Ports, []int{8080, 9090}) ||
		command.Containers[1].Expose {
		t.Fatalf("second container = %#v", command.Containers[1])
	}
}
```

- [ ] **Step 2: RED 확인**

Run:

```text
go test ./internal/httpapi -run 'TestCreateWorkloadRequestDecodesMultipleContainers' -count=1
```

Expected: `RuntimeWorkload.Containers` 또는 `CreateWorkloadCommand.Containers`가 없어 compile 실패.

- [ ] **Step 3: Domain과 DTO 최소 구현**

`internal/provisioner/create.go`에 다음 모델을 추가하고 Domain Command에서는 기존
단일 이미지 필드 대신 정규화된 목록을 사용한다.

```go
type WorkloadContainer struct {
	Name   string
	Image  string
	Ports  []int
	Expose bool
}

type CreateWorkloadCommand struct {
	RequestID      string
	InstanceID     string
	TeamID         int64
	RuntimeType    RuntimeType
	TargetID       string
	Containers     []WorkloadContainer
	ResourceLimits ResourceLimits
}
```

`internal/httpapi/create.go`의 DTO는 호환 필드와 새 필드를 함께 decode한다.

```go
type RuntimeContainer struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Ports  []int  `json:"ports"`
	Expose bool   `json:"expose"`
}

type RuntimeWorkload struct {
	Image          string             `json:"image,omitempty"`
	ContainerPort  int                `json:"container_port,omitempty"`
	Containers     []RuntimeContainer `json:"containers,omitempty"`
	ResourceLimits ResourceLimits     `json:"resource_limits"`
}
```

`ToCommand()`는 `containers[]`를 새 slice로 복사한다. 새 목록이 없으면 기존
`image`, `container_port`를 다음 항목 하나로 정규화한다.

```go
provisioner.WorkloadContainer{
	Name: "challenge", Image: request.Workload.Image,
	Ports: []int{request.Workload.ContainerPort}, Expose: true,
}
```

- [ ] **Step 4: Command slice의 방어적 복사와 멱등 비교 구현**

slice 추가로 기존 struct `==` 비교가 compile되지 않으므로 같은 task에서
`copyCreateCommand`와 `sameCreateCommand` helper를 추가한다. 컨테이너 slice와
각 `Ports` slice를 새 backing array로 복사하고 모든 scalar와 slice 항목을
순서대로 비교한다. `NewCreateOperation`, `copyOperation`,
`Operation.SameRequest`와 Memory Store idempotency가 이 helper를 사용하게 한다.

원본 Command를 enqueue한 뒤 원본의 컨테이너 image와 port를 바꿔도 Store 값이
바뀌지 않는 테스트를 먼저 추가한다.

```go
original := validCreateCommand("req-1")
stored, _, err := store.EnqueueCreate(original, 2)
original.Containers[0].Image = "mutated:latest"
original.Containers[0].Ports[0] = 9999
got, err := store.Get(stored.ID)
if err != nil {
	t.Fatal(err)
}
if got.CreateCommand.Containers[0].Image != "nginx:1.27" ||
	got.CreateCommand.Containers[0].Ports[0] != 80 {
	t.Fatalf("store leaked command slices: %#v", got.CreateCommand)
}
```

- [ ] **Step 5: GREEN 확인**

Run:

```text
go test ./internal/httpapi ./internal/provisioner ./internal/operations ./internal/runtimeops ./internal/k3s -count=1
```

Expected: 모든 기존 fixture를 `Containers` 형식으로 바꾼 뒤 PASS.

- [ ] **Step 6: 검증 실패 테스트 작성**

table test로 다음 입력을 각각 거절하는지 검증한다.

```text
containers와 legacy image/container_port 동시 사용
빈 containers와 빈 legacy 입력
중복 container name
DNS label이 아닌 name
빈 image
빈 ports
0 또는 65536 port
한 container 안의 중복 port
expose=true가 하나도 없음
CPU, memory, storage 합산값이 container 수보다 작음
```

- [ ] **Step 7: RED 확인**

Run:

```text
go test ./internal/httpapi -run 'TestCreateWorkloadRequestRejectsInvalidContainerSet' -count=1
```

Expected: 첫 미지원 검증 case가 통과해 test FAIL.

- [ ] **Step 8: 검증 최소 구현**

DNS label은 `k8s.io/apimachinery/pkg/util/validation.IsDNS1123Label`을 사용한다.
컨테이너와 포트 중복은 map으로 검사한다. 합산 리소스는 양수이면서 각 값이
컨테이너 수 이상이어야 한다.

- [ ] **Step 9: HTTP 회귀 검증**

기존 단일 요청이 `challenge` 컨테이너 하나로 enqueue되고 다중 요청이 모든
컨테이너를 보존하는 handler 테스트를 추가한 후 실행한다.

```text
go test ./internal/httpapi ./internal/provisioner -count=1
```

Expected: PASS.

- [ ] **Step 10: 커밋**

```text
git add internal/httpapi internal/provisioner internal/operations internal/runtimeops internal/k3s
git commit -m "Feat: 다중 컨테이너 생성 계약 추가"
```

---

### Task 2: Endpoint Operation 결과

**Files:**
- Modify: `internal/provisioner/create.go`
- Modify: `internal/operations/memory_store.go`
- Modify: `internal/operations/memory_store_test.go`
- Modify: `internal/httpapi/runtime.go`
- Modify: `internal/httpapi/runtime_test.go`

**Interfaces:**
- Consumes: `CreateWorkloadCommand.Containers`
- Produces: `provisioner.WorkloadEndpoint`, `CreateWorkloadResult.Endpoints`, 안전한 결과 copy

- [ ] **Step 1: Endpoint 결과 실패 테스트 작성**

```go
result := OperationResult{Create: &provisioner.CreateWorkloadResult{
	RuntimeWorkloadID: "aws-dev/ns/challenge",
	ServiceURL: "https://gateway/instances/id",
	Endpoints: []provisioner.WorkloadEndpoint{
		{ContainerName: "web", Port: 8080, ServiceURL: "https://gateway/instances/id"},
	},
}}
```

Store 반환값의 Endpoint를 수정해도 다시 조회한 결과가 유지되는지 검증한다.
HTTP `newOperationResultResponse`가 `endpoints[]`를 JSON DTO로 변환하는지도
literal 구조로 검증한다.

- [ ] **Step 2: RED 확인**

Run:

```text
go test ./internal/operations ./internal/httpapi -run 'Test.*Endpoint' -count=1
```

Expected: Endpoint type/field가 없어 compile 실패.

- [ ] **Step 3: Endpoint 모델과 copy 구현**

```go
type WorkloadEndpoint struct {
	ContainerName string
	Port          int
	ServiceURL    string
}

type CreateWorkloadResult struct {
	RuntimeWorkloadID string
	ServiceURL        string
	Endpoints         []WorkloadEndpoint
}
```

Operation 결과 copy도 Endpoint slice를 새 backing array로 복사한다. HTTP
`CreateWorkloadResponse`와 `OperationResultResponse`에는 다음 DTO를 추가한다.

```go
type WorkloadEndpointResponse struct {
	ContainerName string `json:"container_name"`
	Port          int    `json:"port"`
	ServiceURL    string `json:"service_url"`
}
```

- [ ] **Step 4: 전체 Operation 검증**

Run:

```text
go test ./internal/operations ./internal/httpapi ./internal/runtimeops -count=1
```

Expected: PASS.

- [ ] **Step 5: 커밋**

```text
git add internal/provisioner internal/operations internal/httpapi internal/runtimeops
git commit -m "Feat: 다중 컨테이너 Operation 결과 보존"
```

---

### Task 3: 합산 리소스 분배와 Kubernetes ResourceSet

**Files:**
- Modify: `internal/k3s/resources.go`
- Modify: `internal/k3s/resources_test.go`

**Interfaces:**
- Consumes: `CreateWorkloadCommand.Containers`, 전체 `ResourceLimits`
- Produces: slice 기반 `ResourceSet`, 컨테이너별 Deployment/Service, 공개 Ingress와 Endpoint

- [ ] **Step 1: 합산 분배 실패 테스트 작성**

두 컨테이너와 `501m`, `513MiB`, `1025MiB` Command로 ResourceSet을 만들고
요청 순서대로 다음 literal을 검증한다.

```text
web:      251m, 257MiB, 513MiB
internal: 250m, 256MiB, 512MiB
합계:     501m, 513MiB, 1025MiB
```

- [ ] **Step 2: RED 확인**

Run:

```text
go test ./internal/k3s -run 'TestBuildResourceSetDistributesAggregateLimitsExactly' -count=1
```

Expected: 단일 `Deployment` 구조라 FAIL.

- [ ] **Step 3: slice 기반 ResourceSet과 분배 구현**

```go
type ResourceSet struct {
	Namespace          *corev1.Namespace
	Deployments        []*appsv1.Deployment
	Services           []*corev1.Service
	Ingress            *networkingv1.Ingress
	ExpectedSpecHashes map[string]string
	RuntimeWorkloadID  string
	ServiceURL         string
	Endpoints          []provisioner.WorkloadEndpoint
}
```

각 리소스 단위에 대해 `base := total/count`, `remainder := total%count`를
계산하고 index가 remainder보다 작으면 1을 더한다.

- [ ] **Step 4: 컨테이너별 리소스 실패 테스트 작성**

다음 동작을 literal로 검증한다.

```text
Deployment names: web, internal
Service names: web, internal
각 Deployment selector는 msgctf.io/container-name으로 서로 다름
각 Service에는 요청한 복수 port가 모두 존재
Ingress backend에는 web Service만 존재
첫 web port path는 /instances/{instance_id}
두 번째 공개 port path는 /instances/{instance_id}/web/{port}
internal은 Ingress backend에 없음
Endpoints와 service_url은 공개 path와 같은 순서
```

- [ ] **Step 5: RED 확인**

Run:

```text
go test ./internal/k3s -run 'TestBuildResourceSetCreatesMultipleContainerResources' -count=1
```

Expected: 단일 `challenge` resource만 생성해 FAIL.

- [ ] **Step 6: 컨테이너별 Kubernetes object 구현**

각 컨테이너별 ownership labels에
`"msgctf.io/container-name": container.Name`을 추가한다. Deployment/Service
이름은 컨테이너 이름을 사용한다. Service port name은
`fmt.Sprintf("port-%d", port)`로 만든다.
Ingress는 하나이며 공개 port마다 path 하나를 만든다.

컨테이너별 spec hash는 instance/team/target와 해당 container spec,
분배된 resource limits로 계산한다. `request_id`와 gateway는 hash에서
제외한다.

- [ ] **Step 7: 유효성·hash 회귀 테스트 정리**

기존 단일 컨테이너 ResourceSet 테스트는 정규화된 `challenge` Command를
사용하고 slice의 첫 항목을 확인하게 바꾼다. container image, port,
expose, 순서 또는 분배된 한도가 바뀌면 관련 hash가 바뀌는지 확인한다.

- [ ] **Step 8: GREEN 확인**

Run:

```text
go test ./internal/k3s -run 'TestBuildResourceSet|TestRuntimeWorkloadIDAndServiceURL' -count=1
```

Expected: PASS.

- [ ] **Step 9: 커밋**

```text
git add internal/k3s/resources.go internal/k3s/resources_test.go
git commit -m "Feat: 다중 컨테이너 K3s 리소스 생성"
```

---

### Task 4: 모든 Deployment와 Service 준비 확인

**Files:**
- Modify: `internal/k3s/adapter.go`
- Modify: `internal/k3s/adapter_test.go`
- Modify: `internal/k3s/status.go`
- Modify: `internal/k3s/status_test.go`
- Modify: `internal/k3s/integration_test.go`

**Interfaces:**
- Consumes: slice 기반 `ResourceSet`
- Produces: 원자적 apply, 전체 workload readiness, 다중 상태 조회, Namespace rollback

- [ ] **Step 1: 전체 apply 실패 테스트 작성**

fake clientset으로 다중 Command를 실행하고 Deployment와 Service가 각각 두 개,
Ingress가 하나 생성되는지 확인한다. 두 번째 Service 생성 reactor가 오류를
반환하면 Namespace rollback이 실행되고 첫 번째 리소스도 남지 않는지 확인한다.

- [ ] **Step 2: RED 확인**

Run:

```text
go test ./internal/k3s -run 'TestAdapter(AppliesAllContainerResources|RollsBackMultiContainerApplyFailure)' -count=1
```

Expected: `applyResourceSet`이 단일 child만 처리해 FAIL.

- [ ] **Step 3: preflight와 apply 반복 구현**

모든 Deployment, Service와 Ingress의 소유권을 먼저 preflight한다. 충돌이
없을 때만 각 slice를 결정적 요청 순서로 upsert한다. 하나라도 실패하면 기존
`failWithRollback`으로 요청 Namespace 전체를 정리한다.

- [ ] **Step 4: 전체 readiness 실패 테스트 작성**

첫 Deployment/Service Endpoint만 준비된 fake client에서
`CreateWorkload`가 반환하지 않는지 확인한다. 두 번째 Deployment의 Ready Pod와
두 번째 Service EndpointSlice를 추가한 뒤에만 성공하는지 확인한다.

- [ ] **Step 5: RED 확인**

Run:

```text
go test ./internal/k3s -run 'TestAdapterWaitsForEveryContainerAndService' -count=1
```

Expected: 첫 workload만 확인하는 기존 readiness가 일찍 성공해 FAIL.

- [ ] **Step 6: 전체 readiness 구현**

`waitUntilReady`는 각 Deployment의 expected hash, Ready Pod와 같은 이름의
Service EndpointSlice를 모두 확인한다. EndpointSlice 조회 selector는
`discoveryv1.LabelServiceName: service.Name`을 사용한다.

- [ ] **Step 7: 상태 조회 회귀 테스트**

같은 Namespace의 서로 다른 Deployment Pod 두 개가 모두
`RuntimeStatus.Containers`에 나오고, 내부 Service Endpoint도 준비된 상태에서
공개 EndpointReady가 올바르게 계산되는지 검증한다. 상태 조회는 Binding의
Namespace만 사용하며 다른 팀 Namespace를 포함하지 않아야 한다.

- [ ] **Step 8: 실제 K3s 통합 테스트 확장**

`TestK3sIntegrationCreateMultiContainerReadyAndCleanup`을 추가한다. 기존
`K3S_INTEGRATION_IMAGE`와 `K3S_INTEGRATION_CONTAINER_PORT`를 사용해 같은
테스트 이미지를 `web`과 `internal` 두 Deployment로 생성한다. `web`만
`Expose: true`로 두고 Deployment/Service 두 개와 Ingress 하나를 조회한 뒤
cleanup한다.

- [ ] **Step 9: GREEN 확인**

Run:

```text
go test ./internal/k3s -count=1
```

Expected: fake-client 전체 PASS. 실제 K3s 환경변수가 없으면 통합 test는 명시적으로 SKIP.

- [ ] **Step 10: 커밋**

```text
git add internal/k3s
git commit -m "Feat: 다중 컨테이너 준비 상태 검증"
```

---

### Task 5: API 문서와 로컬 GHCR 검증

**Files:**
- Modify: `docs/api/runtime-operations.md`
- Modify: `docs/api/secure-provisioner.openapi.yaml`
- Modify: `README.md`
- Create: `examples/requests/create-multi-container.json`
- Create: `examples/requests/delete-runtime.json`

**Interfaces:**
- Consumes: 최종 HTTP 요청/Operation 응답 계약
- Produces: 사람이 실행할 수 있는 요청 예제와 OpenAPI schema

- [ ] **Step 1: 실행 가능한 다중 요청 예제 추가**

`examples/requests/create-multi-container.json`은 제공된 GHCR 이미지를
`web`, `internal` 두 항목에 사용하고 합산 리소스를 포함한다. 주소는 테스트
입력에만 존재하며 production code에는 넣지 않는다.

- [ ] **Step 2: Markdown 계약 갱신**

다중 컨테이너 요청, 단일 요청 호환, 합산 분배, 내부 Service DNS,
`endpoints[]`, GHCR 인증 전제와 삭제가 Namespace 전체에 적용된다는 내용을
한글로 추가한다.

- [ ] **Step 3: OpenAPI schema 갱신**

`RuntimeContainer`, `WorkloadEndpoint` schema를 추가한다.
`Workload`는 `resource_limits`와 함께 legacy 단일 필드 조합 또는
`containers`를 받는 `oneOf` 계약으로 표현한다. `CreateOperationResult`의
required에 `endpoints`를 추가한다.

- [ ] **Step 4: 문서·계약 회귀 검사**

Run:

```text
go test ./internal/httpapi -count=1
git diff --check
```

Expected: PASS.

- [ ] **Step 5: 로컬 이미지 접근 확인**

자격 증명을 출력하지 않고 다음을 실행한다.

```text
docker manifest inspect ghcr.io/msg-ctf/challenges/oob-test/web:latest
```

성공하면 digest와 platform만 기록한다. `unauthorized`이면 코드 문제가 아니라
GHCR `read:packages` 또는 K3s containerd 인증 준비가 필요한 것으로 기록한다.

- [ ] **Step 6: 가능한 경우 실제 K3s 다중 생성·삭제**

다음 환경변수가 이미 안전하게 준비된 경우에만 실행한다.

```text
K3S_INTEGRATION_TARGET_ID
K3S_INTEGRATION_KUBECONFIG
K3S_INTEGRATION_PUBLIC_GATEWAY
K3S_INTEGRATION_IMAGE
K3S_INTEGRATION_CONTAINER_PORT
```

Run:

```text
go test ./internal/k3s -run 'TestK3sIntegrationCreateMultiContainerReadyAndCleanup' -count=1 -v
```

환경이나 GHCR 인증이 없으면 fake-client 검증 완료와 외부 blocker를 구분해
보고한다.

- [ ] **Step 7: 커밋**

```text
git add docs README.md examples/requests
git commit -m "Docs: 다중 컨테이너 API와 테스트 예제 추가"
```

---

### Task 6: 전체 회귀 검증

**Files:**
- Verify only

**Interfaces:**
- Consumes: Tasks 1-5의 모든 변경
- Produces: 병합 가능한 검증 결과

- [ ] **Step 1: format**

Run:

```text
gofmt -w internal
```

- [ ] **Step 2: 전체 test**

Run:

```text
go test -count=1 ./...
```

Expected: 모든 package PASS, 외부 환경이 필요한 test만 명시적 SKIP.

- [ ] **Step 3: vet와 build**

Run:

```text
go vet ./...
go build ./...
```

Expected: exit code 0.

- [ ] **Step 4: diff 검사**

Run:

```text
git diff --check
git status --short --branch
git log --oneline --decorate -8
```

Expected: whitespace 오류 없음. 의도한 파일 외 변경 없음.
