# NodePort Service URL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Return a reachable `http://<target public IP>:<allocated NodePort>` for every exposed workload port without changing the scheduler-facing create response.

**Architecture:** Add an explicit cluster exposure mode with backward-compatible Ingress behavior. In NodePort mode, Kubernetes allocates external ports on exposed Services; the Adapter reads the persisted Service allocations after reconciliation and builds operation endpoints from them. Status checks use the same exposed Services and their EndpointSlices instead of an Ingress.

**Tech Stack:** Go 1.26, Kubernetes client-go v0.36, fake clientsets, existing asynchronous operation and K3s adapter layers.

## Global Constraints

- Do not change scheduler code or the create/status/delete HTTP routes.
- Preserve `service_url` as the first entry of `endpoints`.
- Omitted `exposure_mode` means `INGRESS_PATH`.
- Kubernetes allocates NodePorts; the Provisioner does not maintain a port pool.
- `expose:false` Services remain ClusterIP-only.
- This first implementation returns HTTP/HTTPS URLs from `public_gateway`; TCP scheme negotiation remains out of scope.
- AWS Security Group, GCP Firewall, and static public IP allocation remain external infrastructure work.

---

### Task 1: Cluster exposure mode configuration

**Files:**
- Modify: `internal/k3s/cluster.go`
- Modify: `internal/k3s/config.go`
- Modify: `internal/k3s/registry.go`
- Test: `internal/k3s/config_test.go`
- Test: `internal/k3s/registry_test.go`

**Interfaces:**
- Produces: `type ExposureMode string`
- Produces: `ExposureModeIngressPath`, `ExposureModeNodePort`
- Produces: `ClusterConfig.ExposureMode`

- [ ] **Step 1: Write failing registry tests**

  Add JSON load tests for `"exposure_mode":"NODE_PORT"`, omitted mode defaulting to `INGRESS_PATH`, unknown values returning `CONFIG_INVALID`, and NodePort gateways rejecting a path or explicit port.

- [ ] **Step 2: Run tests to verify RED**

  Run: `go test ./internal/k3s -run 'TestLoadRegistry|TestNewRegistry'`

  Expected: missing field/constant assertions fail.

- [ ] **Step 3: Implement config parsing and validation**

  Define:

  ```go
  type ExposureMode string

  const (
      ExposureModeIngressPath ExposureMode = "INGRESS_PATH"
      ExposureModeNodePort    ExposureMode = "NODE_PORT"
  )
  ```

  Normalize an empty mode to `INGRESS_PATH`. For `NODE_PORT`, require an HTTP or HTTPS `public_gateway` with hostname, no path, query, fragment, user info, or explicit port.

- [ ] **Step 4: Run tests and verify GREEN**

  Run: `gofmt -w internal/k3s/cluster.go internal/k3s/config.go internal/k3s/registry.go internal/k3s/*_test.go && go test ./internal/k3s`

- [ ] **Step 5: Commit**

  ```text
  git add internal/k3s/cluster.go internal/k3s/config.go internal/k3s/registry.go internal/k3s/config_test.go internal/k3s/registry_test.go
  git commit -m "Feat: NodePort 노출 모드 설정"
  ```

### Task 2: NodePort Kubernetes resources

**Files:**
- Modify: `internal/k3s/resources.go`
- Test: `internal/k3s/resources_test.go`

**Interfaces:**
- Consumes: `Cluster.Config.ExposureMode`
- Produces: exposed `corev1.ServiceTypeNodePort` Services in NodePort mode
- Produces: `ResourceSet.Ingress == nil` in NodePort mode
- Produces: `BuildNodePortEndpoints(publicGateway string, services []*corev1.Service) ([]provisioner.WorkloadEndpoint, error)`

- [ ] **Step 1: Write failing resource tests**

  Assert a two-container workload creates a NodePort `web` Service, ClusterIP `internal` Service, and no Ingress. Populate `web.Spec.Ports[0].NodePort = 31042` and assert endpoint URL `http://203.0.113.10:31042`. Add failure cases for zero NodePort and duplicate or missing Service allocations.

- [ ] **Step 2: Run tests to verify RED**

  Run: `go test ./internal/k3s -run 'TestBuildResourceSet.*NodePort|TestBuildNodePortEndpoints'`

  Expected: NodePort resource and endpoint builder tests fail.

- [ ] **Step 3: Implement NodePort resource construction**

  In `BuildResourceSet`, set an exposed Service to `corev1.ServiceTypeNodePort` only when the mode is `NODE_PORT`; keep internal Services as ClusterIP and do not append Ingress paths. Set `ResourceSet.Ingress` to nil in NodePort mode.

- [ ] **Step 4: Implement allocated endpoint construction**

  Iterate Services and their ports in request order. For every NodePort Service port, construct a URL by copying the `public_gateway` URL and setting `url.Host` with `net.JoinHostPort(url.Hostname(), strconv.Itoa(int(port.NodePort)))`. Return `RESOURCE_APPLY_FAILED` if any exposed port has no allocation.

- [ ] **Step 5: Run tests and verify GREEN**

  Run: `gofmt -w internal/k3s/resources.go internal/k3s/resources_test.go && go test ./internal/k3s`

- [ ] **Step 6: Commit**

  ```text
  git add internal/k3s/resources.go internal/k3s/resources_test.go
  git commit -m "Feat: 공개 컨테이너 NodePort 리소스 생성"
  ```

### Task 3: Adapter endpoint result and NodePort preservation

**Files:**
- Modify: `internal/k3s/adapter.go`
- Test: `internal/k3s/adapter_test.go`

**Interfaces:**
- Produces: `appliedResourceSet` with Deployments and Services returned from Kubernetes
- Consumes: `BuildNodePortEndpoints`
- Preserves: Service `ClusterIP`, `ClusterIPs`, and each matching `NodePort` during retry updates

- [ ] **Step 1: Write failing adapter success and retry tests**

  Configure a fake client reactor to allocate NodePort `31042` when the exposed Service is created. Assert `CreateWorkload` returns `http://203.0.113.10:31042`. Preload a Service with that NodePort and assert a retry does not clear or change it.

- [ ] **Step 2: Run tests to verify RED**

  Run: `go test ./internal/k3s -run 'TestAdapter.*NodePort|TestUpsertService.*NodePort'`

- [ ] **Step 3: Return applied Services from reconciliation**

  Change `upsertService` to return the created or updated Service and make `applyResourceSet` retain those server responses alongside Deployments. Skip Ingress preflight and upsert when `resources.Ingress == nil`.

- [ ] **Step 4: Preserve allocated NodePorts**

  In `preserveServiceAllocation`, copy each existing port's `NodePort` into the desired port that has the same name and service port number when the desired value is zero.

- [ ] **Step 5: Build the operation result after readiness**

  In `CreateWorkload`, use existing resource endpoints for Ingress mode and `BuildNodePortEndpoints` with applied Services for NodePort mode. Set `ServiceURL` to the first endpoint and roll back the Namespace on an allocation error.

- [ ] **Step 6: Run tests and verify GREEN**

  Run: `gofmt -w internal/k3s/adapter.go internal/k3s/adapter_test.go && go test ./internal/k3s`

- [ ] **Step 7: Commit**

  ```text
  git add internal/k3s/adapter.go internal/k3s/adapter_test.go
  git commit -m "Feat: 할당 NodePort를 생성 결과로 반환"
  ```

### Task 4: Status readiness by exposure mode

**Files:**
- Modify: `internal/k3s/status.go`
- Test: `internal/k3s/status_test.go`

**Interfaces:**
- Produces: `hasReadyNodePortEndpoints(ctx, client, namespace)`
- Preserves: existing `hasReadyIngressEndpoints` behavior for Ingress mode

- [ ] **Step 1: Write failing NodePort readiness tests**

  Assert NodePort mode returns `endpoint_ready:true` only when every owned NodePort Service has a non-empty Ready EndpointSlice. Assert internal ClusterIP Services do not affect endpoint readiness.

- [ ] **Step 2: Run tests to verify RED**

  Run: `go test ./internal/k3s -run 'TestStatusReader.*NodePort'`

- [ ] **Step 3: Implement mode-specific readiness**

  Select `hasReadyNodePortEndpoints` when `cluster.Config.ExposureMode == ExposureModeNodePort`; otherwise use the existing Ingress function. List owned Services, retain only `Type: NodePort`, and reuse the EndpointSlice readiness rule.

- [ ] **Step 4: Run tests and verify GREEN**

  Run: `gofmt -w internal/k3s/status.go internal/k3s/status_test.go && go test ./internal/k3s`

- [ ] **Step 5: Commit**

  ```text
  git add internal/k3s/status.go internal/k3s/status_test.go
  git commit -m "Feat: NodePort 엔드포인트 준비 상태 조회"
  ```

### Task 5: Contract docs, local registry, and full verification

**Files:**
- Modify: `docs/api/runtime-operations.md`
- Modify: `docs/openapi/runtime-operations.yaml`
- Modify outside repository: `local-runtime-lab/aws-e2e-ui/registry.json`

**Interfaces:**
- Documents: NodePort `service_url` and endpoint example
- Configures: local AWS target with `exposure_mode: NODE_PORT` and its public IP base URL

- [ ] **Step 1: Update documentation examples**

  Add a NodePort response example with `http://203.0.113.10:31042`, state that ports are Kubernetes-allocated, and retain the Ingress mode example as a supported alternative.

- [ ] **Step 2: Run full repository verification**

  Run:

  ```text
  go test ./...
  go vet ./...
  git diff --check
  ```

  Expected: all commands exit 0.

- [ ] **Step 3: Commit repository documentation**

  ```text
  git add docs/api/runtime-operations.md docs/openapi/runtime-operations.yaml docs/superpowers/plans/2026-08-05-nodeport-service-url.md
  git commit -m "Docs: NodePort 참가자 URL 계약 정리"
  ```

- [ ] **Step 4: Configure and restart the local Provisioner**

  Set the local AWS cluster registry to `"exposure_mode":"NODE_PORT"` and `"public_gateway":"http://3.38.101.0"`. Delete test workloads through the existing API before restarting so in-memory bindings are not orphaned.

- [ ] **Step 5: Perform live AWS verification**

  Create the two-container web problem, poll the operation to `SUCCEEDED`, confirm only the public Service is NodePort, confirm the internal Service is ClusterIP, and verify the returned URL contains the allocated NodePort. Test the NodePort from inside the AWS VM; do not change Security Group rules.

- [ ] **Step 6: Delete the live test workload**

  Delete through the asynchronous API, poll to `SUCCEEDED`, and confirm the Namespace and NodePort Service are gone.
