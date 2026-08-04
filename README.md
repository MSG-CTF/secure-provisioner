# Secure Provisioner

CTF 문제 인스턴스의 K3s 워크로드 생성·삭제와 상태 조회를 담당하는 Go
서비스입니다. Instance Scheduler는 `target_id`로 대상 VM의 단일 노드 K3s를
선택하고, 생성·삭제 Operation의 완료 여부를 폴링합니다.

## 현재 구현 범위

- 단일 또는 다중 컨테이너 요청으로 Namespace·Deployment·Service·Ingress 생성
- 문제 전체 합산 자원을 컨테이너별로 균등 분배
- 공개 컨테이너의 포트별 접속 주소 반환
- 생성·삭제 요청의 비동기 Operation 처리
- Operation 상태 폴링과 최종 결과 반환
- 저장된 Runtime Binding의 Namespace UID와 소유권 label을 검증한 뒤 실제 K3s Namespace 삭제
- 컨테이너 상태, 요청량·제한량, Metrics 사용량 조회
- 단일 노드의 Condition, capacity, allocatable, requested, schedulable 조회
- Registry에 등록된 AWS·GCP·NCP K3s target을 `target_id`로 직접 선택
- `STANDARD@v1` 격리 baseline, non-root UID, 제한된 writable path,
  명시적 내부 연결과 기본 `NONE` outbound 정책 적용
- 적용된 challenge/profile identity, resolver 승인 요구사항과 Namespace UID를 Runtime Binding에 기록

API 계약은 [런타임 API 명세](docs/api/runtime-operations.md)와
[OpenAPI](docs/api/secure-provisioner.openapi.yaml)에 정리되어 있습니다.

새 Scheduler 요청은 `challenge_ref`, `isolation_ref`, `resource_profile_ref`,
`outbound_mode`와 각 명시적 컨테이너의 `run_as_user`를 all-or-none으로 보냅니다.
[다중 컨테이너 예제](examples/requests/create-multi-container.json)는 non-root
`web`/`api`, 크기가 제한된 `/tmp`, `web -> api:8080/TCP`, outbound `NONE`을
보여줍니다. raw Kubernetes/보안 설정은 API 계약이 아닙니다. 정책 필드를 모두
생략한 기존 요청은 임시 호환 경로에서 `legacy@v1`, `STANDARD@v1`, 컨테이너
수에 맞는 `SMALL_SINGLE@v1`/`SMALL_MULTI@v1`, UID `10001`, outbound `NONE`으로
정규화됩니다. 일부 정책 필드만 보내는 요청은 호환 요청으로 간주하지 않습니다.

## 실행 설정

`PROVISIONER_CLUSTER_REGISTRY`는 필수입니다.

| 환경 변수 | 기본값 | 의미 |
|---|---:|---|
| `PROVISIONER_CLUSTER_REGISTRY` | 없음 | target Registry JSON 파일 경로 |
| `PROVISIONER_ADDR` | `127.0.0.1:8080` | HTTP 수신 주소 |
| `PROVISIONER_WORKER_CONCURRENCY` | `4` | Operation Worker 수 |
| `PROVISIONER_MAX_ATTEMPTS` | `3` | Operation 최대 시도 횟수 |
| `PROVISIONER_READY_TIMEOUT` | `2m` | 생성 후 Ready 확인 제한 시간 |
| `PROVISIONER_POLL_INTERVAL` | `1s` | K3s 상태 확인 간격 |
| `PROVISIONER_ROLLBACK_TIMEOUT` | `30s` | 생성 실패 rollback 제한 시간 |
| `PROVISIONER_DELETE_TIMEOUT` | `1m` | Namespace 삭제 완료 제한 시간 |
| `PROVISIONER_WORKER_SHUTDOWN_TIMEOUT` | rollback + `10s` | 종료 시 Worker cleanup 대기 시간 |

Registry 예시:

```json
{
  "clusters": [
    {
      "target_id": "aws-k3s-001",
      "provider": "AWS",
      "region": "ap-northeast-2",
      "architecture": "amd64",
      "kubeconfig_path": "C:/secure/kubeconfigs/aws-k3s-001.yaml",
      "public_gateway": "https://gateway.example.com",
      "ingress_class": "traefik",
      "security_capabilities": {
        "network_policy_enforced": true,
        "supplemental_groups_policy_strict": true,
        "network_policy_provider": "kube-router",
        "dns_namespace": "kube-system",
        "dns_pod_selector": {"k8s-app": "kube-dns"},
        "ingress_namespace": "kube-system",
        "ingress_pod_selector": {"app.kubernetes.io/name": "traefik"}
      },
      "enabled": true
    },
    {
      "target_id": "gcp-k3s-001",
      "provider": "GCP",
      "region": "asia-northeast3",
      "architecture": "amd64",
      "kubeconfig_path": "C:/secure/kubeconfigs/gcp-k3s-001.yaml",
      "public_gateway": "https://gateway-gcp.example.com",
      "ingress_class": "traefik",
      "security_capabilities": {
        "network_policy_enforced": true,
        "supplemental_groups_policy_strict": true,
        "network_policy_provider": "kube-router",
        "dns_namespace": "kube-system",
        "dns_pod_selector": {"k8s-app": "kube-dns"},
        "ingress_namespace": "kube-system",
        "ingress_pod_selector": {"app.kubernetes.io/name": "traefik"}
      },
      "enabled": true
    }
  ]
}
```

각 `target_id`는 독립 Kubernetes·Metrics 클라이언트와 연결됩니다. 상태
조회 대상은 노드가 정확히 하나인 K3s여야 합니다.

활성화된 target은 `network_policy_enforced`와
`supplemental_groups_policy_strict`를 모두 명시해야 합니다. 필드가 없거나
`null`이면 Registry 설정이 유효하지 않습니다. 명시적인 `false`는 진단을 위해
로드되지만 workload 생성은 Kubernetes 작업 전에 재시도하지 않는
`TARGET_CAPABILITY_MISMATCH`로 거절됩니다.
기존 활성화 Registry도 새 Provisioner를 rollout하기 전에 이 필드를 추가해야
합니다. 실제 Node/CRI 지원을 확인하지 않은 target은 `true`로 선언하거나
승인하지 말고 `false`로 유지하거나 비활성화해야 합니다.

PowerShell 실행 예시:

```powershell
$env:PROVISIONER_CLUSTER_REGISTRY = "C:\secure\clusters.json"
go run ./cmd/provisioner
```

## 비동기 흐름

생성 또는 삭제 요청이 접수되면 서버는 리소스 작업이 끝나기 전에
`202 Accepted`와 `operation_id`를 반환합니다. Scheduler는 응답의
`Location`을 `Retry-After` 간격으로 조회합니다.

```text
POST 또는 DELETE
  -> 202 QUEUED + operation_id
  -> GET /internal/v1/operations/{operation_id}
  -> QUEUED/RUNNING/RETRYING
  -> SUCCEEDED(result) 또는 FAILED(last_error_code)
```

Scheduler는 CREATE Operation이 `SUCCEEDED`가 되고 `result`에서
`runtime_workload_id`, `service_url`, `endpoints`를 받은 시점에 DB를 `RUNNING`으로
변경할 수 있습니다.

## 다중 컨테이너 로컬 검증

K3s 연결 없이 빠르게 회귀 테스트하려면 다음 명령을 실행합니다.

```powershell
go test ./internal/httpapi ./internal/operations ./internal/k3s ./internal/runtimeops -count=1
```

실제 단일 노드 K3s에서 테스트하려면 아래 환경변수를 설정합니다. 이미지 주소는
요청 입력이므로 다른 문제 이미지로 바꿔도 됩니다.

```powershell
$env:K3S_INTEGRATION_TARGET_ID = "aws-k3s-001"
$env:K3S_INTEGRATION_KUBECONFIG = "C:\secure\kubeconfigs\aws-k3s-001.yaml"
$env:K3S_INTEGRATION_PUBLIC_GATEWAY = "https://gateway.example.com"
$env:K3S_INTEGRATION_IMAGE = "ghcr.io/msg-ctf/challenges/oob-test/web:latest"
$env:K3S_INTEGRATION_CONTAINER_PORT = "8080"
go test ./internal/k3s -run TestK3sIntegrationCreateMultiContainerReadyAndDelete -v -count=1
```

테스트는 같은 이미지로 공개 `web`과 내부 `internal` 컨테이너를 만들고,
모두 Ready인지 확인한 다음 실제 Delete Adapter로 Namespace 전체를 삭제한다.
비공개 GHCR Package라면 K3s가 사용할 `read:packages` 권한의 pull credential이
필요하다. 인증 정보는 API 요청이나 저장소에 넣지 않는다.

## 검증

```powershell
go test -count=1 ./...
go vet ./...
npx --yes @redocly/cli lint docs/api/secure-provisioner.openapi.yaml
```

현재 Operation Store와 Runtime Binding Store는 인메모리 구현입니다.
CREATE 성공 결과 checkpoint는 같은 프로세스 안의 재시도에서는 CREATE 재호출을
막지만, 프로세스를 재시작하면 checkpoint, 진행 중 작업과 바인딩이 복구되지 않으므로
운영 전 영속 Store가 필요합니다. 실제 비공개 문제 이미지의 Registry 인증·pull
통합 검증은 별도 단계입니다.

MVP profile ref는 `name`/`version`뿐이며 immutable digest나 Catalog assignment
authority가 아닙니다. Registry의 `security_capabilities`도 target capability의
선언값이지 실제 enforcement attestation이 아닙니다. Provisioner는 Pod에
`supplementalGroupsPolicy: Strict`를 지정하고 `supplementalGroups`와 `fsGroup`은
지정하지 않지만, 실제 Node의 `status.features.supplementalGroupsPolicy`와 CRI 지원을
자동으로 증명하지 않습니다. 이 Node/CRI attestation은 Task 12 / issue `#11`의
후속 범위입니다. 이 기능이 alpha였던 Kubernetes v1.31-v1.32에서는 지원하지 않는
Node가 Strict 요청을 거절하지 않고 `Merge`로 조용히 fallback할 수 있으므로 해당
Node를 capable로 선언하거나 승인하면 안 됩니다. Kubernetes v1.33 이상은 지원하지
않는 Node의 Strict Pod를 거절하므로 이 경우 workload는 fail-closed로 실패합니다. 이는 특정
K3s 버전의 지원을 보장한다는 의미가 아닙니다. 실제 NetworkPolicy 격리 효과와
resident-node/metadata host boundary는 각각 `#11`, `#32`의 검증이 끝날 때까지
production 완료로 간주하지 않습니다.
