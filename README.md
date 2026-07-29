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
- 저장된 Runtime Binding을 검증한 뒤 실제 K3s Namespace 삭제
- 컨테이너 상태, 요청량·제한량, Metrics 사용량 조회
- 단일 노드의 Condition, capacity, allocatable, requested, schedulable 조회
- Registry에 등록된 AWS·GCP·NCP K3s target을 `target_id`로 직접 선택

API 계약은 [런타임 API 명세](docs/api/runtime-operations.md)와
[OpenAPI](docs/api/secure-provisioner.openapi.yaml)에 정리되어 있습니다.

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
      "enabled": true
    }
  ]
}
```

각 `target_id`는 독립 Kubernetes·Metrics 클라이언트와 연결됩니다. 상태
조회 대상은 노드가 정확히 하나인 K3s여야 합니다.

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
프로세스를 재시작하면 진행 중 작업과 바인딩이 복구되지 않으므로 운영 전
영속 Store가 필요합니다. 실제 비공개 문제 이미지의 Registry 인증·pull
통합 검증은 별도 단계입니다.
