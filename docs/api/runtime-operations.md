# Secure Provisioner 런타임 API 명세

## 문서 정보

- API 버전: 내부 API v1
- OpenAPI: `docs/api/secure-provisioner.openapi.yaml`
- 설계 문서:
  `docs/superpowers/specs/2026-07-28-async-runtime-operations-status-design.md`

## 공통 규칙

- 생성과 삭제는 비동기 Operation으로 접수한다.
- 접수 성공은 HTTP `202 Accepted`다.
- `Location` Header는 Operation 조회 경로를 제공한다.
- `Retry-After` Header는 다음 조회까지 기다릴 초를 제공한다.
- `request_id`는 멱등 키다.
- JSON 필드는 `snake_case`를 사용한다.
- 시간은 UTC RFC 3339 형식을 사용한다.
- 로컬 기본 주소는 `http://127.0.0.1:8080`이다.
- 현재 코드에는 애플리케이션 인증이 연결되지 않았으므로 OpenAPI에는
  `security: []`로 명시한다. 운영 인증은 별도 보안 계약이 필요하다.

## Operation 상태

| 상태 | 의미 |
|---|---|
| `QUEUED` | 접수됐으며 Worker 실행을 기다림 |
| `RUNNING` | K3s에서 생성 또는 삭제 처리 중 |
| `RETRYING` | 일시 오류 후 재시도 대기 중 |
| `SUCCEEDED` | 최종 성공이며 `result`가 존재함 |
| `FAILED` | 최종 실패이며 `last_error_code`가 존재함 |

`WAITING`은 컨테이너 상태에서만 사용하며 Operation 상태에는 사용하지
않는다.

## 생성 접수

```http
POST /internal/v1/instances
Content-Type: application/json
```

### 요청

```json
{
  "request_id": "runtime-create-018f3f1e",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id": 18,
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-k3s-001"
  },
  "workload": {
    "image": "registry.example.com/challenge@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "container_port": 8080,
    "resource_limits": {
      "cpu_millicores": 500,
      "memory_mib": 512,
      "ephemeral_storage_mib": 1024
    }
  }
}
```

### 응답

```http
HTTP/1.1 202 Accepted
Location: /internal/v1/operations/op-create-123
Retry-After: 2
```

```json
{
  "operation_id": "op-create-123",
  "request_id": "runtime-create-018f3f1e",
  "type": "CREATE",
  "status": "QUEUED",
  "attempt": 0,
  "max_attempts": 3,
  "created": true
}
```

동일한 요청을 반복하면 같은 `operation_id`와 현재 상태를 반환하며
`created`는 `false`다.

## 삭제 접수

```http
DELETE /internal/v1/instances/{instance_id}
Content-Type: application/json
```

### 요청

```json
{
  "request_id": "runtime-delete-018f3f1e",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id": 18,
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-k3s-001"
  },
  "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e/challenge",
  "delete_reason": "USER_REQUESTED"
}
```

`instance_id` 경로 값과 본문 값은 같아야 한다.

### 응답

```http
HTTP/1.1 202 Accepted
Location: /internal/v1/operations/op-delete-123
Retry-After: 2
```

```json
{
  "operation_id": "op-delete-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "QUEUED",
  "attempt": 0,
  "max_attempts": 3,
  "created": true
}
```

## Operation 조회

```http
GET /internal/v1/operations/{operation_id}
```

### 처리 중

```http
HTTP/1.1 200 OK
Retry-After: 2
```

```json
{
  "operation_id": "op-create-123",
  "request_id": "runtime-create-018f3f1e",
  "type": "CREATE",
  "status": "RUNNING",
  "attempt": 1,
  "max_attempts": 3
}
```

`QUEUED`, `RUNNING`, `RETRYING` 응답에는 `Retry-After`를 포함한다.

### 생성 성공

```json
{
  "operation_id": "op-create-123",
  "request_id": "runtime-create-018f3f1e",
  "type": "CREATE",
  "status": "SUCCEEDED",
  "attempt": 1,
  "max_attempts": 3,
  "result": {
    "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e/challenge",
    "service_url": "https://challenge.example.com"
  }
}
```

### 삭제 성공

```json
{
  "operation_id": "op-delete-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "SUCCEEDED",
  "attempt": 1,
  "max_attempts": 3,
  "result": {
    "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e/challenge",
    "status": "SUCCESS"
  }
}
```

### 최종 실패

```json
{
  "operation_id": "op-create-123",
  "request_id": "runtime-create-018f3f1e",
  "type": "CREATE",
  "status": "FAILED",
  "attempt": 3,
  "max_attempts": 3,
  "last_error_code": "TARGET_TEMPORARILY_UNAVAILABLE"
}
```

## 런타임 상태 조회

```http
GET /internal/v1/instances/{instance_id}/runtime-status
```

### 응답

```json
{
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "target_id": "aws-k3s-001",
  "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e/challenge",
  "phase": "READY",
  "endpoint_ready": true,
  "metrics_available": true,
  "observed_at": "2026-07-28T14:00:00Z",
  "node": {
    "ready": true,
    "memory_pressure": false,
    "disk_pressure": false,
    "pid_pressure": false,
    "capacity": {
      "cpu_millicores": 2000,
      "memory_mib": 4096,
      "ephemeral_storage_mib": 20480
    },
    "allocatable": {
      "cpu_millicores": 1800,
      "memory_mib": 3584,
      "ephemeral_storage_mib": 18432
    },
    "requested": {
      "cpu_millicores": 900,
      "memory_mib": 1536,
      "ephemeral_storage_mib": 4096
    },
    "schedulable": {
      "cpu_millicores": 900,
      "memory_mib": 2048,
      "ephemeral_storage_mib": 14336
    },
    "usage": {
      "cpu_millicores": 640,
      "memory_mib": 1720
    }
  },
  "containers": [
    {
      "pod_name": "challenge-7b8f64cd8f-kw2gz",
      "name": "challenge",
      "state": "RUNNING",
      "ready": true,
      "restart_count": 0,
      "requests": {
        "cpu_millicores": 100,
        "memory_mib": 128,
        "ephemeral_storage_mib": 256
      },
      "limits": {
        "cpu_millicores": 500,
        "memory_mib": 512,
        "ephemeral_storage_mib": 1024
      },
      "usage": {
        "cpu_millicores": 86,
        "memory_mib": 146
      }
    }
  ]
}
```

### 자원 의미

| 필드 | 의미 |
|---|---|
| `capacity` | VM Node가 가진 전체 자원 |
| `allocatable` | K3s가 Pod에 할당할 수 있는 자원 |
| `requested` | 해당 Node의 미종료 Pod가 예약한 자원 |
| `schedulable` | `max(allocatable - requested, 0)` |
| `usage` | Metrics API가 관찰한 현재 CPU·메모리 사용량 |

Metrics API를 사용할 수 없으면 `metrics_available`은 `false`이고
Node·Container의 `usage`는 `null`이다. Core 상태와 배치 가능 공간은
계속 반환한다.

## 오류 응답

```json
{
  "error": {
    "code": "INSTANCE_BINDING_MISMATCH",
    "message": "request does not match the stored runtime binding"
  }
}
```

| HTTP | Code | 의미 |
|---|---|---|
| 400 | `INVALID_REQUEST` | JSON, UUID, enum 또는 필수 필드 오류 |
| 404 | `INSTANCE_NOT_FOUND` | Instance Binding 없음 |
| 404 | `OPERATION_NOT_FOUND` | Operation 없음 |
| 409 | `INSTANCE_BINDING_MISMATCH` | 요청과 Binding 식별자 불일치 |
| 409 | `REQUEST_ID_CONFLICT` | 멱등 키를 다른 명령에 재사용 |
| 409 | `INSTANCE_STATE_CONFLICT` | 현재 Binding 상태에서 작업 불가 |
| 409 | `RUNTIME_OWNERSHIP_MISMATCH` | Kubernetes 소유권 불일치 |
| 502 | `RUNTIME_STATUS_FAILED` | K3s 상태 조회 실패 |
| 503 | `TARGET_NOT_FOUND` | Registry에 target 없음 |
| 503 | `TARGET_TOPOLOGY_INVALID` | target이 단일 노드 K3s가 아님 |

Operation 실행 중 발생한 오류는 Operation을 `RETRYING` 또는 `FAILED`로
변경하고 `last_error_code`에 안정 오류 코드를 기록한다.

## 로컬 구현 제한

현재 Operation Store와 Binding Store는 인메모리 구현이다. 프로세스를
재시작하면 작업과 Binding이 복구되지 않는다. 운영 영속 저장소가
구현되기 전까지 API는 재시작 내구성을 보장하지 않는다.
