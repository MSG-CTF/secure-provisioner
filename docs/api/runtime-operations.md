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

`requested`는 해당 Node에 배치된 `Succeeded`, `Failed` 이외 Pod를 대상으로
일반 컨테이너 요청량 합계, init container의 실행 단계별 최대 요청량,
Pod overhead를 반영한다. 다른 Node에 배치됐거나 아직 Node가 정해지지 않은
Pod는 포함하지 않는다.

Metrics API를 사용할 수 없으면 `metrics_available`은 `false`이고
Node·Container의 `usage`는 `null`이다. Core 상태와 배치 가능 공간은
계속 반환한다.

## 오류 응답

<!-- Historical summary retained in source only; superseded by the Scheduler contract below.

이 절의 endpoint별 오류 계약과 Scheduler 계약은 아래 기존의 간단한 오류 표를 대체한다.

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

-->

### Scheduler 오류 계약

이 하위 절이 위의 요약 표보다 우선하는 현재 구현 기준의 계약이다. HTTP 접수 실패와
Scheduler가 처리한 비동기 Operation의 최종 실패는 서로 다른 계약이다.

- Operation 생성 전 HTTP 접수 실패는 해당 HTTP 상태와 다음 envelope를 반환한다. 이 경우
  Operation은 생성되지 않았고 Worker도 실행하지 않는다.

```json
{
  "error": {
    "code": "...",
    "message": "..."
  }
}
```

- Worker 실행 뒤의 실패는 HTTP 오류 응답으로 바꾸지 않는다. `GET /internal/v1/operations/{operation_id}`가
  HTTP `200 OK`로 Operation을 반환하며, 최종 실패는 `status: "FAILED"`와
  `last_error_code`로 식별한다. 원인 문자열이나 인프라 상세는 노출하지 않는다.

#### Endpoint별 HTTP 접수 오류

아래 표의 Scheduler 동작은 **HTTP 접수 오류가 반환된 경우**의 동작이다. 이 표의 code는
`last_error_code`가 아니며, 이미 생성된 Operation의 상태를 변경하지 않는다.

| Endpoint | HTTP | Stable code | 사유 | Scheduler 동작 |
|---|---:|---|---|---|
| `POST /internal/v1/instances` | 400 | `INVALID_REQUEST` | JSON, UUID, enum 또는 필수 필드가 유효하지 않음 | 접수 거절; Operation/Worker 없음 |
| `POST /internal/v1/instances` | 409 | `REQUEST_ID_CONFLICT` | `request_id`가 다른 명령에 이미 사용됨 | 접수 거절; 기존 Operation은 그대로 유지 |
| `POST /internal/v1/instances` | 415 | `UNSUPPORTED_MEDIA_TYPE` | `Content-Type`이 `application/json`이 아님 | 접수 거절; Operation/Worker 없음 |
| `POST /internal/v1/instances` | 502 | `CREATE_QUEUE_FAILED` | 생성 Operation을 queue에 기록하지 못함 | 접수 거절; Worker 실행 없음 |
| `DELETE /internal/v1/instances/{instance_id}` | 400 | `INVALID_REQUEST` | JSON, 경로/본문 값, enum 또는 필수 필드가 유효하지 않음 | 접수 거절; Operation/Worker 없음 |
| `DELETE /internal/v1/instances/{instance_id}` | 404 | `INSTANCE_NOT_FOUND` | Instance Binding이 없음 | 접수 거절; Operation/Worker 없음 |
| `DELETE /internal/v1/instances/{instance_id}` | 409 | `INSTANCE_BINDING_MISMATCH` | 요청이 저장된 Binding과 일치하지 않음 | 접수 거절; Operation/Worker 없음 |
| `DELETE /internal/v1/instances/{instance_id}` | 409 | `REQUEST_ID_CONFLICT` | `request_id`가 다른 명령에 이미 사용됨 | 접수 거절; 기존 Operation은 그대로 유지 |
| `DELETE /internal/v1/instances/{instance_id}` | 409 | `INSTANCE_STATE_CONFLICT` | 현재 Binding 상태에서는 삭제를 시작할 수 없음 | 접수 거절; Operation/Worker 없음 |
| `DELETE /internal/v1/instances/{instance_id}` | 415 | `UNSUPPORTED_MEDIA_TYPE` | `Content-Type`이 `application/json`이 아님 | 접수 거절; Operation/Worker 없음 |
| `DELETE /internal/v1/instances/{instance_id}` | 502 | `DELETE_QUEUE_FAILED` | 삭제 Operation을 queue에 기록하지 못함 | 접수 거절; Worker 실행 없음 |
| `GET /internal/v1/operations/{operation_id}` | 404 | `OPERATION_NOT_FOUND` | Operation이 없음 | 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |
| `GET /internal/v1/operations/{operation_id}` | 500 | `OPERATION_LOOKUP_FAILED` | Operation Store 조회 실패 | 조회 실패; Scheduler 상태는 변경하지 않음 |
| `GET /internal/v1/instances/{instance_id}/runtime-status` | 404 | `INSTANCE_NOT_FOUND` | Instance Binding이 없음 | 상태 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |
| `GET /internal/v1/instances/{instance_id}/runtime-status` | 409 | `RUNTIME_OWNERSHIP_MISMATCH` | Kubernetes 리소스 소유권이 Binding과 다름 | 상태 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |
| `GET /internal/v1/instances/{instance_id}/runtime-status` | 503 | `TARGET_NOT_FOUND` | Registry에 target이 없음 | 상태 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |
| `GET /internal/v1/instances/{instance_id}/runtime-status` | 503 | `TARGET_TOPOLOGY_INVALID` | target이 단일 노드 K3s 토폴로지가 아님 | 상태 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |
| `GET /internal/v1/instances/{instance_id}/runtime-status` | 502 | `TARGET_TEMPORARILY_UNAVAILABLE` | target 조회가 일시적으로 불가함 | 상태 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |
| `GET /internal/v1/instances/{instance_id}/runtime-status` | 502 | `K3S_UNAVAILABLE` | K3s client가 준비되지 않음 | 상태 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |
| `GET /internal/v1/instances/{instance_id}/runtime-status` | 502 | `RUNTIME_STATUS_FAILED` | 코드화되지 않은 런타임 상태 조회 실패 | 상태 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |

#### Scheduler Operation 실행 오류

아래 code는 Worker가 실행 중 기록할 수 있는 `last_error_code`다. retryable code는
`max_attempts`에 도달하기 전 `RETRYING`이 된 뒤 재queue되고, 비재시도 code 또는 마지막
시도 실패는 `FAILED`가 된다. `INVALID_OPERATION_RESULT`는 Worker가 성공 결과를 저장하지
못할 때 직접 `FAILED`로 기록한다.

| Operation | `last_error_code` | 조건 | Worker 처리 |
|---|---|---|---|
| `CREATE` | `TARGET_NOT_FOUND` | 생성 target이 Registry에 없음 | 즉시 `FAILED` |
| `CREATE` | `TARGET_DISABLED` | 생성 target이 비활성화됨 | 즉시 `FAILED` |
| `CREATE` | `K3S_UNAVAILABLE` | K3s client를 사용할 수 없음 | 재시도 후 한도 도달 시 `FAILED` |
| `CREATE` | `INVALID_CREATE_COMMAND` | Worker가 받은 생성 명령으로 리소스를 구성할 수 없음 | 즉시 `FAILED` |
| `CREATE` | `OPERATION_CANCELLED` | 작업 context가 취소됨 | 재시도 후 한도 도달 시 `FAILED` |
| `CREATE` | `RESOURCE_OWNERSHIP_CONFLICT` | 기존 Namespace, Deployment, Service 또는 Ingress의 소유권이 다름 | 즉시 `FAILED` |
| `CREATE` | `RESOURCE_APPLY_FAILED` | Kubernetes 리소스 적용에 실패함 | 재시도 후 한도 도달 시 `FAILED` |
| `CREATE` | `WORKLOAD_NOT_READY` | 준비 시간 안에 Workload가 ready가 되지 않음 | 재시도 후 한도 도달 시 `FAILED` |
| `CREATE` | `ROLLBACK_FAILED` | 생성 실패 후 Namespace rollback에 실패함 | 재시도 후 한도 도달 시 `FAILED` |
| `CREATE` | `EXECUTION_FAILED` | 코드화되지 않은 실행 실패 | 즉시 `FAILED` |
| `CREATE` | `INVALID_OPERATION_RESULT` | 성공 결과가 Operation Store 검증을 통과하지 못함 | 즉시 `FAILED` |
| `DELETE` | `INSTANCE_NOT_FOUND` | 실행 시점에 Instance Binding이 없음 | 즉시 `FAILED` |
| `DELETE` | `INSTANCE_BINDING_MISMATCH` | 삭제 명령이 Binding과 일치하지 않음 | 즉시 `FAILED` |
| `DELETE` | `TARGET_NOT_FOUND` | 유지보수 target이 Registry에 없음 | 즉시 `FAILED` |
| `DELETE` | `K3S_UNAVAILABLE` | K3s client를 사용할 수 없음 | 재시도 후 한도 도달 시 `FAILED` |
| `DELETE` | `OPERATION_CANCELLED` | 작업 context가 취소됨 | 재시도 후 한도 도달 시 `FAILED` |
| `DELETE` | `RUNTIME_OWNERSHIP_MISMATCH` | Namespace 소유권이 Binding과 다름 | 즉시 `FAILED` |
| `DELETE` | `TARGET_TEMPORARILY_UNAVAILABLE` | Kubernetes API 호출이 일시적으로 실패함 | 재시도 후 한도 도달 시 `FAILED` |
| `DELETE` | `NAMESPACE_DELETE_TIMEOUT` | Namespace 삭제 완료 대기 시간이 초과됨 | 재시도 후 한도 도달 시 `FAILED` |
| `DELETE` | `EXECUTION_FAILED` | 코드화되지 않은 실행 실패 | 즉시 `FAILED` |
| `DELETE` | `INVALID_OPERATION_RESULT` | 성공 결과가 Operation Store 검증을 통과하지 못함 | 즉시 `FAILED` |

`UNSUPPORTED_OPERATION`은 Executor의 방어적 분기에서만 반환되며, 이 API가 생성하는
`CREATE`/`DELETE` Operation에는 도달하지 않는다. 따라서 외부 Scheduler 계약 표에는 포함하지 않는다.

#### Scheduler 폴링과 다음 단계

| Operation 상태 | Scheduler 동작 |
|---|---|
| `QUEUED`, `RUNNING`, `RETRYING` | 같은 `operation_id`를 `Retry-After` 기준으로 계속 조회한다. 이 기간에는 같은 create/delete 요청을 같은 `request_id`로 새로 접수하지 않는다. |
| `SUCCEEDED` | `result`를 사용해 다음 단계로 진행한다. |
| `FAILED` | `last_error_code`를 확인한 뒤 요청을 중단하거나 운영자 확인·조치를 수행한다. 실패 Operation은 자동으로 새 요청으로 바꾸지 않는다. |

이미지 pull 실패, capacity 사전 거절, DNS/외부 URL, 인증, 영속 Store 접근 오류의 세부 분류는
현재 필수 API 계약이 아니다. 이들은 별도 후속 확장 범위에서 code, HTTP/Operation 노출 방식,
재시도 정책을 함께 설계한다.

## 로컬 구현 제한

현재 Operation Store와 Binding Store는 인메모리 구현이다. 프로세스를
재시작하면 작업과 Binding이 복구되지 않는다. 운영 영속 저장소가
구현되기 전까지 API는 재시작 내구성을 보장하지 않는다.
