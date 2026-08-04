# Secure Provisioner 런타임 API 명세

## 문서 정보

- API 버전: 내부 API v1
- OpenAPI: `docs/api/secure-provisioner.openapi.yaml`
- 설계 문서:
  `docs/superpowers/specs/2026-07-28-async-runtime-operations-status-design.md`
  및 `docs/superpowers/specs/2026-07-30-multi-container-runtime-design.md`

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
  "challenge_ref": {
    "challenge_id": "web-chall2",
    "version": "2026.08.1"
  },
  "isolation_ref": {
    "name": "STANDARD",
    "version": "v1"
  },
  "resource_profile_ref": {
    "name": "SMALL_MULTI",
    "version": "v1"
  },
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-k3s-001"
  },
  "workload": {
    "containers": [
      {
        "name": "web",
        "image": "ghcr.io/msg-ctf/challenges/oob-test/web:latest",
        "ports": [8080],
        "expose": true,
        "run_as_user": 101,
        "writable_paths": [
          {"path": "/tmp", "size_mib": 64}
        ]
      },
      {
        "name": "api",
        "image": "ghcr.io/msg-ctf/challenges/oob-test/web:latest",
        "ports": [8080],
        "expose": false,
        "run_as_user": 10001
      }
    ],
    "internal_connections": [
      {
        "source_container": "web",
        "destination_container": "api",
        "protocol": "TCP",
        "port": 8080
      }
    ],
    "outbound_mode": "NONE",
    "resource_limits": {
      "cpu_millicores": 200,
      "memory_mib": 256,
      "ephemeral_storage_mib": 256
    }
  }
}
```

`containers`는 1개 이상이며 이름은 요청 안에서 고유한 Kubernetes DNS label이어야
한다. 각 컨테이너는 내부 포트를 여러 개 가질 수 있다. `expose: true`인
컨테이너의 포트만 Ingress 접속점으로 공개되며, 적어도 하나는 공개돼야 한다.

`challenge_ref`, `isolation_ref`, `resource_profile_ref`, `outbound_mode`와 각
명시적 컨테이너의 `run_as_user`는 마이그레이션 중인 정책 필드다. 이 중 하나라도
보내면 전부 보내야 하며 일부만 보내거나 빈 객체/값을 명시하면 `400
INVALID_REQUEST`다. `writable_paths`와 `internal_connections`는 명시적 정책
요청 안에서 선택 사항이며, 위 예제는 non-root UID, 크기가 제한된 `/tmp`,
`web -> api:8080/TCP`, 외부 송신 차단 `NONE`을 선언한다. API는 raw Pod spec,
SecurityContext, ServiceAccount, RBAC, RuntimeClass, host namespace/hostPath 같은
Kubernetes 보안 설정을 받지 않는다.

`resource_limits`는 문제 런타임 전체의 합산값이며 `resource_profile_ref`의
trusted profile과 정확히 일치해야 한다. MVP는 `SMALL_SINGLE@v1`을
100m/128MiB/128MiB, `SMALL_MULTI@v1`을 200m/256MiB/256MiB로 해석한다.
root UID(`run_as_user <= 0`), 잘못된 절대 경로·크기·중첩 writable path, 잘못된
내부 연결과 지원하지 않는 outbound enum처럼 요청 자체가 유효하지 않으면 `400
INVALID_REQUEST`다. 형식은 유효하지만 알려지지 않았거나 자원값과 일치하지 않는
profile, `/proc`·`/sys`·`/var/run/secrets` 아래 writable path, writable 합계가
ephemeral-storage 한도를 넘는 요청, 현재 승인하지 않는 `PUBLIC_INTERNET`은 trusted
resolver가 `422 ISOLATION_POLICY_REJECTED`로 거절한다.

기존 단일 컨테이너 요청의 `image`와 `container_port`도 계속 허용한다. 이 형식은
서버에서 이름 `challenge`, `expose: true`인 컨테이너 1개로 변환한다.
`containers`와 기존 필드는 한 요청에서 함께 사용할 수 없다.

정책 마이그레이션 필드를 **모두 생략한** 기존 요청도 계속 허용한다. 서버는
`legacy@v1`, `STANDARD@v1`, 컨테이너 수에 따른 `SMALL_SINGLE@v1` 또는
`SMALL_MULTI@v1`, 각 컨테이너 UID `10001`, 빈 writable/internal connection,
`outbound_mode: NONE`을 적용하고 profile의 자원값으로 정규화한다. 이는 wire
호환을 위한 임시 기본값이지 caller가 baseline을 선택하거나 덮어쓰는 기능이 아니다.

예제의 GHCR 주소는 로컬 통합 테스트용 입력일 뿐이며 코드에 고정되지 않는다.
비공개 Package라면 K3s 노드에 GHCR pull credential을 별도로 설정해야 한다.

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

CREATE adapter가 성공한 뒤에만 Runtime Binding을 저장한다. Binding에는
적용된 challenge ID/version, `STANDARD@v1` 같은 isolation profile identity,
resource profile identity, resolver가 승인한 컨테이너 UID/port/writable path,
내부 연결, outbound mode와 자원 합산값을 방어적으로 복사해 기록한다. raw 요청,
이미지 credential, baseline 보안 플래그 또는 Kubernetes 설정은 기록하지 않는다.
Adapter 실패나 생성 rollback은 Binding을 만들지 않으며, 같은 적용 결과의 멱등
재실행은 기존 Binding을 보존한다. 같은 instance에 다른 적용 정책을 저장하려 하면
충돌로 처리하고 생성 리소스를 rollback한다. Adapter 성공 뒤 Binding 저장이
실패해도 요청 context와 독립된 제한 시간의 cleanup으로 방금 생성한 workload를
삭제한다. cleanup이 성공하면 `RUNTIME_BINDING_SAVE_FAILED`, cleanup도 실패하면 두
원인을 보존한 `ROLLBACK_FAILED`로 기록한다. 두 경우 모두 이번 생성 경로에서는 새
Binding을 저장하지 않으며, `ErrConflict` 또는 `ErrInvalidTransition`을 일으킨 기존
Binding은 변경하지 않고 그대로 보존한다.

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
  "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
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
    "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
    "service_url": "https://gateway.example.com/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001",
    "endpoints": [
      {
        "container_name": "web",
        "port": 8080,
        "service_url": "https://gateway.example.com/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001"
      }
    ]
  }
}
```

`service_url`은 하위 호환을 위한 첫 번째 공개 접속점이다. 신규 연동에서는
`endpoints`를 사용한다. 여러 포트가 공개되면 첫 번째 접속점 이후의 경로는
`/instances/{instance_id}/{container_name}/{port}` 형식이다.

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
    "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
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
  "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
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

다중 컨테이너 런타임은 컨테이너마다 Deployment와 ClusterIP Service를 하나씩
만든다. 조회 결과의 `containers`에는 같은 팀·인스턴스 Namespace에 속한 모든
컨테이너가 반환된다. `endpoint_ready`는 Ingress가 참조하는 모든 공개 Service에
Ready EndpointSlice가 있을 때만 `true`다.

## 생성·삭제의 K3s 단위

- 팀의 문제 런타임 인스턴스 1개마다 전용 Namespace 1개를 만든다.
- 해당 Namespace 안에 전용 `challenge-runtime` ServiceAccount, ResourceQuota,
  LimitRange, NetworkPolicy와 컨테이너별 Deployment·Service, 공개용 Ingress 1개를 둔다.
- ServiceAccount와 Pod 양쪽에서 token 자동 마운트를 끄고, Pod·컨테이너에는 non-root
  UID, read-only root filesystem, privilege escalation·privileged 금지, 모든 Linux
  capability drop, `RuntimeDefault` seccomp와 host namespace 비활성화를 적용한다.
  승인된 writable path만 크기가 제한된 `emptyDir`로 마운트한다.
- ResourceQuota와 LimitRange는 승인된 resource profile의 CPU·memory·ephemeral-storage
  합계와 namespaced object 수를 제한한다.
- `default-deny-all`을 먼저 두고 DNS egress, 공개 컨테이너로 향하는 ingress,
  명시적으로 승인된 컨테이너 간 TCP 연결만 NetworkPolicy allowlist로 연다. 현재
  `outbound_mode`는 `NONE`만 승인하므로 그 밖의 외부 egress는 열지 않는다.
- Namespace와 모든 기존 리소스의 소유권을 먼저 검사한 뒤 ServiceAccount →
  ResourceQuota → LimitRange → NetworkPolicy 순으로 적용·read-back 검증한다. 이 보호
  리소스가 모두 확인된 뒤에만 Deployment → Service → Ingress를 적용한다.
- 생성은 모든 Deployment, Pod, Service Endpoint가 준비돼야 성공한다.
- 생성 중 일부 리소스가 실패하면 해당 Namespace 전체를 롤백한다.
- 삭제는 저장된 `target_id`, Namespace, 팀·인스턴스 소유권을 확인한 뒤
  Namespace 전체를 삭제한다.
- 삭제가 반복됐는데 Namespace가 이미 없으면 성공으로 처리한다.

이 baseline은 Provisioner가 생성한 리소스에 적용하는 방어 계층이다. 별도 Admission
강제와 sandbox RuntimeClass 선택은 아직 없으므로 Provisioner 밖에서 만든 Pod까지
cluster-wide로 강제하지 않으며, 고위험 workload의 커널 격리를 증명하지 않는다.
또한 NetworkPolicy 객체의 생성·read-back과 Registry capability 선언은 dataplane의
실제 enforcement 증명이 아니다. 표준 NetworkPolicy만으로 resident node에서 오거나
resident node·metadata endpoint로 향하는 트래픽의 차단도 보장하지 않는다. 실제 K3s
격리 효과는 `#11`, resident-node/metadata host boundary와 attestation은 `#32`에서
검증해야 production 경계로 간주할 수 있다.

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
| `POST /internal/v1/instances` | 400 | `INVALID_REQUEST` | JSON, UUID, enum, 필수 필드, root UID, writable path 또는 내부 연결 형식이 유효하지 않음 | 접수 거절; Operation/Worker 없음 |
| `POST /internal/v1/instances` | 409 | `REQUEST_ID_CONFLICT` | `request_id`가 다른 명령에 이미 사용됨 | 접수 거절; 기존 Operation은 그대로 유지 |
| `POST /internal/v1/instances` | 415 | `UNSUPPORTED_MEDIA_TYPE` | `Content-Type`이 `application/json`이 아님 | 접수 거절; Operation/Worker 없음 |
| `POST /internal/v1/instances` | 422 | `ISOLATION_POLICY_REJECTED` | 형식은 유효하지만 trusted resolver가 profile 또는 요구사항을 승인하지 않음 | 접수 거절; Operation/Worker/Binding 없음 |
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

`OPERATION_CANCELLED`은 Scheduler가 처리할 실패 code가 아니다. Worker 종료 또는 취소 중
`context.Canceled`/`context.DeadlineExceeded` chain이 반환되면 Worker는
`MarkRetrying`이나 `MarkFailed` 전에 Operation을 재queue한다. 따라서 이 비종결 내부 경로는
영속 `last_error_code`로 기록되지 않는다.

| Operation | `last_error_code` | 조건 | Worker 처리 |
|---|---|---|---|
| `CREATE` | `TARGET_NOT_FOUND` | 생성 target이 Registry에 없음 | 즉시 `FAILED` |
| `CREATE` | `TARGET_DISABLED` | 생성 target이 비활성화됨 | 즉시 `FAILED` |
| `CREATE` | `K3S_UNAVAILABLE` | K3s client를 사용할 수 없음 | 재시도 후 한도 도달 시 `FAILED` |
| `CREATE` | `INVALID_CREATE_COMMAND` | Worker가 받은 생성 명령으로 리소스를 구성할 수 없음 | 즉시 `FAILED` |
| `CREATE` | `RESOURCE_OWNERSHIP_CONFLICT` | 기존 Namespace, Deployment, Service 또는 Ingress의 소유권이 다름 | 즉시 `FAILED` |
| `CREATE` | `RESOURCE_APPLY_FAILED` | Kubernetes 리소스 적용에 실패함 | 재시도 후 한도 도달 시 `FAILED` |
| `CREATE` | `WORKLOAD_NOT_READY` | 준비 시간 안에 Workload가 ready가 되지 않음 | 재시도 후 한도 도달 시 `FAILED` |
| `CREATE` | `RUNTIME_BINDING_SAVE_FAILED` | Workload 생성 뒤 Binding 저장에 실패했지만 생성 리소스 cleanup은 성공함 | 즉시 `FAILED` |
| `CREATE` | `ROLLBACK_FAILED` | 생성 실패 뒤 Namespace rollback 또는 Binding 저장 실패 뒤 cleanup에도 실패함 | cleanup 오류 분류에 따라 재시도하며 한도 도달 시 `FAILED` |
| `CREATE` | `EXECUTION_FAILED` | 코드화되지 않은 실행 실패 | 즉시 `FAILED` |
| `CREATE` | `INVALID_OPERATION_RESULT` | 성공 결과가 Operation Store 검증을 통과하지 못함 | 즉시 `FAILED` |
| `DELETE` | `INSTANCE_NOT_FOUND` | 실행 시점에 Instance Binding이 없음 | 즉시 `FAILED` |
| `DELETE` | `INSTANCE_BINDING_MISMATCH` | 삭제 명령이 Binding과 일치하지 않음 | 즉시 `FAILED` |
| `DELETE` | `TARGET_NOT_FOUND` | 유지보수 target이 Registry에 없음 | 즉시 `FAILED` |
| `DELETE` | `K3S_UNAVAILABLE` | K3s client를 사용할 수 없음 | 재시도 후 한도 도달 시 `FAILED` |
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

MVP profile ref는 `name`과 `version`만 사용한다. immutable digest 또는 Catalog
assignment authority가 아직 아니므로 이 ref만으로 production-grade policy
attestation을 주장하지 않는다. Target Registry의 `security_capabilities`도
NetworkPolicy provider와 DNS/Ingress selector를 운영자가 선언한 값이며 런타임
검증 증명이 아니다. 실제 K3s NetworkPolicy 격리 효과는 `#11`, resident-node 및
metadata host boundary attestation은 `#32`에서 완료해야 production 경계를
충족한다.
