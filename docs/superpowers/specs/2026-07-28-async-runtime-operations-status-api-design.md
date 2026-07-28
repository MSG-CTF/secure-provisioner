# 비동기 생성·삭제 및 런타임 상태 조회 API 설계

## 문서 상태

- 작성일: 2026-07-28
- 저장소: `MSG-CTF/secure-provisioner`
- 관련 이슈: #16, #25, #26
- 관련 런타임 작업: #17, #18, #24

## 목적

Secure Provisioner에 비동기·멱등 생성·삭제 API와 공통 Operation 폴링
API를 제공한다. 별도의 런타임 상태 API에서는 인스턴스 컨테이너의 실제
상태와 `target_id`가 가리키는 단일 노드 K3s의 배치 가능 자원을 함께
제공한다.

이번 구현은 Secure Provisioner 저장소로 한정한다. Instance Scheduler
저장소는 API 계약을 확인하는 용도로만 사용하며 수정하지 않는다.

## 확정 사항

1. 생성과 삭제 요청을 모두 비동기로 처리한다. 정상 접수되면 HTTP 202와
   `operation_id`를 반환한다.
2. 생성과 삭제는 같은 Operation 상태 모델과 폴링 API를 사용한다.
3. Operation 대기 상태는 `QUEUED`를 사용한다. `WAITING`은 컨테이너
   상태로만 사용하며 Operation 상태에는 사용하지 않는다.
4. 삭제 요청 JSON은 기존 Scheduler DTO에 맞춰 `delete_reason` 필드를
   사용한다.
5. 생성 성공 Operation은 `runtime_workload_id`와 `service_url`을 최종
   결과로 제공한다. 삭제 성공 Operation은 Scheduler가 기존에 기대하던
   `runtime_workload_id`와 `status: SUCCESS` 의미를 유지한다.
6. 런타임 상태는 `instance_id`로 조회한다. 저장된 Binding에서
   `target_id`를 결정하므로 호출자가 다른 target으로 조회를 우회할 수
   없다.
7. 하나의 target은 VM 한 대에서 실행되는 단일 노드 K3s 하나를
   의미한다.
8. 컨테이너 추가 배치 가능 공간은 Kubernetes의
   `allocatable - requested`로 계산한다. 순간 CPU·메모리 사용량은
   관찰용 보조 정보이며 배치 판단의 기준으로 사용하지 않는다.
9. AWS EC2·CloudWatch와 GCP Compute·Monitoring 정보는 2차 작업으로
   분리하며 이번 범위에서 제외한다.
10. 로컬 대시보드는 계속 로컬 전용으로 유지하며 배포 가능한 API 구현에
    포함하지 않는다.

## 작업 범위

### 포함

- Scheduler 호환 생성 요청 디코딩과 검증
- 비동기 생성 접수
- Scheduler 호환 삭제 요청 디코딩과 검증
- 비동기 삭제 접수
- `request_id` 기반 멱등 처리
- Operation 폴링과 최종 결과 응답
- Cluster Registry를 이용한 정확한 `target_id` 라우팅
- Binding과 Kubernetes 리소스 소유권 검증
- Foreground 방식 Namespace 삭제
- 이미 없는 Namespace의 성공 처리
- 오류 재시도 가능 여부 분류와 제한된 재시도
- 컨테이너 생명주기, requests, limits와 Metrics API 사용량 조회
- 단일 노드 K3s 건강 상태, capacity, allocatable, requested,
  schedulable과 Metrics API 사용량 조회
- OpenAPI 3.1 명세와 Markdown 요청·응답 예제
- Fake Kubernetes·Metrics Client 테스트
- 로컬 HTTP 폴링 테스트

### 제외

- `MSG-CTF/instance-scheduler` 변경
- Scheduler DB 상태 변경 또는 폴링 Worker
- Operation·Binding의 운영 DB 영속화
- TTL 감지
- AWS/GCP VM 생성과 삭제
- 클라우드 Provider의 VM 전원, 네트워크, 디스크 I/O 조회
- 멀티노드 K3s target
- target 선택 또는 스케줄링 정책
- 로컬 대시보드 배포와 GitHub 업로드

## 아키텍처

### 런타임 Binding

`InstanceRuntimeBinding`은 workload 실행 위치의 기준 정보다.

```text
instance_id
  -> team_id
  -> target_id
  -> namespace
  -> runtime_workload_id
  -> lifecycle state
```

삭제와 상태 조회는 Binding을 한 번 읽고 Cluster Registry에서 정확히
하나의 target만 해석한다. AWS, GCP 또는 NCP의 다른 target을 순회하지
않는다.

인메모리 Binding Store는 인터페이스 뒤의 Adapter로 유지한다. 운영
영속화는 이번 작업에서 제외하므로 프로세스 재시작 후 복구를 지원한다고
표현하지 않는다.

### 비동기 생성

생성 HTTP Handler는 Scheduler 호환 요청을 검증한 다음
`RuntimeService.EnqueueCreate`를 호출한다.

서비스 처리 순서는 다음과 같다.

1. 같은 `request_id`의 기존 Operation 여부를 확인한다.
2. 같은 요청이면 기존 Operation을 반환하고 다른 요청이면 충돌로
   거부한다.
3. 멱등 CREATE Operation을 등록한다.
4. K3s 생성 완료를 기다리지 않고 Operation을 반환한다.

Worker 처리 순서는 다음과 같다.

1. Operation의 `target_id`로 정확한 K3s Client 하나를 선택한다.
2. 기존 K3s 생성 Adapter로 Namespace, Deployment, Service와 Ingress를
   생성·재조정한다.
3. 현재 Deployment revision의 Pod Ready와 Endpoint 준비를 확인한다.
4. 생성 결과를 Instance Runtime Binding에 저장한다.
5. `runtime_workload_id`와 `service_url`을 Operation 결과에 저장한다.
6. 모든 단계가 끝난 뒤에만 Operation을 `SUCCEEDED`로 변경한다.

생성 중 오류가 발생하면 기존 Adapter의 소유권 검증과 rollback을
사용한다. K3s 생성은 성공했지만 Binding 저장이 실패한 경우에도 해당
요청이 소유한 리소스를 정리한 뒤 Operation을 최종 실패로 기록한다.
일시적인 K3s 오류만 재시도하며 동일한 `request_id`는 새 workload를
만들지 않는다.

### 비동기 삭제

삭제 HTTP Handler는 경로와 Scheduler 호환 요청을 검증한 다음
`RuntimeService.EnqueueDelete`를 호출한다.

서비스 처리 순서는 다음과 같다.

1. `instance_id`로 Binding을 조회한다.
2. 인스턴스, 팀, target, runtime type과 workload 식별자를 비교한다.
3. Binding을 `DELETING`으로 변경한다.
4. 멱등 DELETE Operation을 등록한다.
5. K3s 삭제 완료를 기다리지 않고 Operation을 반환한다.

새로운 Binding 상태 전이 후 Operation 등록이 실패하면 상태를 복구한다.
따라서 `request_id` 충돌이나 Store 오류가 Binding을 `DELETING`에
고립시키지 않는다. 동일 요청의 재전송은 기존 상태를 유지하고 같은
Operation을 반환한다.

Worker 처리 순서는 다음과 같다.

1. Binding을 조회한다.
2. Binding의 `target_id`로 정확한 K3s Client 하나를 선택한다.
3. Namespace의 소유권 Label을 확인한다.
4. Foreground 방식으로 Namespace 삭제를 요청한다.
5. Adapter 제한 시간 안에서 Namespace가 `NotFound`가 될 때까지
   확인한다.
6. Namespace가 이미 없다면 성공으로 처리한다.
7. Scheduler 호환 삭제 결과를 Operation에 저장한다.
8. Binding을 `DELETED`로 변경한다.

### Operation Store

Operation Store는 다음 상태 전이를 관리한다.

```text
QUEUED -> RUNNING -> SUCCEEDED
                  -> RETRYING -> QUEUED
                  -> FAILED
```

`request_id`는 멱등 키다.

- 같은 `request_id`와 같은 명령: 기존 Operation 반환
- 같은 `request_id`와 다른 명령: `REQUEST_ID_CONFLICT`
- 이미 완료된 Operation: 저장된 최종 상태 그대로 반환

로컬 구현은 현재 인메모리 Store를 사용한다. API와 Store 인터페이스는
프로세스 재시작 후에도 Operation이 유지된다고 보장하지 않는다.

### 런타임 상태 조회

상태 조회 서비스는 Binding을 읽고 정확히 하나의 target을 선택한 다음
Namespace 소유권을 검증한다. 이후 다음 정보를 조회한다.

- Kubernetes Core API의 인스턴스 Pod와 컨테이너 상태
- Metrics API의 Pod별 CPU·메모리 사용량
- Core API의 단일 Node와 Node Condition
- Metrics API의 Node CPU·메모리 사용량
- 해당 Node에 배치된 전체 미종료 Pod의 자원 요청량

Node는 반드시 하나여야 한다. Node가 없거나 둘 이상이면 이번 설계의
단일 VM 조건과 다르므로 `TARGET_TOPOLOGY_INVALID`를 반환한다.

Pod 자원 요청량은 Kubernetes 스케줄링 규칙에 맞춰 계산한다. 일반
컨테이너 requests의 합, init container의 최댓값과 Pod overhead를
포함하고 종료된 Pod는 제외한다. 배치 가능 값은 음수가 되지 않도록
0에서 제한한다.

```text
schedulable = max(allocatable - requested, 0)
```

CPU는 millicore, 메모리와 ephemeral storage는 MiB 단위로 반환한다.

Metrics 조회 실패는 상태 전체의 실패로 처리하지 않는다. Core API에서
얻는 상태, capacity, allocatable, requested와 Condition은 그대로
반환한다. 사용량 필드는 `null`, Metrics 사용 가능 여부는 `false`로
표시한다.

## HTTP API

### 생성 접수

```http
POST /internal/v1/instances
Content-Type: application/json
```

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

응답:

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

생성 성공 Operation은 다음 결과를 제공한다.

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

### 삭제 접수

```http
DELETE /internal/v1/instances/{instance_id}
Content-Type: application/json
```

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

응답:

```http
HTTP/1.1 202 Accepted
Location: /internal/v1/operations/op-123
Retry-After: 2
```

```json
{
  "operation_id": "op-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "QUEUED",
  "attempt": 0,
  "max_attempts": 3,
  "created": true
}
```

동일한 요청을 반복하면 `created`가 `false`이고 기존 Operation의 현재
상태가 반환된다.

### Operation 폴링

```http
GET /internal/v1/operations/{operation_id}
```

처리 중 응답:

```json
{
  "operation_id": "op-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "RUNNING",
  "attempt": 1,
  "max_attempts": 3
}
```

상태가 `QUEUED`, `RUNNING` 또는 `RETRYING`이면 응답에 `Retry-After`
Header를 포함한다.

삭제 성공 응답:

```json
{
  "operation_id": "op-123",
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

최종 실패 응답:

```json
{
  "operation_id": "op-123",
  "request_id": "runtime-delete-018f3f1e",
  "type": "DELETE",
  "status": "FAILED",
  "attempt": 3,
  "max_attempts": 3,
  "last_error_code": "TARGET_TEMPORARILY_UNAVAILABLE"
}
```

### 런타임 상태 조회

```http
GET /internal/v1/instances/{instance_id}/runtime-status
```

응답 구조는 다음과 같다.

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

## 오류 계약

API 오류는 기존의 안정적인 Envelope를 사용한다.

```json
{
  "error": {
    "code": "INSTANCE_BINDING_MISMATCH",
    "message": "request does not match the stored runtime binding"
  }
}
```

반드시 제공할 오류는 다음과 같다.

| HTTP | Code | 의미 |
|---|---|---|
| 400 | `INVALID_REQUEST` | 잘못된 JSON, UUID, enum 또는 필수 필드 |
| 404 | `INSTANCE_NOT_FOUND` | 인스턴스 Binding 없음 |
| 404 | `OPERATION_NOT_FOUND` | Operation 없음 |
| 409 | `INSTANCE_BINDING_MISMATCH` | 요청 식별자가 Binding과 다름 |
| 409 | `REQUEST_ID_CONFLICT` | 멱등 키를 다른 명령에 재사용 |
| 409 | `INSTANCE_STATE_CONFLICT` | 현재 Binding 상태에서 삭제 불가 |
| 409 | `RUNTIME_OWNERSHIP_MISMATCH` | Kubernetes 소유권 Label 불일치 |
| 502 | `RUNTIME_STATUS_FAILED` | target 상태 조회 실패 |
| 503 | `TARGET_NOT_FOUND` | Registry에 target 없음 |
| 503 | `TARGET_TOPOLOGY_INVALID` | target이 단일 노드 K3s가 아님 |

kubeconfig 내용, Kubernetes API 주소, 자격 증명, 컨테이너 환경변수와
내부 Client 오류는 응답에 포함하지 않는다.

## 동시성과 실패 처리

- 생성과 삭제는 기존 `(target_id, instance_id)` workload lock을
  공유한다.
- 같은 workload의 생성과 삭제가 Kubernetes 리소스를 동시에 변경하지
  못하게 한다.
- Foreground Namespace 삭제는 제한된 timeout과 poll interval을
  사용한다.
- 명시적으로 분류된 일시 오류만 재시도한다.
- Client 연결이 끊겨도 Operation 소유권은 바뀌지 않으며 새 Operation을
  만들지 않는다.
- 중복 요청은 기존 Operation을 조회한다.
- 소유권 불일치는 최종 오류이며 재시도하지 않는다.
- Metrics 오류는 삭제나 생명주기 상태 변경을 유발하지 않는다.

인메모리 Store는 프로세스 장애 후 복구를 제공하지 못한다. API 문서에서는
이를 로컬 구현의 제한으로 명시하고 영속 Operation을 보장하지 않는다.

## 테스트

### 생성

- 정상 요청이 202, Location, Retry-After와 `QUEUED`를 반환한다.
- 같은 요청을 반복하면 같은 CREATE Operation을 반환한다.
- 같은 `request_id`의 다른 요청은 409를 반환한다.
- Worker가 RUNNING을 거쳐 SUCCEEDED가 된다.
- Pod와 Endpoint가 준비되기 전에는 SUCCEEDED가 되지 않는다.
- 성공 결과가 `runtime_workload_id`와 `service_url`을 포함한다.
- 생성 성공 후 Runtime Binding이 저장된다.
- 재시도 가능한 오류가 RETRYING을 거쳐 성공한다.
- 부분 생성 실패와 Binding 저장 실패가 요청 소유 리소스를 정리한다.

### 삭제

- 정상 요청이 202, Location, Retry-After와 `QUEUED`를 반환한다.
- 같은 요청을 반복하면 같은 Operation을 반환한다.
- 같은 `request_id`의 다른 요청은 409를 반환한다.
- 경로와 본문의 instance가 다르면 409를 반환한다.
- Worker가 RUNNING을 거쳐 SUCCEEDED가 된다.
- 재시도 가능한 오류가 RETRYING을 거쳐 성공한다.
- 최종 오류가 FAILED와 안정 오류 코드를 반환한다.
- Namespace가 이미 없으면 성공한다.
- 소유권이 다르면 삭제 요청을 보내지 않는다.
- 성공 결과가 Scheduler 호환 필드를 포함한다.

### 런타임 상태 조회

- Binding의 target Client 하나만 사용한다.
- 컨테이너 생명주기와 사용량이 정확히 매핑된다.
- Node 하나의 Condition과 자원 상태가 반환된다.
- 해당 Node의 모든 미종료 Pod requests가 합산된다.
- schedulable 자원이 음수가 되지 않는다.
- Metrics API가 없으면 usage가 `null`인 Core 상태를 반환한다.
- Node가 없거나 둘 이상이면 `TARGET_TOPOLOGY_INVALID`를 반환한다.
- Namespace 소유권 불일치를 거부한다.

### 검증 명령

```text
go test -count=1 ./...
go vet ./...
go build ./...
git diff --check
```

로컬 HTTP 테스트는 loopback에서 Provisioner 호환 데모 서비스를
실행한다. 삭제를 접수하고 `SUCCEEDED`까지 폴링하며, 삭제 전에 런타임
상태 응답을 확인한다. 대시보드를 배포하거나 실제 자격 증명을 사용하지
않는다.

## API 문서 산출물

- `docs/api/runtime-operations.md`
- `docs/api/secure-provisioner.openapi.yaml`

두 문서는 비동기 생성·삭제, 공통 Operation 폴링, 런타임 상태 응답,
안정 오류, 멱등 처리와 로컬 인메모리 Store의 영속성 제한을 포함한다.
