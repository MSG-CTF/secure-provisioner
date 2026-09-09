# Secure Provisioner 런타임 API 명세

## 문서 정보

- API 버전: 내부 API v1
- OpenAPI: `docs/api/secure-provisioner.openapi.yaml`
- 설계 문서:
  `docs/superpowers/specs/2026-07-28-async-runtime-operations-status-design.md`
  및 `docs/superpowers/specs/2026-09-09-instance-network-policy-design.md`

## 공통 규칙

- 생성과 삭제는 비동기 Operation으로 접수한다.
- 접수 성공은 HTTP `202 Accepted`다.
- `Location` Header는 Operation 조회 경로를 제공한다.
- `Retry-After` Header는 다음 조회까지 기다릴 초를 제공한다.
- `request_id`는 멱등 키다.
- JSON 필드는 `snake_case`를 사용한다.
- 시간은 UTC RFC 3339 형식을 사용한다.
- 로컬 기본 주소는 `http://127.0.0.1:8080`이다.
- 모든 `/internal/v1/*` 요청은 `Authorization: Bearer <service_token>` Header를
  정확히 한 번 보내야 한다.
- token이 없거나 형식이 잘못됐거나 유효하지 않으면 body나 Operation을 처리하지
  않고 `401 UNAUTHENTICATED`와 `WWW-Authenticate: Bearer realm="secure-provisioner"`를 반환한다.
- 운영 전송은 HTTPS를 사용한다. 현재 token과 선택적인 이전 token을 함께 허용해
  Scheduler token을 무중단 교체할 수 있다.

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
Authorization: Bearer <service_token>
Content-Type: application/json
```

### 요청

```json
{
  "request_id": "runtime-create-018f3f1e",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id": "00000000-0000-4000-8000-000000000018",
  "isolation_profile": "WEB",
  "target": {
    "runtime_type": "KUBERNETES",
    "target_id": "aws-k3s-001"
  },
  "workload": {
    "containers": [
      {
        "name": "web",
        "image": "ghcr.io/msg-ctf/challenges/oob-test/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ports": [8080],
        "expose": true,
        "run_as_user": 101,
        "writable_paths": [
          {"path": "/tmp/web", "size_mib": 64}
        ]
      },
      {
        "name": "api",
        "image": "ghcr.io/msg-ctf/challenges/oob-test/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ports": [9000],
        "expose": false,
        "run_as_user": 10001
      }
    ],
    "resource_limits": {
      "cpu_millicores": 500,
      "memory_mib": 512,
      "ephemeral_storage_mib": 1024
    }
  }
}
```

`containers`는 1개 이상이며 이름은 요청 안에서 고유한 Kubernetes DNS label이어야
한다. 각 컨테이너는 내부 포트를 여러 개 가질 수 있다. workload 전체에서
공개 포트는 적어도 1개 있어야 한다. 공개 선언은 컨테이너마다 다음 중 하나를 사용한다.

- 기존 `expose: true`: `ports` 전체 공개. `false`, `null`, 생략은 전체 private.
- 신규 `exposed_ports`: 공개할 포트 목록. 중복 없는 `ports` 부분집합이며 빈 배열은
  전체 private다. `null`, 중복, 범위 밖 포트, `ports`에 없는 포트는 거절한다.
- 두 필드를 함께 보내면 `expose: false`나 `null`도 포함하여 `400 INVALID_REQUEST`다.

### 같은 WEB 컨테이너에서 public/private 포트 혼합

다음은 `containers[]` 원소 예시다. 8080만 외부에 공개하고 9000에는 NodePort나
Ingress를 만들지 않는다. 전체 요청 예시는
[`create-web-mixed-ports.json`](../../examples/requests/create-web-mixed-ports.json)을 참고한다.
이미지 digest와 target_id는 예시이며 실환경 값으로 교체해야 한다.

```json
{
  "name": "web",
  "image": "web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "ports": [8080, 9000],
  "exposed_ports": [8080],
  "run_as_user": 10001
}
```

혼합 컨테이너의 내부 Service는 기존 컨테이너 이름을 유지하며 모든 `ports`를
가진 ClusterIP다. 별도 공개 Service는 공개 포트만 포함하고, NODE_PORT에서는
NodePort, INGRESS_PATH에서는 Ingress backend용 ClusterIP가 된다. 생성 결과의
`endpoints[]`에는 8080만 포함한다. 동일 인스턴스의 다른 컨테이너는 내부 Service의
9000에 별도 연결 선언 없이 접근할 수 있다. 다른 인스턴스에는 내부 허용 규칙이
적용되지 않는다. 같은 컨테이너 내부 loopback 통신도 유지한다.

기존 전체 공개/비공개 요청의 Service 이름과 저장 표현은 유지한다. 목록은 `ports`
순서로 정규화하며, 전체 포트 선택은 기존 `expose:true`와 동일하게 처리한다.
PWN은 기존 보안 범위를 유지하여 공개 컨테이너의 `ports` 자체가 1개여야 한다.

**롤아웃:** 먼저 이 변경이 포함된 Provisioner를 배포해야 한다. 이전 Provisioner는
`exposed_ports`를 unknown field로 거절한다. Scheduler의 입력·저장·Runtime DTO가
새 필드를 전달하도록 변경한 뒤 Scheduler를 배포한다. 현재 Scheduler dev의
다중 endpoints 지원만으로 포트별 공개 요청을 전송할 수 있는 것은 아니다.

`isolation_profile`은 필수이며 정확히 `WEB` 또는 `PWN`이어야 한다. 누락하거나
소문자·알 수 없는 값을 보내면 `400 INVALID_REQUEST`다. Provisioner는 이를 각각
`STANDARD@v2 + WEB@v1` 또는 `STANDARD@v2 + PWN@v1`으로 내부 합성한다. caller는
baseline 버전, RuntimeClass 또는 Kubernetes 보안 설정을 직접 선택할 수 없다.

### 기술 명세의 프로필 이름과 API 입력값

`STANDARD@v2`은 WEB만의 별칭이 아니라 WEB/PWN 모두에 적용되는 공통 baseline이다.
API 입력은 `WEB` 또는 `PWN`이며 `standard-web`, `pwn-sandbox`, `strong-isolation`을
자동 변환하는 alias는 없다. 해당 문자열을 `isolation_profile`에 보내면
`400 INVALID_REQUEST`다. 생성 경로는 단수 `instance`가 아닌
`POST /internal/v1/instances`다.

별도 기술 문서의 `standard-web`이 일반 웹용을 의미한다면 WEB과 용도상 대응할 수
있지만, 세부 보안 조건까지 동일하다는 뜻은 아니다. 설계 문서의 용어를 API enum으로
그대로 사용하지 않는다. 현행 코드에는 `strong-isolation`이라는 세 번째 실행
프로필이 없으며, 더 강한 격리가 필수인 문제를 WEB/PWN으로 임의 하향 변환해
지원된 것으로 간주하면 안 된다. 그런 문제는 별도 정책·대상 capability 계약이 필요하다.

Scheduler는 세부 Kubernetes 보안 설정을 구성하지 않는다. 다만 PWN을 실행할 때
gvisor와 NODE_PORT를 지원하는 적합한 target이 공급되는지는 Broker/DevOps와
맞춰야 한다. Provisioner는 Registry capability 불일치를
`TARGET_CAPABILITY_MISMATCH`로 거절하며, 이 최종 검사가 후보 공급 단계의
적합성 보장을 대신한다는 뜻은 아니다.

### 인스턴스 내부 통신과 정책 전환

`writable_paths`는 선택 사항이다. `workload.internal_connections`는 삭제된 필드이며
`null`, 빈 배열, 연결 목록 모두 `400 INVALID_REQUEST`로 거절한다. 같은 인스턴스의
동일 소유권 Pod끼리는 양방향 내부 통신을 기본 허용한다. 내부 포트/프로토콜 연결
목록은 필요하지 않으며, 외부 공개는 컨테이너의 `ports`/`exposed_ports`로 제한한다.

Namespace ingress/egress 기본 차단에 소유권 label이 일치하는 동일 Namespace의
Pod만 허용한다. 다른 팀·같은 팀 다른 인스턴스·다른 문제 인스턴스에는 적용되지
않는다. public internet egress는 고정 `NONE`이며 DNS와 동일 인스턴스 내부 통신만
허용한다. raw NetworkPolicy나 외부 egress DSL 입력은 현재 제공하지 않는다.
노드/metadata 경계의 실제 강제는 #32의 별도 범위다.

신규 승인 정책은 `STANDARD@v2`다. 기존 DB에 저장된 `STANDARD@v1` Operation은
승인된 연결 목록으로 재시도하며, 실행 중인 인스턴스의 정책을 자동 확대하지 않는다.
legacy 연결 필드는 기존 snapshot 복원에만 남기고 신규 Operation/Binding에는
저장하지 않는다. 과거 설계 문서의 연결 목록 설명은 v1 이력이다.

**전환:** Runtime과 CI/Registry/Scheduler caller의 배포를 조율한다. 신규 Runtime은
구 caller가 보내는 삭제 필드를 명확히 거절한다. 기존 Operation은 `operation_id`로
끝까지 조회하고 기존 인스턴스는 그대로 삭제할 수 있다. 새 정책으로 생성할 때는
새 `request_id`와 `instance_id`를 사용한다. 구 요청을 새 정책으로 다시 접수하면
멱등 충돌이 발생할 수 있으므로 같은 ID를 재사용하지 않는다.

`resource_limits`는 문제 런타임 전체의 CPU·memory·ephemeral-storage 합산값이다.
Scheduler가 문제별 수치를 결정하고 Provisioner는 양수 및 표현 가능 범위를 검증한 뒤
Pod requests/limits, ResourceQuota, LimitRange에 그대로 강제한다. named resource
profile과 비교하지 않는다. root UID, 잘못된 경로·크기·중첩 writable path는 거부한다.

Web은 Target의 기본 runtime을 사용하고 `INGRESS_PATH`와 `NODE_PORT` Target을 모두
지원하며 endpoint protocol은 `HTTP`다. 일반 Pwn 문제는 다음 계약을 사용한다.

```json
{
  "request_id": "runtime-create-pwn-018f3f1e",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd009",
  "team_id": "00000000-0000-4000-8000-000000000018",
  "isolation_profile": "PWN",
  "target": {"runtime_type": "KUBERNETES", "target_id": "aws-k3s-pwn-001"},
  "workload": {
    "containers": [{
      "name": "challenge",
      "image": "ghcr.io/msg-ctf/challenges/pwn-buffer-01@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "ports": [31337],
      "expose": true,
      "run_as_user": 10001,
      "writable_paths": [{"path": "/tmp", "size_mib": 64}]
    }],
    "resource_limits": {
      "cpu_millicores": 100,
      "memory_mib": 128,
      "ephemeral_storage_mib": 128
    }
  }
}
```

Pwn은 모든 Pod에서 `runtimeClassName: gvisor`를 강제하고, 외부 노출 컨테이너와
TCP 포트를 각각 하나만 허용하며, writable path는 `/tmp` 또는 그 하위 경로만
허용한다. endpoint protocol은 `TCP`이며, Pwn 요청은 gVisor가 검증된
`NODE_PORT` Target에만 배치할 수 있다.

기존 단일 컨테이너 요청의 `image`와 `container_port`도 계속 허용한다. 이 형식은
서버에서 이름 `challenge`, `expose: true`, UID `10001`인 컨테이너 1개로 변환한다.
이 호환 입력도 `isolation_profile`과 수치형 `resource_limits`를 반드시 보내야 하며,
`containers`와 한 요청에서 함께 사용할 수 없다. 새 Scheduler는 `containers[]`를
정식 계약으로 사용한다.

Kubernetes PodSpec에는 pre-pull 여부와 관계없이 정확한 image identifier가 필요하므로
`image`는 계속 전달한다. 모든 컨테이너는 `imagePullPolicy: IfNotPresent`를 사용한다.
tag-only 및 `latest`는 거부하며 모든 image는 lowercase 64자리 `@sha256:<digest>`로
고정해야 한다.
같은 digest가 노드에 있으면 캐시를 사용하고, 없으면 container runtime이 lazy pull한다.
Pod egress 차단은 node의 image pull을 막지 않는다. 비공개 GHCR Package라면 K3s
노드에 pull credential을 별도로 설정해야 한다.

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
적용된 `STANDARD@v2` baseline과 `WEB@v1` 또는 `PWN@v1` workload profile identity,
resolver가 승인한 컨테이너 UID/port/writable path, 내부 연결, 고정 outbound mode,
Scheduler가 전달한 자원 합산값과 Kubernetes Namespace UID를 방어적으로
복사해 기록한다. Namespace UID는 내부 소유권 확인에만 사용하며 API 응답에는 노출하지 않는다. raw 요청,
이미지 credential, baseline 보안 플래그 또는 Kubernetes 설정은 기록하지 않는다.
CREATE adapter의 성공 결과는 Binding 저장보다 먼저 Operation 내부 checkpoint에
기록한다. checkpoint에는 Namespace UID가 포함되지만 공개 Operation `result`로는
노출하지 않는다. Binding 저장 또는 UID-bound cleanup이 재시도되면 Worker는 이
checkpoint에서 후속 처리를 재개하며 CREATE adapter를 다시 호출하지 않는다. Binding
저장이 끝난 뒤에만 checkpoint를 최종 `result`로 승격하고 Operation을 `SUCCEEDED`로
표시한다.
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
Authorization: Bearer <service_token>
Content-Type: application/json
```

### 요청

```json
{
  "request_id": "runtime-delete-018f3f1e",
  "instance_id": "018f3f1e-21b8-7a91-a30b-63b3400fd001",
  "team_id": "00000000-0000-4000-8000-000000000018",
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
Authorization: Bearer <service_token>
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
    "service_url": "http://203.0.113.10:31042",
    "endpoints": [
      {
        "container_name": "web",
        "port": 8080,
        "protocol": "HTTP",
        "service_url": "http://203.0.113.10:31042"
      }
    ]
  }
}
```

`service_url`은 하위 호환을 위한 첫 번째 공개 접속점이며 첫 번째
`endpoints[]` 항목과 같다. 신규 연동에서는 `endpoints`를 사용한다.

#### 공개 포트가 여러 개인 경우

공개 포트마다 `endpoints[]` 항목을 하나씩 반환한다. 예를 들어 같은 WEB 컨테이너의
`ports: [8080, 9000, 9090]`, `exposed_ports: [8080, 9090]` 요청은 공개 URL 2개를
반환하고 private 포트 9000은 응답에서 제외한다. 다음은 NODE_PORT 모드의 생성 완료
`result` 예시이며, 외부 포트 31042·31043은 예시 할당값이다.

```json
{
  "runtime_workload_id": "aws-k3s-001/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
  "service_url": "http://203.0.113.10:31042",
  "endpoints": [
    {
      "container_name": "web",
      "port": 8080,
      "protocol": "HTTP",
      "service_url": "http://203.0.113.10:31042"
    },
    {
      "container_name": "web",
      "port": 9090,
      "protocol": "HTTP",
      "service_url": "http://203.0.113.10:31043"
    }
  ]
}
```

각 항목의 `container_name`, `port`, `protocol`, `service_url`은 모두 필수다.
`port`는 컨테이너 내부 포트이므로 접속 주소에 직접 붙이지 않는다. 접속에는 각
`service_url`을 사용한다. INGRESS_PATH에서는 외부 포트 대신 URL 경로가 구분된다.

로컬 AWS 검증에 사용하는 `NODE_PORT` 노출 모드는 Kubernetes가 각 공개 포트의
NodePort를 자동 할당하며 주소는 `http://<target 공인 IP>:<NodePort>` 형식이다.
내부 컨테이너(`expose: false`)는 ClusterIP로만 생성된다. 기존
`INGRESS_PATH` 노출 모드도 지원하며, 이때 주소는
`<public_gateway>/instances/{instance_id}` 형식이다. `exposure_mode`를 생략한
기존 Registry 설정은 `INGRESS_PATH`로 해석된다.

Pwn 성공 결과는 endpoint의 `protocol`이 `TCP`이고 주소가
`tcp://<target 공인 IP>:<NodePort>` 형식이다. Scheduler와 프론트엔드는 URL 문자열을
추측하지 않고 `protocol`을 기준으로 Web과 Pwn 접속 방식을 구분한다.

```json
{
  "container_name": "challenge",
  "port": 31337,
  "protocol": "TCP",
  "service_url": "tcp://203.0.113.10:31042"
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
Authorization: Bearer <service_token>
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

다중 컨테이너 런타임은 컨테이너마다 Deployment와 Service를 하나씩
만든다. 조회 결과의 `containers`에는 같은 팀·인스턴스 Namespace에 속한 모든
컨테이너가 반환된다. `endpoint_ready`는 현재 노출 모드에서 모든 공개 Service에
Ready EndpointSlice가 있을 때만 `true`다. `NODE_PORT`에서는 NodePort Service를,
`INGRESS_PATH`에서는 Ingress가 참조하는 Service를 확인한다.

## 생성·삭제의 K3s 단위

- 팀의 문제 런타임 인스턴스 1개마다 전용 Namespace 1개를 만든다.
- 해당 Namespace 안에 전용 `challenge-runtime` ServiceAccount, ResourceQuota,
  LimitRange, NetworkPolicy와 컨테이너별 Deployment·Service를 둔다.
- `NODE_PORT`에서는 공개 컨테이너의 Service만 NodePort로 만들고 Ingress는 만들지
  않는다. `INGRESS_PATH`에서는 Service는 ClusterIP이며 공개용 Ingress 1개를 둔다.
  혼합 컨테이너는 위의 내부/공개 Service 분리를 적용한다. Service quota는 실제
  생성 개수에 맞추며 CREATE 완료 전에는 두 Service 모두의 EndpointSlice를 확인한다.
- `STANDARD@v2`은 모든 문제에 적용한다. `WEB@v1`은 Target 기본 runtime을 사용하고,
  `PWN@v1`은 운영자가 검증한 `gvisor` RuntimeClass와 `NODE_PORT`를 요구한다.
- ServiceAccount와 Pod 양쪽에서 token 자동 마운트를 끄고, Pod·컨테이너에는 non-root
  UID, read-only root filesystem, privilege escalation·privileged 금지, 모든 Linux
  capability drop, `RuntimeDefault` seccomp와 host namespace 비활성화를 적용한다.
  승인된 writable path만 크기가 제한된 `emptyDir`로 마운트한다.
- ResourceQuota와 LimitRange는 Scheduler가 전달하고 Provisioner가 검증한 CPU·memory·ephemeral-storage
  합계와 namespaced object 수를 제한한다. `NODE_PORT`에서는 공개 컨테이너의 승인된
  포트 수만큼 `services.nodeports` quota를 허용하고 그 이상은 차단한다.
- `default-deny-all`을 먼저 두고 DNS egress, 공개 컨테이너로 향하는 ingress,
  명시적으로 승인된 컨테이너 간 TCP 연결만 NetworkPolicy allowlist로 연다. 현재
  `INGRESS_PATH`의 공개 ingress source는 설정된 ingress controller로 제한한다.
  `NODE_PORT`는 외부 source를 허용하되 승인된 공개 포트 목록만 연다. 현재
  outbound는 내부적으로 항상 `NONE`이므로 그 밖의 외부 egress는 열지 않는다.
- Namespace와 모든 기존 리소스의 소유권을 먼저 검사한 뒤 ServiceAccount →
  ResourceQuota → LimitRange → NetworkPolicy 순으로 적용·read-back 검증한다. 이 보호
  리소스가 모두 확인된 뒤에만 Deployment → Service를 적용하고, `INGRESS_PATH`에서만
  Ingress를 적용한다.
- 생성은 모든 Deployment, Pod, Service Endpoint가 준비돼야 성공한다.
- 생성 중 일부 리소스가 실패하면 해당 Namespace 전체를 롤백한다.
- 삭제는 저장된 `target_id`, Namespace, 팀·인스턴스 소유권을 확인한 뒤
  Namespace 전체를 삭제한다.
- 삭제가 반복됐는데 Namespace가 이미 없으면 성공으로 처리한다.

이 baseline은 Provisioner가 생성한 리소스에 적용하는 방어 계층이다. Pwn Pod에는
gVisor RuntimeClass를 선택하지만 별도 Admission 강제는 없으므로 Provisioner 밖에서
만든 Pod까지 cluster-wide로 강제하지 않으며, 고위험 workload의 커널 격리를
증명하지 않는다.
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
| 409 | `RUNTIME_IDENTITY_MISMATCH` | Kubernetes Namespace UID 불일치 |
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
| `GET /internal/v1/instances/{instance_id}/runtime-status` | 409 | `RUNTIME_IDENTITY_MISMATCH` | Namespace UID가 Binding과 다름 | 상태 조회 실패; Scheduler에 작업을 만들거나 변경하지 않음 |
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
| `CREATE` | `RESOURCE_OWNERSHIP_CONFLICT` | 생성 전에 같은 이름의 Namespace가 이미 있거나 다른 리소스의 소유권이 다름 | 즉시 `FAILED` |
| `CREATE` | `RUNTIME_IDENTITY_MISMATCH` | 생성 성공 확인 전에 Namespace UID가 바뀜 | 즉시 `FAILED` |
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
| `DELETE` | `RUNTIME_IDENTITY_MISMATCH` | Namespace UID가 Binding과 다름 | 즉시 `FAILED` |
| `DELETE` | `RUNTIME_OWNERSHIP_MISMATCH` | Namespace 소유권이 Binding과 다름 | 즉시 `FAILED` |
| `DELETE` | `TARGET_TEMPORARILY_UNAVAILABLE` | Kubernetes API 호출이 실패함 | Forbidden/Unauthorized/BadRequest/Invalid는 즉시 `FAILED`, 그 밖의 일시 오류는 재시도 후 한도 도달 시 `FAILED` |
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
재시작하면 진행 중 create checkpoint, 작업과 Binding이 복구되지 않는다. checkpoint는
동일 프로세스 안의 Worker 재시도와 cancellation/requeue에서만 CREATE 재호출을 막는다.
운영 영속 저장소가 구현되기 전까지 API는 재시작 내구성을 보장하지 않는다.

MVP profile ref는 `name`과 `version`만 사용한다. immutable digest 또는 Catalog
assignment authority가 아직 아니므로 이 ref만으로 production-grade policy
attestation을 주장하지 않는다. Target Registry의 `security_capabilities`도
NetworkPolicy provider, DNS/Ingress selector, Strict supplemental-groups, Pod PID 제한과 설치된
`runtime_classes` 지원을
운영자가 선언한 값이며 런타임 검증 증명이 아니다. Provisioner는 Pod에
`supplementalGroupsPolicy: Strict`를 지정하고 `supplementalGroups`와 `fsGroup`은
지정하지 않는다. 실제 Node의 `status.features.supplementalGroupsPolicy`와 CRI 지원
attestation은 Task 12 / issue `#11`에서 완료해야 한다. 기존 활성화 Registry는 새
Provisioner rollout 전에 `supplemental_groups_policy_strict`와 `pod_pid_limit_enforced`를
추가해야 하며, 지원을
확인하지 않은 target을 capable로 선언하거나 승인하면 안 된다. 이 기능이 alpha였던
Kubernetes v1.31-v1.32에서는 지원하지 않는 Node가 Strict 요청을 거절하지 않고
`Merge`로 조용히 fallback할 수 있다. Kubernetes v1.33 이상은 지원하지 않는 Node의
Strict Pod를 거절하므로 workload는 fail-closed로 실패한다. 이 동작만으로 특정 K3s 버전의
지원을 보장하지 않는다. 실제 NetworkPolicy 격리 효과는 `#11`, resident-node 및
metadata host boundary attestation은 `#32`에서 완료해야 production 경계를 충족한다.

Kubernetes는 PodSpec에 개별 PID limit를 두지 않는다. Broker/K3s bootstrap은 모든
노드의 kubelet에 `pod-max-pids=<positive-value>` 또는 `PodPidsLimit`를 설정하고
fork probe를 통과한 후에만 `pod_pid_limit_enforced: true`를 선언한다. 누락하면
Registry 설정이 거절되고, 명시적 `false`면 Kubernetes 작업 전에
`TARGET_CAPABILITY_MISMATCH`로 생성이 거절된다.

Pwn Target은 Registry에 다음 조건을 선언해야 한다. Provisioner는 gVisor를 설치하지
않으며, Broker/K3s bootstrap이 `RuntimeClass/gvisor`를 설치하고 검증한 뒤에만 이 값을
기록한다.

```json
{
  "public_gateway": "http://203.0.113.10",
  "exposure_mode": "NODE_PORT",
  "security_capabilities": {
    "pod_pid_limit_enforced": true,
    "runtime_classes": ["gvisor"]
  }
}
```
