# Runtime → Gateway v1 연동 검토

상태: **사용자 범위 확정(A안), 구현은 별도 feature 브랜치에서 진행. 이 PR은 문서만 포함.**

추적: [Runtime issue #73](https://github.com/MSG-CTF/secure-provisioner/issues/73).

검토 기준은 2026-10-24 사용자가 전달한 `Runtime → Gateway API 계약 v1.0.0`과
secure-provisioner `origin/dev`의 `a4c1f47d5a96f44222c87cc3fd458943771a61b7`이다.
이 문서는 사용자에게서 전달받은 계약의 적용 가능성을 검토한다. 실제 Gateway의
배포 버전·가용성·DNS·인증서·인증 토큰을 검증했다는 의미는 아니다.
전달 원문의 SHA-256은
`8a28e7c593850833b5ee9a5a72a51a8cb07794defe95d58f110c0559075008e1`이다.

## 결론과 아직 필요한 선택

현재 Runtime에는 해당 Gateway API client가 없다. `public_gateway` 값을
`https://gate.msgctf.kr`로 바꾸는 설정만으로 연동할 수 없다.

권장하는 첫 범위는 **다중 컨테이너를 유지하되 공개 endpoint가 정확히 하나인
NodePort target**이다. 내부 보조 컨테이너와 그 준비 검증은 유지한다. 공개
endpoint가 여러 개인 요청을 몰래 첫 포트로 줄이거나, 일부 주소만 반환하면 안 된다.
사용자가 이 범위를 확정했다: "v1 그대로: 보조 컨테이너는 유지하고 공개 endpoint
1개·NodePort부터 지원". 첫 구현은 K3s NodePort target의 명시적 opt-in으로 제한하고
기본값은 off다. Compose VM은 첫 구현에서 제외한다.

| 접근 | 장점 | 제약·필요한 합의 |
| --- | --- | --- |
| A. Gateway v1 그대로, 공개 endpoint 하나부터 | 제공된 계약으로 연동 가능. 새 Gateway API 설계가 불필요 | Gateway 사용 target에서 공개 포트 합계가 1이어야 함. 다른 모드는 기존 동작 유지 |
| B. 다중 공개 endpoint 계약을 먼저 확장 | 현재 Runtime의 포트별 `endpoints[]` 기능 유지 | Gateway가 `instance_id + endpoint_key` 또는 별도 `route_id`를 받아야 함. 부분 등록 실패·일괄 삭제·tombstone 범위도 새로 합의 |

기존 `instance_id` 대신 임의로 `instance_id:container:port`를 넣는 것은 v1의
"팀의 문제 배포마다 고유한 ID" 의미를 바꾼다. 문법상 허용된다는 이유로 적용하지
않는다. B를 택하면 Gateway 소유자와 ID·삭제 단위를 먼저 합의해야 한다.

전용 Compose VM은 별도 범위다. 현재 VM catalog는 정적 `public_url`만 가지며
실제 upstream 공인 IP·host published port를 구조화하여 보장하지 않는다. 이를
명시하는 target 계약과 VM 포트 보존/정지 작업이 추가되기 전에는 K3s와 같다고
가정하지 않는다.

## 현재 코드와 계약의 차이

| 항목 | 현재 dev | 신규 작업 |
| --- | --- | --- |
| 외부 주소 | Ingress path 또는 공인 host + Kubernetes 할당 NodePort를 조립 | Gateway `PUT` 응답의 난수 hostname/HTTPS URL을 저장·반환 |
| 공개 포트 | 컨테이너별 공개 포트마다 endpoint 하나 | v1 사용 범위는 합계 1개 검증. 보조 컨테이너는 private 가능 |
| 목적지 | `public_gateway`는 URL/hostname도 허용 | Gateway가 수락하는 실제 공인 IP literal + 실제 allocated NodePort를 명시 |
| 인증 | Runtime 수신 API용 Service token | Gateway 송신용 고정 Runtime token 별도 주입. Broker `RUNTIME_API_TOKEN`과 같은 값 |
| 생성 복구 | adapter 반환 이후 전체 결과 checkpoint 한 번 | 원격 PUT 전 intent, 원격 결과 및 route 단계별 durable 기록 |
| 삭제 | Namespace UID/소유권 검증 후 Namespace 전체 삭제 | route 삭제 확인까지 NodePort 할당 보존. workload 정지와 포트 해제를 분리 |
| 실패 생성 cleanup | Namespace/VM generation의 제거 증명 | route/tombstone 확인도 cleanup proof에 포함 |
| 상태 | 컨테이너·Service EndpointSlice 중심 | workload 준비와 Gateway 반영 상태를 구분. Gateway 2xx를 외부 서비스 health로 해석하지 않음 |
| 참가자 TCP | `tcp://<host>:<NodePort>`, `protocol=TCP` | TLS/SNI hostname/443 전달 계약 추가. 기존 TCP 클라이언트와 호환되지 않을 수 있음 |

코드 근거:

- [`internal/k3s/resources.go`](../../internal/k3s/resources.go): 공개 포트별 Service와
  `BuildNodePortEndpoints`의 주소 조립. 반환 endpoint의 `port`는 컨테이너 내부
  포트이며 Gateway의 목적지 `target_port`는 실제 Service의 `nodePort`여야 한다.
- [`internal/k3s/registry.go`](../../internal/k3s/registry.go): `INGRESS_PATH`와
  `NODE_PORT`만 지원하며 `public_gateway`를 URL로 검증한다.
- [`internal/k3s/adapter.go`](../../internal/k3s/adapter.go): 모든 workload 준비 후
  결과 반환. checkpoint 전 재시작의 이전 Namespace는 rollback 대상으로 처리한다.
- [`internal/operations/worker.go`](../../internal/operations/worker.go): adapter
  반환 뒤 create checkpoint, Binding finalize, 성공 기록 순서. 실행 동안 slot 점유.
- [`internal/runtimeops/service.go`](../../internal/runtimeops/service.go): Binding
  저장 실패 시 cleanup; 기본 cleanup timeout 30초; delete adapter 성공 뒤 `DELETED`.
- [`internal/k3s/delete_adapter.go`](../../internal/k3s/delete_adapter.go): Namespace
  foreground 삭제와 실제 부재 확인. Service/NodePort도 함께 회수된다.
- [`internal/provisioner/cleanup.go`](../../internal/provisioner/cleanup.go): cleanup
  완료는 실제 자원 부재 증명이며, 생성 실패·Binding 부재·삭제 접수만으로 대체 불가.
- [`internal/vm/adapter.go`](../../internal/vm/adapter.go): 정적 `public_url` 반환,
  guest create/status/delete 호출. Gateway API 호출 및 독립적인 port hold 작업 없음.
- [`internal/httpapi/runtime.go`](../../internal/httpapi/runtime.go): 공개 endpoint는
  현재 `container_name`, 내부 `port`, `protocol`, `service_url`만 반환한다.

## 고정해야 할 Gateway v1 의미

- Base URL은 `https://gate.msgctf.kr`. 실제 Runtime 호출은 TLS 인증서를 검증한다.
- 송신 Bearer token은 Broker와 같은 고정 `RUNTIME_API_TOKEN` 값이다. Broker 로그인
  JWT, K3s 인증서, Runtime 수신 Service token과 자동으로 동일시하지 않는다.
- `PUT /v1/routes/{instance_id}` 본문은 `target_ip`, 정수 `target_port`, 소문자
  `http|tcp`만 포함한다. 지원하지 않는 필드를 추가하지 않는다.
- 동일 ID·정규화된 IP·포트·protocol PUT은 최초 `201`, 재시도 `200` 및 같은 주소를
  반환한다. 응답 유실을 새로운 ID나 목적지 변경으로 해결하지 않는다.
- GET 응답에는 목적지 IP/포트가 없다. **GET 200만으로 저장된 목적지 일치를 증명할
  수 없다.** 저장된 동일 본문 PUT의 200/201로 일치를 확인한다.
- DELETE는 처음 없던 ID도 tombstone을 만들고 204를 반환한다. 따라서 **GET 404는
  늦은 PUT을 막는 tombstone의 증명이 아니다.** DELETE 204를 확인해야 한다.
- 삭제한 ID는 새 배포에 재사용하지 않는다. 실패 rollback에서 tombstone이 생기면
  같은 ID로 새 workload를 만들 수 없다. 새 배포 ID는 Scheduler가 정해야 한다.
- 201/200은 Nginx 설정 검사·reload 명령 성공이다. workload 응답, DNS, 방화벽,
  인증서, 기존 TCP 연결 종료까지 증명하지 않는다.
- 공개 IP와 목적지는 Runtime 운영자가 관리하는 target 정보로 고정한다. 생성 API
  caller가 임의 IP/port를 지정하도록 새 기능을 열지 않는다.

## 요청·응답 연결 예시

아래 PUT은 **치환이 필요한 문서 템플릿**이며 실제 Gateway에 실행하지 않았다.
문서 예시 IP(`203.0.113.0/24` 등)는 계약상 등록이 거절된다.

```http
PUT /v1/routes/00000000-0000-4000-8000-000000000001
Authorization: Bearer <secret reference에서 읽은 Runtime token>
Content-Type: application/json

{"target_ip":"<실제 worker 공인 IP>","target_port":31042,"protocol":"http"}
```

Gateway가 `hostname=example-random.gate.msgctf.kr`, `port=443`, `tls=true`,
`protocol=http`, `url=https://example-random.gate.msgctf.kr`를 반환하면 Runtime의
해당 endpoint `service_url`과 첫 endpoint 별칭인 상위 `service_url`에 그 URL을
그대로 사용한다. 공개 endpoint의 내부 `port=8080`은 계속 8080으로 유지한다.
참가자 주소에 내부 포트 8080 또는 upstream NodePort 31042를 붙이지 않는다.

TCP의 경우 Gateway `url=null`이므로 HTTP URL 생성 규칙을 재사용하지 않는다.
기존 `protocol=TCP`는 문제 서비스 protocol로 유지하되 transport가 TLS임을 표현할
`hostname`, `connection_port=443`, `tls=true`, `server_name` 등의 선택 필드 또는
동등한 버전 계약을 Scheduler/Backend/Frontend와 먼저 합의한다. `tcp://host:443`
문자열만 바꾸면 기존 평문 TCP 클라이언트가 오동작할 수 있다. 구체적인 필드명은
이 문서의 제안이며 아직 확정된 API 계약이 아니다.

Scheduler `dev`의 `d9bb3c3fe7f4a52fd3c6e8db0d1d2bebdaf66d41`을 함께 검토한
결과, `RuntimeDtos.kt`의 endpoint DTO와 `InstanceOperationService.kt`의
`applyEndpoints`는 현재 위 네 필드만 전달한다. Runtime에 TLS/SNI 필드를 추가해도
현재 Scheduler는 이를 저장·전달하지 않는다. TCP 지원은 Runtime 단독 변경으로
완료할 수 없으며 Scheduler 및 이후 응답 경로를 같이 변경해야 한다.

## durable 생성·삭제 상태와 재시작 복구

Operation의 기존 외부 상태(`QUEUED/RUNNING/RETRYING/SUCCEEDED/FAILED`)는 유지하고,
아래 내부 phase와 원격 intent를 PostgreSQL에 추가하는 방향을 제안한다. memory
mode는 재시작 후 포트 보존을 보장할 수 없으므로 Gateway production mode에서
허용하지 않는다. 스키마/API 필드명은 구현 설계에서 최종 확정한다.

Route record에는 적어도 원래 instance ID, operation ID, namespace/Service UID 또는
VM generation, target ID, 정규화된 공인 IP, 실제 allocated host port, protocol,
phase, 반환 hostname/URL/443/TLS/created_at, 마지막 오류 분류, next retry 시간,
fencing version을 저장한다. 비밀 token은 저장하지 않는다. 기존 Binding과
operation checkpoint의 하위 호환 decode와 원본 입력 idempotency를 유지한다.

### 생성

1. 기존 정책·인증·platform·격리 검증 후 workload를 생성하고 **전체 컨테이너와
   공개 Service** 준비를 확인한다. 공개 endpoint가 1개인지 admission과 replay에서
   모두 검증한다. 이 제한은 Gateway가 켜진 target에만 적용한다.
2. 실제 Service readback의 NodePort와 generation을 읽어 `UPSTREAM_READY`를
   checkpoint한다. 포트 claim은 route 정리 완료까지 유지한다.
3. **원격 호출 전** `ROUTE_APPLY_PENDING`과 변경 불가 PUT 본문을 저장한다. DB에
   intent를 저장하지 못하면 PUT을 보내지 않는다.
4. 동일 ID·본문 PUT을 수행한다. 200/201 응답의 ID·protocol·hostname·TLS·443·HTTP
   URL 관계를 검증하고 `ROUTE_APPLIED`를 저장한다. 재개 시 GET 존재 확인만으로
   목적지 일치로 간주하지 않는다.
5. Gateway metadata를 포함한 최종 checkpoint/Binding을 finalize한 뒤에만 CREATE를
   `SUCCEEDED`로 만든다. Scheduler에는 Gateway 공개 주소를 반환한다.

이 제안에서 `SUCCEEDED`는 전체 workload 준비와 Gateway control plane 반영 확인을
뜻한다. 실제 DNS·공인 인증서·외부 end-to-end 응답까지 확인한 상태는 아니다.
외부 접속까지 `READY`의 필수 조건으로 삼으려면 별도 probe의 관측·실패·timeout
계약을 추가해야 한다. 현재 workload의 `endpoint_ready`와 Gateway 반영 상태를
구분하여 이 차이가 사용자 상태에서 사라지지 않게 한다.

원격 PUT 성공 후 응답 유실/프로세스 중단/DB 저장 실패가 있으면 같은 phase에서
같은 PUT을 재시도한다. 현재 adapter의 "checkpoint 없는 이전 Namespace rollback"
경로가 이를 우회하지 않도록 복구 분기를 먼저 바꿔야 한다. `GET=404`가 나와도
기존 할당 포트를 바꾸거나 새 ID를 발급하지 않는다.

실패 rollback이 필요하면 삭제 intent를 저장하고 아래 삭제 절차를 따른다. route가
존재하지 않았을 가능성이 있어도 DELETE 204로 늦은 PUT을 fence한다. 이 뒤에는
같은 ID의 CREATE를 재개하지 않으며 최종 실패/cleanup 완료 또는 cleanup 대기로
끝낸다. 기존 `CreateCleanup`의 Namespace proof만으로 완료 처리하지 않는다.

### 삭제와 포트 보존

1. `DELETE_REQUESTED`를 durable하게 기록하고 새 create/route apply를 막는다.
   Binding은 `DELETING`을 유지한다. immutable upstream tuple을 intent에서 읽는다.
2. workload를 정지하되 **NodePort Service와 포트 할당은 유지**한다. K3s에는
   Deployment 정지/Pod 종료 확인 단계가, VM에는 published port 소유권을 놓지 않는
   guest stop/hold 동작이 필요하다. 기존 Namespace 전체 삭제를 이 단계에 쓰지 않는다.
   정지 실패 시 정지 완료로 보고하지 않는다.
3. 동일 instance ID로 DELETE를 호출하고 `204`만 route 삭제 확인으로 기록한다.
   timeout·연결 실패·비JSON 응답·GET404·삭제 접수·재시도 소진은 그 증명이 아니다.
4. `ROUTE_DELETED`가 durable하게 저장된 뒤 Namespace/VM 자원을 삭제하고 기존 UID·
   소유권·실제 부재 확인을 수행한다. 그 뒤에만 포트 claim, Binding, Scheduler
   자원 예약을 해제할 수 있다.
5. route 삭제 실패/불명 시 Service와 포트 claim을 보존하고 `ROUTE_DELETE_PENDING`
   및 오류를 남겨 운영자가 원인을 고친 뒤 동일 삭제를 재개한다. 재시도 상한에
   도달해도 포트를 해제하거나 cleanup 완료를 반환하지 않는다.

위 Scheduler 예약 보존은 **필요한 신규 통합 계약**이다. 현재 Scheduler
`d9bb3c3`의 `InstanceOperationService.applyFailed`는 DELETE 실패 시 `parkFailed`
후 `takeReservation`을 호출한다. `giveUpPolling`도 `STOPPING/CLEANUP_PENDING`이고
runtime workload ID가 있으면 같은 경로로 예약을 반납한다. 따라서 Runtime에서
`FAILED`나 cleanup 미확인을 전달하는 것만으로 현재 Scheduler 예약이 보존되지는
않는다. Scheduler가 route/workload 정리 완료 증명을 받기 전에는 cleanup 작업과
예약을 유지·재개하도록 변경해야 한다. 현재 Runtime의 `cleanup_completed`도
실패 CREATE를 위한 값이므로 DELETE의 같은 보장에 사용할지 새로 합의해야 한다.

두 자원을 구분한다. NodePort 재할당 방지는 Kubernetes Service/실제 port hold가
담당하고, Scheduler의 CPU/메모리 capacity 예약은 별도 admission 정보다. Scheduler
예약만 보존해도 NodePort가 안전해지는 것은 아니며, Service만 보존해도 현재
Scheduler의 조기 자원 반납 동작이 바뀌지는 않는다. 특히 workload 정지 미확인
상태에서 자원 예약을 반납하면 다른 작업에 가용량을 잘못 알릴 수 있다. 1차 구현
수용조건에는 이 cross-service cleanup proof와 예약 반납 변경도 포함한다.

DELETE는 기존 TCP 연결을 강제로 끊지 않으므로 workload 정지가 별도로 필요하다.
구체적 stop/hold 방식이 준비되지 않은 경우 최소한 route DELETE 확인 전에
Namespace를 삭제하지 않아야 하지만, 이것만으로 즉시 workload 종료를 보장한다고
보고해서는 안 된다.

PostgreSQL의 IP+port unique claim만으로 Kubernetes 자동 allocator를 막을 수 없다.
**실제 NodePort Service 보존**이 필요하다. 외부 관리자/다른 controller가 Service나
Namespace를 삭제하거나 target의 K3s 상태를 초기화하면 이 보장도 깨진다. 소유
리소스 삭제 권한을 제한하고, generation/Service 유실 시 해당 target의 신규
할당을 중지하여 기존 route tombstone을 확인한 뒤 다시 열어야 한다. 복구 불명
상태에서 target을 신규 배치에 재개방하지 않는다.

### Lease/fencing의 한계

현재 3분 lease/1분 renewal은 75초 호출과 공존할 수 있다. lease는 실행 timeout이
아니다. 호출이 길다는 이유만으로 worker 수나 lease를 무조건 늘리지 않는다.

현재 DB fencing version은 stale worker의 DB 갱신을 막지만 이미 전송된 원격 HTTP
요청까지 취소하지 못한다. lease 상실 시 ctx 취소, mutation 직전 intent/fence
재확인, 단계별 CAS가 필요하다. 동일 PUT 재시도와 DELETE tombstone이 늦은 PUT
경합을 안전하게 닫는다. 한번 삭제 intent가 기록된 ID를 새 create phase로 되돌리지
않는다. 여러 replica에서 동시 실행되는 순서까지 복구 테스트에 포함한다.

## 오류별 처리

| 결과 | Runtime 처리 | 포트/정리 |
| --- | --- | --- |
| PUT 200/201 + 유효 본문 | 동일 목적지 등록 확인, 결과 persist 후 finalize | 계속 유지 |
| PUT 응답유실·timeout·TLS/연결 실패·비JSON proxy 오류 | 원본 intent 유지, bounded backoff 후 같은 PUT. 필요시 GET 보조 확인 | 해제 금지 |
| PUT 400/422 | 입력/구현 결함. 같은 잘못된 본문 무한재시도 금지. 원격 적용 가능성을 기록하고 삭제 절차로 정리 | cleanup 확인 전 해제 금지 |
| 401, 설정/권한 관련 503 | 설치·토큰 문제로 분류, 운영자 조치 상태 표시 | 자동 자원 반납 금지 |
| PUT 409 INSTANCE_CONFLICT/TARGET_IN_USE | collision으로 중단. 다른 ID·포트 자동 발급 금지. durable tuple/소유권 점검 | 원래 claim 유지. 타 instance route 삭제 금지 |
| PUT 409 INSTANCE_DELETED | 폐기 ID. 같은 ID로 create 재개 금지 | workload cleanup. 새 배포는 새 ID |
| 500, 502 NGINX_APPLY_FAILED | 상태 불명/적용 실패 분류. 동일 요청으로 재확인·재시도 | 확인 전 해제 금지 |
| 503 GATEWAY_BUSY | jitter와 next retry 시간으로 지연, 즉시 반복 금지 | 계속 유지 |
| 503 REGISTRY_INVALID/NGINX_RECOVERY_REQUIRED | 운영 복구 필요, mutation을 지연/중지 | 포트 재사용 금지 |
| GET 200/404 | 존재·주소의 보조 관측. 목적지 일치/삭제 tombstone의 대체 증명 아님 | 변경 없음 |
| DELETE 204 | route 삭제/tombstone 확인 persist | 이후 workload 부재 확인 후 해제 가능 |
| DELETE의 나머지 모든 결과 | 삭제 미확인으로 유지, 동일 ID로 재시도/운영 복구 | 해제 금지 |

Gateway error JSON만 가정하지 않는다. HTTP status, 응답 크기 제한, 잘린 JSON,
HTML proxy 오류, 413, TLS 인증서 오류, ctx 취소를 별도 처리한다. 원문 오류 응답을
그대로 사용자에게 노출하거나 Authorization header/token을 로그에 기록하지 않는다.
일반 transport 오류라도 TLS 검증을 끄거나 HTTP로 downgrade하지 않는다.

재시도 budget 소진은 "자동 재시도 중단/운영 조치 필요"의 의미다. remote 부재나
cleanup 완료의 증명이 아니다. 같은 ID에 대한 원래 tuple과 삭제 intent를 보존해야
작업 재개가 가능하다.

## 설정 제안과 동시성

아래 이름은 **신규 구현 제안**이다. 현재 바이너리에서 지원하는 환경변수가 아니다.

| 제안 설정 | 의미 |
| --- | --- |
| `PROVISIONER_GATEWAY_MODE` | 기본 off, 선택적으로 single-endpoint. target별 적용/이행 범위를 명시 |
| `PROVISIONER_GATEWAY_BASE_URL` | `https://gate.msgctf.kr`, HTTPS·고정 신뢰 endpoint 검증 |
| `PROVISIONER_GATEWAY_RUNTIME_TOKEN_FILE` | Broker의 RUNTIME_API_TOKEN과 같은 값을 별도 Secret 파일로 주입. token 원문 전달 불필요 |
| `PROVISIONER_GATEWAY_REQUEST_TIMEOUT` | 제안 90초, 계약 권장 최소 75초 이상. 실제 Gateway nginx/proxy/server timeout과 함께 확인 |
| `PROVISIONER_GATEWAY_MAX_INFLIGHT` | 전체 workload worker 수와 분리한 Gateway mutation 동시 호출 제한. 값은 Gateway 부하 측정 후 결정 |
| target의 명시적 upstream 공인 IP | 기존 public_gateway hostname을 임의 DNS resolve하여 대체하지 않음 |

token rotation은 Gateway의 고정 token 수신 계약과 운영 교체 절차를 따로 정한다.
현재 Runtime 수신 Service token의 previous-token 기능이 Gateway에도 있다고 가정하지
않는다. 토큰 값 없이 설정 key/Secret 위치/교체 절차만 공유하면 된다.

기존 K3s Ready 대기는 worker slot을 계속 점유한다. Gateway 호출을 그대로 뒤에
붙이면 호출마다 최대 요청 timeout만큼 점유가 더 길어진다. 기본 worker 10개 또는
30개로 늘리는 것만으로 150건 Gateway 용량을 주장할 수 없다. 이전 worker 부하
시험의 controlled adapter에는 Gateway/Nginx 처리 시간이 포함되지 않았다.

장기적으로는 `next_retry_at`/next poll 시간을 DB에 저장하고 worker가 짧은 단계만
처리하는 방식이 맞다. 한번의 HTTP call 자체는 완료/timeout까지 in-flight다.
단계 사이 및 `GATEWAY_BUSY` backoff 동안 slot을 반환하고, 별도의 전역/replica별
Gateway admission budget을 둔다. 한 replica의 semaphore를 전체 replica 전역 제한으로
오해하지 않는다. 실제 계약/성능에 맞게 전체 한도를 조율한다.

Runtime 수신 생성 API는 기존처럼 비동기 Operation을 접수하므로 HTTP 서버의
10초 WriteTimeout을 Gateway 90초 때문에 함께 늘릴 필요는 없다. 반면 기존
rollback 30초/worker shutdown 40초는 장시간 Gateway cleanup을 끝낼 수 없을 수 있다.
각 phase를 durable하게 중단·재개할 수 있도록 바꾸고 cleanup 전용 timeout/budget을
분리한다. 단순히 전체 timeout만 늘려 불명 상태를 숨기지 않는다.

현재 Scheduler의 real profile은 병렬 처리 8, 최소 poll 5초, Runtime 접수 read
timeout 5초/연결 2초, Operation polling 전체 예산 10분이다. Gateway 호출을
접수 HTTP handler나 `enqueueMu` 안에서 수행하지 않는다. 75초 이상의 송신
timeout은 비동기 phase 내부에 적용하며, Scheduler의 짧은 접수 timeout은 유지한다.
Gateway 대기·재시도·K3s 준비 시간의 합은 Scheduler의 전체 10분 예산에는 포함되므로
예산 만료 시에도 원래 ID의 정리·예약 보존 계약을 유지해야 한다. 위 Scheduler 값은
이 문서에서 검토한 commit 기준이며 새 성능 권장값이 아니다.

## 구현·검증 순서와 완료 기준

1. 공개 endpoint 1개부터인지, 다중 endpoint 계약 확장부터인지 결정한다. TCP/SNI
   응답 전달과 Compose VM 포함 여부도 명시한다.
2. Gateway HTTP client를 로컬 fake server로 검증한다. 실제 token/실서비스는 사용하지
   않는다. 고정 endpoint, TLS, status별 오류, 동일 PUT/DELETE 재시도, 제한된 decode를
   구현한다.
3. Gateway intent/phase/port claim을 PostgreSQL에 추가하고 기존 snapshot 하위 호환,
   lease fencing, 재시작 시 동일 요청 재개를 검증한다.
4. create/cleanup/delete 경로와 Service 보존/stop 기능을 통합한다. Gateway 등록 전
   전체 workload 준비, 등록 뒤 최종 결과 공개, 삭제 확인 전 포트 해제 방지를 검증한다.
5. Scheduler/Backend/Frontend의 URL/TCP transport 전달 계약을 연결한다. Gateway
   upstream tuple은 참가자 응답에 노출하지 않는다. Scheduler DELETE 실패/전체
   polling 만료에서 예약을 반납하는 현재 경로를 cleanup proof 기반으로 수정한다.
6. 전용 시험 target에서만 DNS/TLS, Gateway → publicIP:NodePort/방화벽/CNI/NAT,
   실제 HTTP/TCP/SNI, workload 종료와 포트 재사용을 확인한다. Gateway 2xx로 이
   검증을 대체하지 않는다. 기존 image 승인·인증·격리 정책은 계속 적용한다.

필수 회귀/복구 시험:

- 다중 private sidecar + 공개 endpoint 1개는 성공; 여러 공개 포트/컨테이너는
  Gateway v1 mode에서 명시적 거절; 기존 Gateway off 경로는 기존 동작 유지.
- target IP 검증, 실제 allocated NodePort readback, IPv6 canonicalization, protocol
  소문자 mapping, HTTP URL 및 TCP TLS/SNI metadata 검증.
- PUT 201/200 동일 주소, GET200 목적지 불명, GET404 삭제 미증명, DELETE204 반복.
- timeout·비JSON·413·400/401/409/422/500/502/503와 지연 재시도; 로그 token 미노출.
- 원격 PUT 전/후, 응답 유실, route 결과 persist 전/후, Binding finalize 전/후
  프로세스 중단을 주입하여 주소/목적지/NodePort가 변하지 않는지 확인.
- DELETE intent 저장 전/후와 원격 DELETE 응답 유실 시 늦은 PUT이 새 route를
  되살리지 못하고, tombstone 확인 전 NodePort가 유지되는지 확인.
- route 적용 뒤 Binding 저장 실패 및 기존 failed-create cleanup에서 Gateway 정리
  증명 없이 `cleanup_completed=true`가 나오지 않는지 확인.
- route 삭제 실패·재시도 소진·target disabled/설정 제거·Service generation 교체 시
  포트/예약이 유지되고 운영 재개가 가능한지 확인.
- Scheduler DELETE FAILED/전체 polling timeout에서도 실제 stop/route 정리 미확인
  상태를 완료로 처리하거나 CPU/메모리 예약을 먼저 반납하지 않는지 통합 확인.
- 두 Runtime replica의 lease reclaim/stale 결과/DELETE와 PUT 경합. DB fencing만으로
  원격 mutation이 중단됐다고 가정하지 않는지 확인.
- 열린 TCP 연결은 route 삭제만으로 종료됐다고 보지 않으며 workload 정지 후 종료
  확인. cleanup/worker shutdown budget 초과 후에도 durable phase 재개.
- 실제 Gateway 사용 승인이 있는 시험에서만 Nginx/DNS/TLS/방화벽을 검증. 최소 150건
  요청의 queue 시간, Gateway call 시간/BUSY 비율, workload 준비, 최종 성공 시간을
  각각 측정하여 worker 및 Gateway 동시성 값을 결정.

이 문서만으로 연동 지원/운영 준비 완료를 선언하지 않는다. 위 제품 선택과 구현,
복구 시험 및 전용 target 검증이 남아 있다.
