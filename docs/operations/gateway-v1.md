# Gateway v1: K3s 단일 공개 endpoint

첫 범위는 사용자가 확정한 **v1 계약 유지, private 보조 컨테이너 유지, 공개 endpoint
1개·NodePort부터 지원**이다. 기본값은 off다. Compose VM과 여러 공개 포트는 이
모드에서 지원하지 않는다. Gateway off target의 기존 Ingress/NodePort 동작은 유지한다.

추적: [Runtime #73](https://github.com/MSG-CTF/secure-provisioner/issues/73),
[설계 검토 #74](https://github.com/MSG-CTF/secure-provisioner/pull/74),
[Scheduler 연계 #76](https://github.com/MSG-CTF/instance-scheduler/issues/76).

## 첫 OFF 업그레이드와 migration 순서

이 문서의 설정 예시는 fleet 전체가 Gateway ON이라는 뜻이 아니다. target opt-in,
consumer 배포, 방화벽 활성화는 각각 검증한 뒤 별도 운영 변경으로 진행한다.

첫 업그레이드의 API bridge는 **후보인 새 바이너리**를 `--deployment-api-only`로
실행한다. 이 bridge와 handoff 잠금 모드는 `OpenExisting`을 사용하므로 기존
operation/Binding schema의 호환성만 확인하고 migration을 실행하지 않는다.
bridge의 환경은 배포 전 디스크에 저장된 Runtime 환경에서 복사한다.

1. 모든 관련 target이 Gateway OFF이고 미완료 Gateway route가 없는지 확인한다.
   DB에 `004_gateway_routes.sql`이 아직 없다면 첫 OFF 배포 동안
   `GatewayTokenFile`에 대응하는 `PROVISIONER_GATEWAY_RUNTIME_TOKEN_FILE` 설정을
   **기존 디스크 환경과 CI `DEPLOY_ENV` 양쪽에서 생략**한다. 새 bundle에서만 지워도
   기존 환경을 복사하는 bridge에는 적용되지 않는다. token 파일 원문을 출력하거나
   지울 필요는 없다. 미완료 route가 있다면 설정을 지우는 대신 먼저 cleanup한다.
2. Gateway OFF 상태로 새 바이너리를 배포한다. API bridge는 migration 없이 기존
   API/queue를 유지하고, 정상 primary 시작이 `004_gateway_routes.sql`과
   `005_gateway_conflict_hold.sql`을 반영한다.
3. 새 primary의 readiness와 두 migration의 반영을 확인한 뒤 token-file 참조를
   디스크 환경과 `DEPLOY_ENV`에 복원한다. credential 값은 출력하지 않는다.
4. 이후 handoff에서는 이미 schema가 준비된 새 바이너리가 bridge/primary를 담당한다.
   consumer readiness, target 연결, Gateway canary를 확인한 뒤 opt-in을 결정한다.

애플리케이션의 worker shutdown 예산을 180초로 운영한다면 systemd의
`TimeoutStopSec=240`을 유지한다. 기존 90초 제한은 drain이 끝나기 전에 프로세스를
강제 종료할 수 있다. Gateway cleanup 예산 이상의 worker timeout도 함께 확인한다.
Gateway 전용 NodePort 방화벽은 [별도 운영 절차](gateway-firewall.md)를 따르며,
첫 OFF 업그레이드에서는 staged/disabled로만 둔다.

## 설정

기존 registry의 해당 K3s target에만 아래 설정을 추가한다. 기존 provider, architecture,
보안 capability, kubeconfig, `public_gateway` 설정도 계속 필요하다. `public_gateway`를
Gateway API 주소로 바꾸는 방식이 아니다.

```json
{
  "target_id": "worker-001",
  "exposure_mode": "NODE_PORT",
  "gateway": {
    "enabled": true,
    "upstream_ip": "<실제 worker 공인 IPv4 또는 IPv6>"
  }
}
```

위 IP는 치환이 필요한 문서 템플릿이다. hostname, 사설/loopback/예약/문서용 IP는
사용하지 않는다. Gateway는 자신의 공인 IP도 거절한다. 대상 IP는 운영자가 관리하며
요청 caller가 임의 IP/port를 지정할 수 없다. 목적지 포트는 Service readback의 실제
allocated NodePort를 사용한다. 내부 컨테이너 포트와 혼동하지 않는다.

Runtime 프로세스 설정:

```sh
PROVISIONER_STORE_MODE=postgres
PROVISIONER_GATEWAY_BASE_URL=https://gate.msgctf.kr
PROVISIONER_GATEWAY_RUNTIME_TOKEN_FILE=/etc/secure-provisioner/secrets/gateway-runtime-token
PROVISIONER_GATEWAY_REQUEST_TIMEOUT=90s
PROVISIONER_GATEWAY_MAX_INFLIGHT=1
```

DB URL은 기존 PostgreSQL Secret 설정을 사용한다. token 파일은 **Broker의 고정
RUNTIME_API_TOKEN과 같은 값**을 별도 Secret으로 주입한다. Runtime 수신 Service token,
Broker 로그인 JWT, K3s 인증서를 대신 넣지 않는다. token 원문을 이슈·로그·API 본문에
보내지 않는다. 파일은 프로세스가 읽을 수 있는 절대 경로이며 값은 시작할 때 읽는다.
교체 시 Gateway와 Runtime의 Secret 교체/프로세스 재시작 순서를 운영자가 조율한다.

HTTPS 인증서 검증은 유지한다. timeout은 최소 75초, 기본 90초다. 불확실한 Gateway
route가 DB에 남아 있다면 opt-in을 지우더라도 송신 Secret 없이 기동해 이를 잊도록
허용하지 않는다. 먼저 같은 instance ID의 cleanup을 완료해야 한다.

기존 rollback timeout과 별개로 Gateway cleanup 예산은 최소
`Gateway request timeout + namespace delete timeout + 10s`를 사용한다. token 파일이
설정되면 기본 worker shutdown 예산도 이 cleanup 예산+10초로 늘어난다. 명시한
`PROVISIONER_WORKER_SHUTDOWN_TIMEOUT`은 cleanup 예산 이상이어야 한다.

신규 migration `004_gateway_routes.sql`, `005_gateway_conflict_hold.sql`을 반영한 PostgreSQL이 필요하다. memory
저장 모드에서는 opt-in을 거절한다. 새 바이너리로 migration을 반영한 뒤 target을
opt-in하며, 미완료 route가 있는 상태에서 구버전 Runtime으로 되돌리지 않는다.

## 생성·응답

Admission과 worker replay에서 모든 컨테이너의 공개 포트 합계가 정확히 1개인지
검사한다. 여러 공개 포트를 첫 포트로 몰래 줄이지 않는다. K3s의 기존 승인 이미지,
격리, 자원, platform, 전체 컨테이너·Service readiness 검증을 계속 거친다. 재개
시에도 private sidecar를 포함한 준비 상태와 Namespace/Service UID를 확인한다.

생성 API는 기존처럼 202 Operation 접수만 수행한다. Gateway IO를 handler나
`enqueueMu` 안에서 실행하지 않는다. 실제 workload 준비 후 worker가 먼저 immutable
upstream intent를 commit하고 PUT한다. 응답 유실/재시작은 저장된 동일 ID·IP·NodePort·
protocol PUT을 재개한다. GET 200에는 목적지가 없으므로 일치 검증을 대체하지 않는다.

HTTP `service_url`은 Gateway의 HTTPS URL이다. TCP 응답 예시는 다음과 같다.

```json
{
  "container_name": "pwn",
  "port": 31337,
  "protocol": "TCP",
  "service_url": "tls://example-random.gate.msgctf.kr:443",
  "hostname": "example-random.gate.msgctf.kr",
  "connection_port": 443,
  "tls": true,
  "server_name": "example-random.gate.msgctf.kr"
}
```

기존 네 필드를 유지하며 `port`는 내부 컨테이너 포트다. 네 transport 필드는 선택
필드이며 legacy endpoint에서는 생략한다. Gateway HTTP에도 같은 transport metadata를
넣는다. TCP 참가자는 TLS/SNI 클라이언트를 사용해야 한다. 현재 Scheduler 이후의
Backend/Frontend가 이 값을 보존·표시하는 변경도 필요하므로 **Runtime 변경만으로
참가자 TCP 연동 완료를 선언하지 않는다**.

CREATE 성공은 workload 준비+Gateway control plane 반영 확인이다. Gateway의 2xx는
DNS·공인 인증서·방화벽·외부 문제 응답을 검증하지 않는다. 전용 target에서 실제
Gateway → 공인 IP:NodePort의 연결, CNI/NAT, HTTP/TCP/SNI를 따로 검증해야 한다.
기존 NodePort 접근 정책을 Gateway 전용 방화벽 규칙으로 자동 변경하지 않는다.

## 삭제·재시작·정리 증명

Binding이 유실돼 Gateway journal에서 복구할 때 승인된 `WorkloadNetwork` 스냅샷도
함께 복원한다. 컨테이너 정체성·peer 그룹·egress의 중첩 값은 복사하여 복구된 Binding을
변경해도 원래 journal의 승인 스냅샷이 바뀌지 않도록 한다.

`runtime_gateway_routes`는 `APPLY_PENDING`, `APPLIED`, `CONFLICT_HOLD`, `DELETE_PENDING`,
`ROUTE_DELETED`, `DELETED` phase와 원래 workload/Service generation 및 upstream을
보관한다. 삭제 ID는 tombstone으로 계속 보존하며 새 배포에 재사용하지 않는다.

삭제 intent를 먼저 commit하고, 소유 Deployment를 0으로 줄여 Pod를 정지시키되
**Service와 NodePort 할당은 유지**한다. 같은 ID DELETE 204를 확인·저장한 뒤에만
Namespace를 삭제하고 실제 부재를 확인한다. 기존 TCP 연결은 route 삭제만으로
종료됐다고 판단하지 않는다. Pod 정지가 일시 실패해도 공개 route 제거는 시도하며
workload cleanup은 미완료로 유지한다.

GET 404, timeout, 연결 실패, 비JSON proxy 오류, 재시도 횟수 소진은 DELETE204의
대체 증명이 아니다. 불확실한 mutation/cleanup은 기존 `RETRYING` 상태로 지연 재개하고
포트/intent를 유지한다. 오래 지속되면 운영자가 token·Gateway 설치/복구·target 상태를
수리한 뒤 같은 작업을 재개한다. 잘못된 ID/목적지로 새 경로를 발급하지 않는다.
확정된 일반 입력 오류는 원래 route tombstone과 workload cleanup 뒤 실패로 끝낸다.

`TARGET_IN_USE`는 **다른 instance ID의 route가 이 IP/port를 참조한다는 증거**다.
`INSTANCE_CONFLICT`도 일반 validation 실패와 구분해 `CONFLICT_HOLD`로 기록한다.
즉시 Pod 정지를 시도하고 Service/NodePort를 보존하며 CREATE 성공으로 승격하지 않는다.
현재 ID DELETE204만으로 다른 ID의 route가 제거되었다고 간주하지 않는다.

운영자가 Gateway에서 다른 ID의 소유권을 확인하여 원인을 정리해야 한다. Runtime은
다른 ID를 추측하거나 자동 삭제하지 않는다. 이 작업 후 기존 cleanup 재시도는
원래 Service UID/포트 소유권 확인 → 원래 ID+tuple PUT200/201의 유일성 증명 →
DELETE204 → 실제 workload 삭제 순서로만 진행한다. 긍정 PUT과 DB phase 저장 사이에
중단돼도 같은 tuple로 다시 확인한다. 충돌이 남거나 원래 ID가 이미 tombstone돼
PUT이 불가능하면 자동 해제하지 않으며 운영 reconciliation이 필요하다. target의
IP/설정 변경만으로 journal/hold가 사라지지 않는다.

Binding 저장 실패 rollback도 Gateway 삭제를 통과한다. Binding/Namespace가 없어도
미완료 journal이 있으면 runtime-status는 `TERMINATING`, `cleanup_pending=true`를
반환한다. journal에서 Binding을 복원해 새 DELETE request ID의 cleanup 재접수도
처리한다. Gateway의 instance ID는 항상 원래 ID다. DELETE 성공에는
`cleanup_completed=true`를 반환하고 실패/불명에는 true를 반환하지 않는다.

Scheduler도 DELETE 실패·polling 만료·404를 cleanup 증명으로 취급하지 않고 예약을
유지해야 한다. 기존 Runtime에는 Gateway journal이 없으므로 optional 필드 누락을
완료로 해석하지 않는다. 실제 NodePort 보존은 Service 객체가, CPU/메모리 admission
예약은 Scheduler가 담당하는 서로 다른 보장이다.

리소스 UID 교체/유실을 감지하면 원래 route의 cleanup으로 전환한다. 불명 cleanup이
있는 target의 신규 Gateway create는 지연한다. 외부 관리자나 다른 controller가
Service/Namespace를 삭제하거나 K3s 저장 상태를 초기화하면 포트 보존이 깨질 수
있으므로 해당 target의 신규 배치를 먼저 막고 원래 route 삭제를 복구해야 한다.

## 동시성과 검증

Gateway 원격 호출 동안 per-instance PostgreSQL session advisory lock을 사용한다.
intent 저장은 autocommit이므로 프로세스 중단 후에도 보인다. lock 전용 pool 8개를
기존 operation/Binding/lease pool 30개와 분리한다. 취소 후 background 5초 unlock이
실패하면 connection을 폐기해 session lock을 pool에 반환하지 않는다.

8은 현재 코드의 고정된 안전 한도이며 환경변수로 조절하지 않는다. 이 lock은 K3s
create/Ready 대기부터 Gateway PUT까지 포함하므로 worker를 30개로 늘려도 한
프로세스에서 활성 Gateway lifecycle은 최대 8개다. 이 한도 포화는 DB connection을
기다리며 추가 worker를 묶지 않고 지연 재시도로 넘긴다. 측정된 최적값이 아니며
환경에 맞춘 변경에는 DB 총 connection 예산과 실제 workload/Gateway 부하 시험이 필요하다.

`MAX_INFLIGHT=1`은 **한 프로세스**의 원격 mutation 제한이며 검증 전 초기값이다.
포화 시 기다리며 DB/worker를 묶지 않고 지연 재시도로 넘긴다. 여러 replica의 전역
호출 한도는 운영에서 별도로 조율해야 한다. 실제 HTTP call 자체와 기존 K3s Ready
대기는 완료/취소까지 worker slot을 점유하므로 기존 worker 수만으로 150건 Gateway
처리량을 보장하지 않는다. Scheduler의 짧은 접수 timeout과 10분 전체 polling 예산은
각각 구분해야 한다.

로컬 검증은 fake TLS Gateway, fake Kubernetes, 별도 PostgreSQL에서만 수행한다.
PUT 응답 유실의 동일 tuple 재개, DELETE 실패 시 Service 보존, Binding 실패 cleanup,
lease/intent/lock 취소 및 pool 기아, private sidecar readiness, TCP metadata·cleanup
proof 전달을 회귀 시험한다. 운영 token이나 실제 Gateway는 이 테스트에 사용하지 않는다.
