# B안 이미지 준비 및 사전 다운로드 API 계약 제안

상태: 구현 전 검토안. 이 문서와 OpenAPI 추가는 HTTP handler, 다운로드 worker,
노드 agent, DB migration 또는 운영 설정을 활성화하지 않는다.
기준: Runtime `a4c1f47`, Scheduler `d138f3f`, Broker staging `fd5ab63`.

연결 이슈: [Runtime #69](https://github.com/MSG-CTF/secure-provisioner/issues/69),
[Scheduler #75](https://github.com/MSG-CTF/instance-scheduler/issues/75),
[Broker #8](https://github.com/MSG-CTF/resource-broker/issues/8),
[Backend #139](https://github.com/MSG-CTF/msg-backend/issues/139).

기계 판독 계약은 [image-preparation.openapi.yaml](image-preparation.openapi.yaml),
검증용 예시는 [examples/image-preparation](examples/image-preparation/)에 있다.

## 역할과 기본 정책

- Backend가 Runtime에 사전 다운로드를 요청하고 작업 진행을 조회한다.
- Scheduler는 Broker 후보를 받은 뒤 Runtime의 준비 상태를 일괄 조회한다(B안).
- Runtime이 노드별 다운로드, 로컬 이미지 확인, 재시도, 상태 만료를 관리한다.
- Broker 후보 조회·예약 요청과 응답은 변경하지 않는다.
- 이미지 준비는 선호 조건이다. 누락, UNKNOWN, 만료, timeout, API 오류만으로
  후보를 제거하거나 생성 실패로 처리하지 않는다. 실제 생성의 인증, digest 승인,
  격리, 플랫폼, 자원 검증 실패는 기존 실패 경로로 처리한다.
- 준비 작업 실패를 release 활성화의 필수 차단 조건으로 만들지 않는다. 그런 gate는
  이번 성능 최적화 계약과 별도 운영 정책이다.

## 조회: POST /v1/image-readiness/query

```json
{
  "architecture": "AMD64",
  "images": [
    "ghcr.io/msg-ctf/challenges/example/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "ghcr.io/msg-ctf/challenges/example/db@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  ],
  "target_ids": ["target-a", "target-b", "unknown-target"]
}
```

`images`는 보조 컨테이너를 포함한 **전체 repository@sha256 참조 집합**이다.
digest 문자열만으로는 저장소와 인증·승인 대상을 식별할 수 없으므로 받지 않는다.
1~32개 이미지, 1~50개 target을 허용하며 중복 입력과 tag-only 입력은 400이다.
순서는 식별값에 영향을 주지 않는다. 하나의 요청은 한 architecture를 나타낸다.
`AMD64`/`ARM64`를 받고 OCI `linux/amd64`/`linux/arm64`로 변환한다.
이번 계약은 Linux K3s이며 다른 OS 및 추가 CPU variant는 지원한다고 선언하지 않는다.

```json
{
  "image_set_id": "sha256:<canonical-input-hash>",
  "architecture": "AMD64",
  "targets": [
    {"target_id":"target-a","ready":true,"ready_node_count":1,"eligible_node_count":2,"observed_at":"2026-10-24T00:00:00Z","valid_until":"2026-10-24T00:01:00Z"},
    {"target_id":"target-b","ready":false,"ready_node_count":0,"eligible_node_count":2,"observed_at":"2026-10-24T00:00:00Z","valid_until":"2026-10-24T00:01:00Z"}
  ]
}
```

설명용 hash placeholder 외에 schema에 맞는 완전한 예시는 별도 JSON에 둔다.
실제 조회 응답에는 요청한 target 중 Runtime Registry에 알려진 대상만 들어간다.
알 수 없는 target은 생략하며 응답 전체를 404로 만들지 않는다. Scheduler는 생략된
대상을 UNKNOWN으로 취급한다. 알려졌지만 비활성, 미관측 또는 미준비인 target은
생략하지 않고 `ready=false`로 반환한다. 응답 순서에 의존하지 않는다.

### ready와 노드 수

`ready=true`는 **같은 노드 한 대 이상**이 다음 조건을 모두 만족함을 뜻한다.

1. 요청한 target에 소속되고, Node Ready이며 cordon 또는 적용되는 NoSchedule/
   NoExecute 제약 때문에 일반 Runtime workload를 받을 수 없는 노드가 아니다.
2. 실제 노드 OS/architecture가 요청과 일치한다.
3. 그 노드의 실제 실행용 CRI 캐시에 전체 이미지가 존재한다. 주 이미지와 보조
   이미지가 서로 다른 노드에 나뉘어 있는 경우는 충족하지 않는다.
4. index digest이면 해당 플랫폼 child manifest와 config/layer가 실행에 사용 가능한
   상태임을 확인한다. CRI image ID가 요청 manifest digest와 항상 같은 값이라고
   가정하지 않는다. 다른 Docker daemon이나 containerd namespace의 캐시는 세지 않는다.
5. 요청한 모든 정확한 이미지 참조가 **현재 로드된 정책**에서 `create_enabled`다.
   정책 미설정/미등록/blocked이면 준비 우선순위를 부여하지 않는다.
6. 위 판단에 사용한 실제 관측값이 아직 유효하다.

`ready_node_count`는 이 전체 교집합을 만족하는 노드 수이며 ready와 동치인
`ready_node_count > 0`을 지킨다. `eligible_node_count`는 같은 관측에서 확인한
기본 실행 자격·플랫폼 적합 노드 수다. 전자는 후자보다 클 수 없다. 이미지별
보유 노드 수를 합산하지 않는다. 이 수는 CPU/메모리 예약이나 해당 인스턴스의
격리·포트·환경·비밀값·전체 실행 스펙 승인까지 보장하지 않는다. 최종 생성에서
그 검증을 다시 수행하며 자원 수용 여부는 Broker 예약과 Kubernetes가 판단한다.

아직 한 번도 완전한 target 관측이 없으면 두 수는 보수적으로 0, `ready=false`,
`observed_at=null`, `valid_until=null`이다. 미관측과 실제 노드 0대를 혼동하지 않도록
클라이언트는 시각 필드도 확인한다.

### 시각과 캐시

- `observed_at`은 실제 노드/캐시 상태 수집을 **시작한 시각**이다. 조회 응답 생성,
  DB 재조회, 캐시 hit, Broker 수신 시각으로 덮어쓰지 않는다.
- 여러 노드 관측을 결합하면 판단·개수에 사용한 증거의 **가장 오래된 시각**을
  사용한다. 하나의 fresh 노드로 오래된 다른 노드의 수를 새로 보이게 만들지 않는다.
- `valid_until`은 그 증거의 최초 만료 시각이며 내부 관측/정책 유효기간보다 늦을 수
  없다. 읽기나 재전송으로 연장하지 않는다. 최신 정책을 검사해도 이미지 관측 시각은
  갱신하지 않는다. 정책 차단은 Runtime의 기존 positive 캐시를 무효화한다.
  별도 push가 없는 B안에서 Scheduler의 positive 힌트는 남은 로컬 TTL 동안
  유지될 수 있다. 즉시 전파를 보장하지 않으며 실제 create는 현재 정책으로 거절한다.
- 만료 또는 알려진 노드 교체/boot ID 변화/캐시 삭제 후에는 `ready=false`,
  `ready_node_count=0`으로 반환한다. 과거 실제 관측과 원래 만료 시각은 보존한다.
  새 관측 전 캐시가 삭제됐다고 단정하거나 이전 준비 상태를 재사용하지 않는다.
- 서버와 클라이언트 시계 허용 오차를 구현 시 명시한다. 미래 관측값은 positive
  증거로 쓰지 않는다. 응답 헤더는 `Cache-Control: no-store`다. Scheduler 내부
  캐시는 별도로 `min(로컬 cache-ttl, 원래 valid_until까지 남은 시간)`만 유지한다.
- 60초 TTL, 300ms 조회 deadline, 10초 Scheduler 캐시는 **초기 제안값**이다.
  새 Runtime 관측 경로의 30초 주기와 조회 p95/p99를 실측한 뒤 조정한다.
  Broker Agent의 기존 300초 전송 주기를 30초라고 간주하지 않는다.
- 조회 handler는 등록된 관측 저장소와 현재 정책을 읽는다. 요청마다 노드에 SSH/
  CRI 호출을 fan-out하거나 다운로드 완료를 기다리지 않는다.

## 이미지 집합 식별

`image_set_id = "sha256:" + SHA256(UTF8(canonical_json))`이다.
canonical JSON은 다음 key 순서, 공백 없는 separators, 중복 없는 images의 ASCII
오름차순 정렬을 사용한다. refs는 유효한 lowercase GHCR immutable 참조여야 한다.

```text
{"schema_version":1,"architecture":"AMD64","images":["<sorted-ref-1>","<sorted-ref-2>"]}
```

`release_id`, target 집합, 정책 버전, 요청 ID, 컨테이너 순서, 환경/비밀값은 hash에
넣지 않는다. architecture와 보조 이미지 변경은 다른 식별값을 만든다. API는
입력에서 직접 계산하므로 클라이언트가 보낸 image_set_id를 신뢰하지 않는다.
다운로드 중복 합치기는 node UID·boot/cache generation·실행 CRI·platform·resolved
digest 단위로 하고, 호출자의 승인·권한 검사는 캐시 hit여도 별도로 수행한다.

## Backend 사전 다운로드 작업

### POST /v1/image-preparations

입력은 `request_id`, 선택적 `release_id`, `architecture`, `isolation_profile`,
`containers[]`(name, image, ports), `target_ids`다. 전체 release 이미지가 필요하며
Secret 원문, 환경변수 값, GHCR credential, kubeconfig는 받지 않는다.
컨테이너·포트·격리 프로필은 승인된 digest 정책과의 일치 확인에 사용한다.

202는 접수만 뜻하며 `operation_id`, `image_set_id`, `status`, 진행 조회 Location을
반환한다. 같은 인증 범위·endpoint·request_id·정규화된 본문은 기존 작업을 반환하고,
다른 내용이면 409다. 정규화는 target_ids 정렬, containers의 name 정렬, ports 정렬을
포함하며 중복 container name/port는 거절한다. request_id를 제외한 나머지 모든 입력과
release_id의 값/생략 여부는 요청 동일성에 포함한다. 기본값 생략과 명시적 값이
같다고 임의 처리하지 않는다. retry 본문은 node_uids를 정렬해 별도로 비교한다.
현재 정책을 재적용하기 전에 이미 접수한 정확한 요청인지 먼저 확인한다. 승인
누락·blocked·잘못된 platform·미등록/비활성 target은 새 접수에서 422로 거절한다.
현재 `CREATE`/`DELETE` Operation과 별도의 작업 타입·영속 상태가 필요하다.

Runtime은 요청한 target 안에서 architecture와 기본 실행 자격이 맞는 노드를 찾고
초기 node UID 집합을 영속화한다. 이 집합이 작업 완료 기준이다. 새 노드는 과거
작업의 완료 대상을 자동으로 늘리지 않으며 준비 여부가 확인될 때까지 UNKNOWN이다.
자동 확장은 별도 후속 준비 요청으로 기록한다. 실행/자원 예약이나 문제 앱 실행은
하지 않는다. 노드 agent가 실제 K3s CRI에 pull/inspect를 수행한다.

### GET /v1/image-preparations/{operation_id}

`QUEUED`, `RUNNING`, `SUCCEEDED`, `PARTIAL`, `FAILED`와 target/node UID/노드명/
architecture/이미지별 상태, 요청 digest와 resolved digest, 시도 횟수, 실제 관측 시각,
분류한 error_code를 반환한다. 같은 노드에서 전체 이미지가 검증돼야 그 노드가
`READY`다. 선택된 모든 노드가 READY면 SUCCEEDED, 일부만 READY면 PARTIAL이다.
적합 노드가 하나도 없으면 FAILED/NO_ELIGIBLE_NODES다. 영구 오류·시도 소진 뒤에만
종료 상태로 집계한다. 알려지지 않은 operation_id는 404다. 모든 적합 노드가
READY라면 이미지별 중복은 개수에 영향을 주지 않는다. 이력의 READY는 당시 관측이다.

작업은 이력이다. SUCCEEDED 이후 캐시가 지워져도 과거 성공을 덮어쓰지 않는다.
현재 우선순위는 별도 image-readiness/query 결과로 판단한다.

### POST /v1/image-preparations/{operation_id}/retry

새 `request_id`와 선택적 `node_uids`를 받는다. 실패·부분 성공으로 끝난 작업에만
허용하며 진행 중 또는 이미 성공한 작업은 409다. 지정 노드는 원래 작업 범위에
속하고 실패한 노드여야 한다. 생략하면 원래 실패 노드를 모두 대상으로 삼는다.
원래 대상 UID가 교체됐다면 새 target 준비 요청이 필요하다.
새 작업 ID와 `parent_operation_id`를 만들어 과거 작업은 보존한다. 같은 재시도 요청은
같은 새 작업을 반환한다. parent 상태 검사보다 정확한 retry replay 조회를 먼저 한다.
성공한 항목은 재검증 후 재사용하고 나머지만 다운로드한다.
재시도 시 현재 승인 정책과 인증 범위를 다시 검사한다.

자동 재시도는 timeout/일시 네트워크/429/registry 5xx에 backoff와 최대 시도를 적용한다.
인증 거절, 미등록 승인, blocked, platform 불일치, 없는 manifest는 자동 반복하지
않으며 원인이 수정된 뒤 명시적 재시도 또는 새 요청으로 처리한다. 디스크 부족은
노드 조치 전까지 RESOURCE_EXHAUSTED로 둔다. 원문 오류/토큰은 응답·로그에 싣지 않는다.
기존 작업 worker와 준비 작업의 동시수를 분리해 생성·삭제가 밀리지 않게 한다.

## 생성과 배치

`POST /internal/v1/instances`에 선택 필드 `release_id`(UUID), `architecture`
(`AMD64`/`ARM64`)를 추가한다. 기존 클라이언트의 생략은 계속 허용하고 새 release
호출자는 둘 다 전달한다. 명시적 null은 거절한다. release_id는 trace 값이며 실행
권한·승인·이미지 선택의 대체 근거가 아니다. 실제 containers 이미지 집합으로
준비 상태를 계산하고 archive/reset/retry에서도 전달받은 원래 값을 보존한다.
architecture가 있으면 actual node·manifest와 대조하는 필수 실행 조건이다. 생략한
구버전 요청도 신뢰된 target 플랫폼과 실제 노드의 불일치를 허용하는 예외가 아니다.

이 두 고정 필드는 최초 접수의 request fingerprint에 포함한다. 같은 생성 요청의
재전송/reconcile은 처음 payload를 그대로 사용해야 한다. 구버전에서 접수한 작업에
새 필드를 나중에 끼워 넣어 재전송하지 않는다. 변동하는 ready 노드 목록·시각은
생성 payload에 넣지 않고 Runtime이 내부에서 계산한다.

Scheduler는 필수 후보 검사를 먼저 하고 같은 위험도 안에서 준비된 target을 우선한
뒤 기존 분산 순서를 유지한다. 준비 조회 예외는 Broker 실패로 전파하지 않는다.
후보 조회 뒤 시간이 흘렀다면 reservation 전에 후보 valid_until을 다시 확인한다.
미확정 예약은 기존 request_id로 복구하며 준비 순위 변화로 다른 후보를 예약하지 않는다.

Runtime은 전체 이미지가 준비된 노드에 `preferredDuringSchedulingIgnoredDuringExecution`
선호도를 각 컨테이너 Deployment에 적용하고 `IfNotPresent`를 유지한다. 준비된 노드가
없으면 이 선호도만 생략한다. OS/architecture·격리 조건은 필수이며 ready를 이유로
이를 완화하지 않는다. 같은 노드에 모든 이미지를 가진다는 준비 기준과 모든 Pod를
한 노드에 모은다는 co-location 요구는 다르며 후자는 이 계약에서 요구하지 않는다.

## 기존 설정과 새 설정 제안

기존 `PROVISIONER_CLUSTER_REGISTRY`, `PROVISIONER_IMAGE_POLICIES`, 서비스 인증을
사용한다. Broker target ID와 Registry target ID가 같아야 한다. Backend 준비 권한,
Scheduler 조회 권한, 노드 관측 권한을 구분하며 CI smoke 토큰에 준비 권한을 주지 않는다.
현재 full/CI 토큰 구조를 확장해야 하므로 이미 권한 분리가 구현돼 있다고 보지 않는다.

아래 항목은 **미구현 새 설정명과 초기값 제안**이다.

```dotenv
PROVISIONER_IMAGE_PREFETCH_ENABLED=false
PROVISIONER_IMAGE_PREFETCH_OBSERVE_INTERVAL=30s
PROVISIONER_IMAGE_PREFETCH_READINESS_TTL=60s
PROVISIONER_IMAGE_PREFETCH_MAX_PARALLEL_PULLS_PER_NODE=1
PROVISIONER_IMAGE_PREFETCH_MAX_ATTEMPTS=3
```

```yaml
scheduler:
  image-readiness:
    enabled: false
    lookup-timeout: 300ms
    cache-ttl: 10s
```

전용 Runtime 조회 timeout을 사용하고 기존 create/operation client의 5초 read timeout을
재사용하지 않는다. 고정된 fallback 동작을 fail-closed 설정으로 바꾸지 않는다.
시범 검증 후 양쪽 enabled를 켠다. TTL과 관측 주기는 함께 설정 검증한다.
실제 배치 가능한 모든 노드에 GHCR pull 인증이 있어야 한다. cache hit만으로
registry 자격을 매번 재인증했다고 선언하지 않는다. 필요 시 K3s 버전과 kubelet의
image pull credential verification 설정을 별도로 확인한다.

## 적용 순서와 완료 기준

1. 계약 PR에서 Scheduler/Backend와 필드·상태 의미를 검토한다. Broker에는 B안에서
   API 변경이 없고 runtime_ready/예약 유효기간과 이미지 준비를 분리한다는 이슈를 연결한다.
2. Runtime의 영속 작업, 관측 경로, HTTP API, 선택적 create 필드, 권한을 먼저 구현한다.
   초기 스위치는 false다. 구버전에서 모르는 JSON key를 거절하므로 Scheduler 선배포 금지다.
3. Backend 준비 요청 및 Scheduler 일괄 조회/재시도 원본 보존을 구현한다.
4. 다음 수용 시험 후 시범 대상에서 스위치를 켠다. 기존 Broker 예약 및 실제 생성은 유지한다.

- 같은 노드에 web/db 모두 존재: true/1. web과 db가 다른 노드에만 존재: false/0.
- 전체 이미지를 가진 노드가 2대면 ready_node_count=2이며 인스턴스 2개 예약을 보장하지 않는다.
- target 일부/전부 미등록이면 해당 결과만 생략한다. 미등록 operation 조회는 404다.
- 조회/캐시 재접근, 정책 재조회, 재전송으로 observed_at/valid_until이 연장되지 않는다.
- 미관측/만료/노드 교체/boot 변화/캐시 삭제는 우선순위를 제거하고 정상 lazy pull을 허용한다.
- 조회 timeout/401/403/404/5xx에도 보안 검사를 통과한 생성은 기존 경로로 진행한다.
  401/403은 설정 오류로 관측하되 실제 생성 API의 인증 오류까지 무시하지 않는다.
- 보조 이미지 미승인, 정책 block, 플랫폼 불일치는 실제 생성에서 거절한다.
- 작업 부분 실패·중복 접수·선택 재시도·재시작 복구를 검사하고 원문 Secret을 기록하지 않는다.
- 두 새 create 필드의 생략 호환성, 원래 payload replay/reconcile/reset 보존을 확인한다.

현재 PR의 검증은 OpenAPI/예시의 형식·계약 검토다. 위 런타임 수용 시험은 실제
handler/agent/worker 구현 PR에서 수행해야 하며 문서 검증으로 통과 처리하지 않는다.
