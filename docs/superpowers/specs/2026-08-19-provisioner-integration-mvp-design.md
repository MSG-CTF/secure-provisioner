# Provisioner 통합 MVP 설계

**작성일:** 2026-08-19

**목표 브랜치:** `dev`

**통합 방식:** `origin/dev`에서 만든 로컬 임시 브랜치에서 안정화한 뒤 단일 Draft PR로 `dev`에 반영

## 1. 목적

현재 서로 다른 브랜치에 있는 다음 기능을 현재 `dev` 구조에 맞춰 하나의 실행 가능한 Provisioner MVP로 결합한다.

- 다중 K3s target 선택과 실제 Kubernetes adapter
- 다중 컨테이너 및 다중 공개 endpoint
- `WEB`/`PWN` 문제 유형별 격리 정책
- 내부 API Bearer 서비스 인증
- PostgreSQL 기반 operation queue, lease, 재시도 및 재시작 복구
- Scheduler와 Broker를 대신하는 로컬 mock 호출 경계
- GHCR digest 이미지로 만든 `test_ctf` 문제 요청

최종 결과는 장기 통합 브랜치로 유지하지 않는다. 로컬 통합 브랜치는 충돌과 계약 차이를 해소하기 위한 작업 공간이며, 검증이 끝난 결과만 원격 브랜치에 한 번 push하여 `dev` 대상 Draft PR로 제출한다.

## 2. 범위

### 포함

- `POST /internal/v1/instances`
- `GET /internal/v1/operations/{operation_id}`
- `GET /internal/v1/instances/{instance_id}/runtime-status`
- `DELETE /internal/v1/instances/{instance_id}`
- 모든 내부 API의 Bearer 인증
- PostgreSQL operation 및 runtime binding 영속화
- 제한된 수의 worker가 PostgreSQL lease로 생성·삭제 작업 처리
- 만료된 lease 회수와 프로세스 재시작 복구
- `WEB` 및 `PWN` 격리 정책 합성과 K3s 리소스 렌더링
- PWN target의 `gvisor` RuntimeClass capability 검증
- Scheduler mock이 TTL 만료 삭제 요청을 보내는 흐름
- 실제 K3s target을 registry의 `target_id`로 선택하는 흐름

### 제외

- 실제 Scheduler 또는 Resource Broker 구현 변경
- Provisioner 내부 TTL 타이머
- K3s reconciler
- 이미지 자동 pre-pull
- 문제 catalog 자동화
- 커널 문제 격리
- 동적 target 등록 및 health scheduler
- 운영용 인증서 발급과 mTLS

## 3. 기준 계약

생성 API는 현재 `dev`의 다중 컨테이너 계약을 유지하며 외부 정책 선택 필드는 하나만 사용한다.

```json
{
  "request_id": "runtime-create-001",
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
        "image": "ghcr.io/msg-ctf/challenge@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ports": [8080],
        "expose": true,
        "run_as_user": 10001,
        "writable_paths": []
      }
    ],
    "internal_connections": [],
    "resource_limits": {
      "cpu_millicores": 500,
      "memory_mib": 512,
      "ephemeral_storage_mib": 1024
    }
  }
}
```

`isolation_profile`은 정확히 `WEB` 또는 `PWN`이어야 한다. `challenge_ref`, `isolation_ref`, `resource_profile_ref`, 외부 입력 `outbound_mode`는 받지 않는다. 이미지 주소는 digest를 포함해야 하며 pre-pull 여부와 무관하게 생성 명령에 포함한다.

TTL은 Scheduler 책임으로 유지한다. Scheduler mock은 만료 시 기존 삭제 API를 `delete_reason: TTL_EXPIRED`로 호출한다. Provisioner는 TTL 시각을 계산하거나 자체 만료 스캔을 수행하지 않는다.

## 4. 구성 요소

### HTTP API

- 요청 body를 읽기 전에 Bearer token을 검증한다.
- 현재 token과 이전 token을 허용하여 무중단 회전을 지원한다.
- 인증 실패는 `401 UNAUTHENTICATED`와 `WWW-Authenticate`를 반환한다.
- JSON duplicate key, unknown field, 잘못된 enum 및 잘못된 digest를 fail closed로 거부한다.

### Isolation resolver

- 모든 요청에 비활성화할 수 없는 `STANDARD@v1` baseline을 적용한다.
- `WEB`은 HTTP endpoint와 현재 지원 노출 방식을 사용한다.
- `PWN`은 TCP endpoint, NodePort 및 `runtimeClassName: gvisor`를 요구한다.
- 두 프로필 모두 non-root, read-only root filesystem, privilege escalation 금지, capabilities 전체 제거, RuntimeDefault seccomp, ServiceAccount token 비활성화를 적용한다.
- 기본 egress는 DNS와 명시된 내부 연결 외에는 차단한다.

### Target registry와 K3s adapter

- 요청의 `target_id`로 정확한 Kubernetes client를 선택한다.
- target 설정은 provider, region, architecture, kubeconfig, public gateway, 노출 방식 및 보안 capability를 포함한다.
- disabled target 또는 필수 capability가 없는 target은 생성 전에 거부한다.
- 생성 결과에는 공개 endpoint를 컨테이너·포트별 목록으로 보존한다.
- 삭제는 저장된 target, Namespace 및 Namespace UID를 사용하여 다른 인스턴스를 삭제하지 못하게 한다.

### Runtime service

- API 요청을 isolation resolver로 해석한 뒤 immutable command snapshot으로 operation을 적재한다.
- CREATE 결과를 operation checkpoint로 먼저 저장하고 runtime binding을 저장한다.
- checkpoint가 있으면 lease 회수 후 K3s 생성 부작용을 반복하지 않고 binding 저장부터 재개한다.
- DELETE 요청은 저장된 binding과 team, target, runtime workload ID가 모두 일치해야 한다.

## 5. PostgreSQL 저장 모델

### `operations`

다음 정보를 저장한다.

- `operation_id`, `request_id`, `operation_type`, `status`
- CREATE 또는 DELETE command snapshot JSON
- `attempt`, `max_attempts`, `last_error_code`
- `next_retry_at`
- `lease_owner`, `lease_until`, `lease_version`
- CREATE checkpoint JSON과 최종 result JSON
- 생성·수정·시작·완료 시각

`request_id`는 전역 unique로 두고, 같은 request payload 재전송은 기존 operation을 반환한다. 같은 `request_id`로 다른 payload가 오면 `REQUEST_ID_CONFLICT`를 반환한다.

### `runtime_bindings`

다음 정보를 저장한다.

- `instance_id`, `team_id`, `target_id`
- `namespace`, `namespace_uid`, `runtime_workload_id`
- endpoint 목록
- resolved isolation/workload profile 및 제한 정보
- `CREATED`, `DELETING`, `DELETED` 상태
- 생성·수정·삭제 시각

`instance_id`는 unique다. 같은 배치 정보를 다시 저장하는 것은 멱등 성공으로 처리하고 다른 배치 정보는 conflict로 처리한다.

### 트랜잭션 경계

- CREATE operation enqueue와 idempotency 판정은 한 트랜잭션에서 처리한다.
- CREATE checkpoint 저장은 lease 소유권을 확인하는 조건부 update로 처리한다.
- binding 저장 후 operation 완료 전 프로세스가 종료되어도 checkpoint를 통해 재개할 수 있다.
- DELETE operation enqueue와 binding의 `DELETING` 전환은 같은 트랜잭션에서 처리한다.
- 실제 K3s 삭제 성공 후 binding의 `DELETED` 전환과 operation 성공 저장도 같은 트랜잭션에서 처리한다.

현재 분리된 memory store 인터페이스를 유지하면서 PostgreSQL 구현에서만 두 저장소를 느슨하게 묶으면 crash gap이 남는다. 따라서 runtime service에 PostgreSQL transaction boundary를 제공하는 작은 repository/coordinator 인터페이스를 추가하고 memory 구현도 같은 동작 계약을 따른다.

## 6. Worker lease 계약

현재 `Next` 후 `MarkRunning`을 호출하는 두 단계 구조는 다중 프로세스 PostgreSQL worker에 사용하지 않는다. 다음 원자적 계약으로 변경한다.

- `Claim(ctx, worker_id, lease_duration)`
- `RenewLease(ctx, operation_id, worker_id, lease_version, lease_until)`
- `MarkRetrying`, `MarkSucceeded`, `MarkFailed`는 동일한 lease owner와 version을 조건으로 수행
- `ReleaseOrRequeue`도 현재 lease 소유자만 수행

claim은 `FOR UPDATE SKIP LOCKED`를 사용해 우선순위와 생성 순서대로 하나의 operation을 `RUNNING`으로 전환한다. DELETE는 CREATE보다 높은 우선순위를 갖는다.

lease renewal 실패 시 해당 operation 실행 context를 취소한다. 이전 worker가 lease를 잃은 후에는 DB 상태를 완료·재시도로 바꿀 수 없다. Kubernetes adapter의 리소스 이름과 Namespace UID 검증, CREATE checkpoint를 함께 사용해 at-least-once 실행의 중복 부작용을 제한한다.

worker 프로세스가 종료되면 미완료 operation은 lease 만료 후 다른 worker가 회수한다. DB의 `max_attempts`가 재시도 한도의 기준이며 프로세스별 설정이 이를 덮어쓰지 않는다.

## 7. 생성 흐름

1. Scheduler mock이 Bearer token과 생성 요청을 전송한다.
2. API가 인증, JSON, digest, target 및 profile 형식을 검증한다.
3. Isolation resolver가 `STANDARD@v1`과 `WEB` 또는 `PWN` 정책을 합성한다.
4. PostgreSQL에 CREATE operation과 immutable command snapshot을 저장한다.
5. Worker가 operation lease를 획득한다.
6. K3s adapter가 target registry에서 client를 선택하고 Namespace 및 격리 리소스를 생성한다.
7. 생성 결과를 checkpoint로 저장한다.
8. Runtime binding을 저장하고 operation을 `SUCCEEDED`로 변경한다.
9. 호출자는 operation API로 완료를 확인한 뒤 runtime-status API를 조회한다.

## 8. 삭제 및 TTL 흐름

1. 사용자 요청 또는 Scheduler mock이 삭제 API를 호출한다.
2. TTL 삭제는 `delete_reason: TTL_EXPIRED`를 사용한다.
3. Runtime service가 저장된 binding과 요청의 소유·target 정보를 비교한다.
4. 한 트랜잭션에서 binding을 `DELETING`으로 전환하고 DELETE operation을 저장한다.
5. Worker가 DELETE lease를 획득한다.
6. K3s adapter가 저장된 Namespace UID를 검증한 후 리소스를 삭제한다.
7. 한 트랜잭션에서 binding을 `DELETED`, operation을 `SUCCEEDED`로 변경한다.

삭제 실패가 retryable이면 같은 operation을 backoff 후 재시도한다. 영구 오류 또는 최대 시도 도달 시 operation은 `FAILED`가 되며 binding은 재시도 또는 운영 조치를 위해 `DELETING`으로 유지한다.

## 9. 오류와 재시도

- 요청 형식과 isolation 정책 오류는 enqueue 전에 반환한다.
- target 없음, binding mismatch 및 request id 충돌은 영구 오류다.
- 일시적 K3s API, 네트워크 및 DB 오류는 제한 재시도한다.
- operation 조회 시 DB 오류를 `not found`로 바꾸지 않는다.
- TTL 삭제 enqueue 실패를 조용히 무시하지 않는다. Scheduler mock이 동일 request id로 재시도할 수 있어야 한다.
- 마지막 오류 code는 저장하되 내부 오류 문자열과 Secret은 API에 노출하지 않는다.

## 10. 통합 순서와 충돌 방지

1. `origin/dev`에서 로컬 `integration/provisioner-mvp`를 만든다.
2. `feat/web-pwn-isolation-profiles`의 격리 변경을 먼저 반영한다.
3. 로컬 NodePort `externalTrafficPolicy: Cluster` 수정과 테스트를 함께 반영한다.
4. `feat/10-service-auth`를 그 위에 반영하고 OpenAPI·문서·HTTP 테스트 충돌을 현재 계약 기준으로 해소한다.
5. PR #35를 merge 또는 전체 cherry-pick하지 않는다.
6. PR #35의 PostgreSQL schema, claim, lease, retry 개념을 현재 `operations`, `runtimeops`, `runtimebinding` 구조로 다시 구현한다.
7. 실행 설정과 migration을 추가하고 memory/PostgreSQL 구성을 선택 가능하게 한다.
8. API/OpenAPI 예제와 `test_ctf` 요청 계약을 최종 형태로 맞춘다.

각 기능은 의미 단위 커밋으로 나누되 최종 원격에는 통합 브랜치 하나와 `dev` 대상 Draft PR 하나만 만든다.

## 11. 이후 검증 계획

이번 설계 단계에서는 테스트를 실행하지 않는다. 구현이 끝난 뒤 다음 순서로 검증한다.

1. 포맷, 정적 분석, 전체 단위 테스트
2. 실제 PostgreSQL에서 enqueue, idempotency, lease 회수 및 재시작 테스트
3. 500개 동시 요청 적재와 제한 worker 처리 테스트
4. Scheduler/Broker mock을 사용한 생성·조회·삭제·TTL 흐름
5. 실제 K3s에서 WEB 단일·다중 컨테이너 및 PWN gVisor smoke test
6. Namespace, NetworkPolicy, 자원 제한, egress, writable path와 삭제 후 잔존 리소스 확인

AWS와 GCP 교차 검증은 로컬 통합이 안정화된 다음 단계에서 같은 체크리스트로 수행한다.

## 12. 완료 기준

- 하나의 Provisioner 프로세스가 PostgreSQL과 실제 K3s target registry를 함께 사용해 기동된다.
- 모든 내부 API가 서비스 인증 없이는 호출되지 않는다.
- 생성·삭제가 비동기 operation으로 적재되고 프로세스 재시작 후 복구된다.
- 동일 request는 멱등 처리되고 다른 payload 재사용은 거부된다.
- `WEB`과 `PWN`이 동일 baseline 위에서 각 프로필 차이만 적용한다.
- PWN은 gVisor capability가 없는 target에서 생성되지 않는다.
- Scheduler mock의 TTL 삭제가 일반 DELETE operation과 같은 worker 경로를 사용한다.
- 다중 공개 포트 결과가 endpoint 목록으로 반환된다.
- 로컬 검증이 모두 통과한 뒤에만 원격 통합 브랜치와 `dev` 대상 Draft PR을 만든다.
