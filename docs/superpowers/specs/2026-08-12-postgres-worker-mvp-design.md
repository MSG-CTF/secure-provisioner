# PostgreSQL Worker MVP Design

## Goal

Secure Provisioner가 최대 500개의 동시 API 요청을 유실 없이 접수하고, PostgreSQL에 영속화된 작업을 제한된 워커 동시성으로 처리하도록 한다. 모든 외부 API·이벤트 JSON 필드는 `snake_case`로 통일하고 `team_id`는 JSON number와 Go `int64`로 표현한다.

## Scope

### Included

- 외부 API 요청·응답·이벤트 payload의 `snake_case` 전환
- `team_id` 타입의 `int64` 전환
- PostgreSQL `instances`, `operations` 테이블과 migration
- `request_id` 기반 멱등성
- DB 기반 작업 선점, lease, 재시도, 재시작 복구
- 삭제 작업의 생성 작업 대비 우선 처리
- 환경변수로 워커 수, lease, polling, 재시도 설정
- Docker Compose 기반 로컬 PostgreSQL
- 500개 동시 API 요청, 멱등성, lease 회수, 재시작 통합 테스트

### Deferred

- 실제 Scheduler 실행을 포함한 E2E
- 다중 K3s 라우팅과 클러스터별 capacity 강제
- Outbox 이벤트 재전송
- Dead Letter 관리 API
- 문제별 격리 프로필 엔진
- 다중 Provisioner replica 부하 테스트
- 운영용 메트릭 대시보드

## API Contract

기존 HTTP 경로는 유지하고 JSON 필드만 전환한다. `camelCase` 호환 계층은 두지 않으며 알 수 없는 필드는 `400 Bad Request`로 거부한다.

```json
{
  "request_id": "req-1001",
  "instance_id": "inst-123",
  "team_id": 101,
  "challenge_id": "web-01",
  "cluster_id": "k3s-01",
  "reservation_id": "rsv-501",
  "created_by": "scheduler",
  "expires_at": "2026-08-12T12:00:00Z"
}
```

성공적으로 접수된 요청은 K3s 완료를 기다리지 않고 `202 Accepted`와 `operation_id`를 반환한다. 같은 `request_id`가 재전송되면 기존 작업을 `duplicate: true`로 반환한다.

## Persistence Model

### instances

- `instance_id`: primary key
- `team_id`: bigint
- `challenge_id`, `cluster_id`, `reservation_id`
- `runtime_workload_id`, `spec_snapshot`
- `phase`, `desired_state`, `generation`
- `security_profile`, `resource_profile`, `network_profile`
- `namespace`, `endpoint`
- `expires_at`, `created_at`, `updated_at`, `ready_at`, `terminated_at`
- `last_error_code`, `last_error_message`

활성 상태의 `(team_id, challenge_id)`는 partial unique index로 제한한다. TTL 스캔을 위해 `(phase, expires_at)` index를 둔다.

### operations

- `operation_id`: primary key
- `request_id`: unique
- `instance_id`: instances foreign key
- `cluster_id`
- `operation_type`: `CREATE` or `DELETE`
- `status`: `PENDING`, `RUNNING`, `RETRY_WAIT`, `SUCCEEDED`, `FAILED`
- `priority`: `DELETE=100`, `CREATE=10`
- `attempt_count`, `max_attempts` (`4`: 최초 1회 + 재시도 3회)
- `next_retry_at`
- `lease_owner`, `lease_until`
- `last_error_code`, `last_error_message`
- `created_at`, `updated_at`, `started_at`, `finished_at`

상태값은 PostgreSQL enum 대신 `TEXT + CHECK`로 강제한다. 워커 선점 조회를 위해 상태·재시도 시각·우선순위·생성 시각 index를 둔다.

## Worker Model

워커는 하나의 트랜잭션에서 `FOR UPDATE SKIP LOCKED`로 처리 가능한 작업 하나를 선택하고 `RUNNING` 및 lease를 기록한다. 삭제를 먼저, 같은 우선순위에서는 생성 시각이 빠른 작업을 먼저 처리한다.

```text
PENDING -> RUNNING -> SUCCEEDED
                   -> RETRY_WAIT -> RUNNING
                   -> FAILED

RUNNING + expired lease -> RUNNING by another worker
```

기본값은 다음과 같다.

- concurrency: 10
- lease: 3 minutes
- poll interval: 200 milliseconds
- maximum retries: 3 (maximum attempts: 4)
- retry backoff: 1 second, 2 seconds, 4 seconds

재시도 가능한 외부 통신·K3s 일시 오류는 `RETRY_WAIT`로 전이한다. 입력·예약 불일치·지원되지 않는 RuntimeClass 같은 영구 오류는 즉시 `FAILED`로 전이한다. 최초 시도 후 최대 3번 재시도하여 총 시도 횟수는 4회다. 프로세스 재시작 후에는 기대 시각을 지난 `PENDING`, `RETRY_WAIT`, lease 만료 `RUNNING`을 다시 처리한다.

## Capacity and Backpressure

API 요청 수와 K3s 동시 작업 수를 분리한다. 500개 요청은 DB에 빠르게 접수하고 실제 K3s 작업은 워커 동시성 10으로 제한한다. 최대 활성 인스턴스 150개 제한은 MVP에서 Scheduler가 소유하고 Provisioner는 예약 일치를 검증한다.

DB 저장에 실패하면 `202`를 반환하지 않는다. DB에 저장된 후 워커 처리가 느려져도 요청은 유실되지 않는다.

## Error Handling

- 요청 검증 실패: `400`
- 인스턴스 ID 충돌: `409`
- DB 접속 불가: `503`
- 정상 작업 접수: `202`
- 영구 작업 오류: 재시도 없이 `FAILED`
- 일시 작업 오류: backoff 후 최대 3회
- 생성 최종 실패: 생성된 Namespace 정리 시도 후 `FAILED`
- 삭제 최종 실패: `DELETE_FAILED`

## Testing

모든 변경은 Go 테스트를 먼저 작성하고 예상한 이유로 실패하는 것을 확인한 뒤 구현한다.

- DTO 직렬화·역직렬화의 `snake_case` 계약 테스트
- `camelCase` 거부 및 `team_id` number 검증
- 동일 `request_id` 멱등성 테스트
- 서로 다른 워커가 같은 작업을 선점하지 않는 통합 테스트
- lease 만료 작업 회수 테스트
- 삭제 우선순위 테스트
- 재시도 시각과 최대 횟수 테스트
- 서비스 재시작 후 미완료 작업 처리 테스트
- 500개 동시 HTTP 요청을 실제 PostgreSQL에 저장하는 부하 테스트
- 전체 `go test ./...`, `go vet ./...`, `go build ./...`

## Success Criteria

- 500개의 서로 다른 유효 요청이 유실 없이 Operation으로 저장된다.
- 중복 `request_id`는 추가 Operation을 만들지 않는다.
- 실제 동시 K3s 호출 수는 설정된 worker concurrency를 초과하지 않는다.
- 재시작·lease 만료 후에도 미완료 작업이 재개된다.
- API payload에 `camelCase` 필드가 남지 않는다.
- 기존 K3s 생성·검증·삭제 테스트가 계속 통과한다.
