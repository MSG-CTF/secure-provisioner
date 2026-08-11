# PostgreSQL Worker MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Secure Provisioner가 `snake_case` API 계약으로 500개 동시 요청을 PostgreSQL에 유실 없이 접수하고 lease 기반 워커로 안전하게 처리하게 한다.

**Architecture:** HTTP handler는 요청을 검증한 뒤 `operationStore`의 하나의 트랜잭션으로 Instance와 Operation을 저장하고 즉시 `202` 응답한다. 워커는 PostgreSQL에서 `FOR UPDATE SKIP LOCKED`로 작업을 lease하고, 일시 실패는 `RETRY_WAIT`, 영구 실패는 `FAILED`로 저장한다. 기존 memory store는 빠른 단위 테스트와 Fake mode를 위해 같은 interface로 유지한다.

**Tech Stack:** Go 1.26.5, `database/sql`, `github.com/jackc/pgx/v5/stdlib`, PostgreSQL 17, Docker Compose, Go `testing`/`httptest`.

## Global Constraints

- 외부 API 요청·응답·이벤트 JSON 필드는 예외 없이 `snake_case`를 사용한다.
- Go 식별자는 Go 관례인 `PascalCase`/`camelCase`를 유지한다.
- `team_id`는 JSON number이며 Go 타입은 `int64`다.
- 최대 활성 인스턴스 150개 정책은 Scheduler가 소유하고 Provisioner는 예약 일치를 검증한다.
- 워커 기본값은 concurrency 10, lease 3분, poll 200ms, 최초 1회 + 재시도 3회, backoff 1s/2s/4s다.
- 요청이 DB에 저장되지 않으면 `202 Accepted`를 반환하지 않는다.
- 사용자의 기존 미커밋 변경을 덮어쓰거나 불필요하게 포맷하지 않는다.

---

### Task 1: `snake_case` API 계약과 `team_id` 타입

**Files:**
- Modify: `internal/provisioner/model.go`
- Modify: `internal/provisioner/dependencies.go`
- Modify: `internal/provisioner/http.go`
- Create: `internal/provisioner/http_contract_test.go`
- Modify: `internal/provisioner/kubernetes_cluster_test.go`
- Modify: `internal/provisioner/dashboard_test.go`

**Interfaces:**
- Consumes: 기존 HTTP 경로와 `CreateRequest`, `DeleteRequest`, `AcceptedOperation`, `InstanceView`, `Operation`.
- Produces: `snake_case` JSON tag를 가진 동일 Go 타입들과 `TeamID int64`.

- [ ] **Step 1: 실패하는 API 계약 테스트 작성**

```go
func TestCreateRequestUsesSnakeCaseAndNumericTeamID(t *testing.T) {
    body := `{"request_id":"req-1","instance_id":"inst-1","team_id":101,"challenge_id":"web-1","cluster_id":"k3s-1","reservation_id":"rsv-1","created_by":"scheduler","expires_at":"2030-01-01T00:00:00Z"}`
    var request CreateRequest
    decoder := json.NewDecoder(strings.NewReader(body))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&request); err != nil { t.Fatal(err) }
    if request.TeamID != 101 { t.Fatalf("team_id = %d", request.TeamID) }
}

func TestCreateRequestRejectsCamelCase(t *testing.T) {
    body := `{"requestId":"req-1","instance_id":"inst-1","team_id":101}`
    var request CreateRequest
    decoder := json.NewDecoder(strings.NewReader(body))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&request); err == nil { t.Fatal("camelCase field must be rejected") }
}
```

- [ ] **Step 2: RED 확인**

Run: `go test ./internal/provisioner -run 'TestCreateRequest' -count=1`

Expected: 기존 camelCase tag 또는 `TeamID string`으로 인해 compile/failure.

- [ ] **Step 3: JSON tag와 타입을 최소 변경**

`CreateRequest`, `DeleteRequest`, `InstanceView`, `Operation`, `AcceptedOperation`, `RuntimeResources`, dependency event payload을 `snake_case`로 바꾸고 `TeamID int64`를 적용한다. `decodeJSON` 안의 `DisallowUnknownFields()`를 유지하여 camelCase를 거부한다. Namespace annotation과 환경변수에서는 `strconv.FormatInt(teamID, 10)`으로 문자열화한다.

- [ ] **Step 4: GREEN 및 회귀 테스트**

Run: `go test ./internal/provisioner -count=1`

Expected: PASS.

- [ ] **Step 5: 커밋**

```powershell
git add internal/provisioner
git commit -m "Refactor: API JSON 계약을 snake case로 전환"
```

### Task 2: Store interface와 memory queue 행동

**Files:**
- Create: `internal/provisioner/operation_store.go`
- Rename: `internal/provisioner/store.go` -> `internal/provisioner/memory_store.go`
- Create: `internal/provisioner/memory_store_test.go`
- Modify: `internal/provisioner/service.go`

**Interfaces:**
- Consumes: `Instance`, `Operation`, `CreateRequest`.
- Produces: `operationStore` interface의 `AcceptCreate`, `AcceptDelete`, `Claim`, `Succeed`, `Retry`, `Fail`, `RenewLease`, `GetInstance`, `GetOperation`, `ExpiredInstances`, `Close`.

```go
type ClaimOptions struct {
    WorkerID     string
    Now          time.Time
    LeaseDuration time.Duration
}

type operationStore interface {
    AcceptCreate(context.Context, CreateRequest, time.Time) (Operation, Instance, bool, error)
    AcceptDelete(context.Context, string, string, time.Time) (Operation, Instance, bool, error)
    Claim(context.Context, ClaimOptions) (Operation, bool, error)
    Succeed(context.Context, string, string, time.Time) error
    Retry(context.Context, string, string, time.Time, string, string) error
    Fail(context.Context, string, string, time.Time, string, string) error
    RenewLease(context.Context, string, string, time.Time) error
    GetInstance(context.Context, string) (Instance, error)
    GetOperation(context.Context, string) (Operation, bool, error)
    ExpiredInstances(context.Context, time.Time) ([]string, error)
    Close() error
}
```

- [ ] **Step 1: 우선순위·lease·멱등성 실패 테스트 작성**

```go
func TestMemoryStoreClaimsDeleteBeforeCreate(t *testing.T) {
    ctx := context.Background()
    now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
    store := newMemoryStore()
    create, _, _, err := store.AcceptCreate(ctx, validCreateRequest(1), now)
    if err != nil { t.Fatal(err) }
    deletion, _, _, err := store.AcceptDelete(ctx, "delete-1", create.InstanceID, now.Add(time.Millisecond))
    if err != nil { t.Fatal(err) }
    claimed, ok, err := store.Claim(ctx, ClaimOptions{WorkerID: "worker-1", Now: now, LeaseDuration: 3 * time.Minute})
    if err != nil { t.Fatal(err) }
    if !ok || claimed.OperationID != deletion.OperationID {
        t.Fatalf("claimed = %q, want delete %q", claimed.OperationID, deletion.OperationID)
    }
}

func TestMemoryStoreDoesNotClaimActiveLeaseTwice(t *testing.T) {
    ctx := context.Background()
    now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
    store := newMemoryStore()
    _, _, _, _ = store.AcceptCreate(ctx, validCreateRequest(1), now)
    first, ok, err := store.Claim(ctx, ClaimOptions{WorkerID: "worker-1", Now: now, LeaseDuration: 3 * time.Minute})
    if err != nil || !ok { t.Fatalf("first claim: ok=%v err=%v", ok, err) }
    second, ok, err := store.Claim(ctx, ClaimOptions{WorkerID: "worker-2", Now: now.Add(time.Second), LeaseDuration: 3 * time.Minute})
    if err != nil { t.Fatal(err) }
    if ok { t.Fatalf("second worker claimed active lease: %s after %s", second.OperationID, first.OperationID) }
}

func TestMemoryStoreReclaimsExpiredLease(t *testing.T) {
    ctx := context.Background()
    now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
    store := newMemoryStore()
    operation, _, _, _ := store.AcceptCreate(ctx, validCreateRequest(1), now)
    _, _, _ = store.Claim(ctx, ClaimOptions{WorkerID: "worker-1", Now: now, LeaseDuration: 3 * time.Minute})
    reclaimed, ok, err := store.Claim(ctx, ClaimOptions{WorkerID: "worker-2", Now: now.Add(3*time.Minute + time.Nanosecond), LeaseDuration: 3 * time.Minute})
    if err != nil { t.Fatal(err) }
    if !ok || reclaimed.OperationID != operation.OperationID { t.Fatalf("expired lease was not reclaimed") }
}

func TestMemoryStoreReturnsExistingOperationForRequestID(t *testing.T) {
    ctx := context.Background()
    now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
    store := newMemoryStore()
    first, _, duplicate, err := store.AcceptCreate(ctx, validCreateRequest(1), now)
    if err != nil || duplicate { t.Fatalf("first accept: duplicate=%v err=%v", duplicate, err) }
    second, _, duplicate, err := store.AcceptCreate(ctx, validCreateRequest(1), now.Add(time.Second))
    if err != nil || !duplicate { t.Fatalf("second accept: duplicate=%v err=%v", duplicate, err) }
    if first.OperationID != second.OperationID { t.Fatalf("operation IDs differ: %s != %s", first.OperationID, second.OperationID) }
}
```

- [ ] **Step 2: RED 확인**

Run: `go test ./internal/provisioner -run 'TestMemoryStore' -count=1`

Expected: `Claim`/lease API가 없어 compile failure.

- [ ] **Step 3: Store interface와 memory 구현**

`ClaimOptions{WorkerID string, Now time.Time, LeaseDuration time.Duration}`를 받아 `DELETE` 우선, `created_at` FIFO로 하나를 claim한다. `RUNNING` lease가 만료하면 재선점하고, `RETRY_WAIT`는 `next_retry_at <= now`일 때만 선점한다.

- [ ] **Step 4: Service가 channel 대신 Store claim을 사용하도록 컴파일 경계 정리**

`AcceptCreate`/`AcceptDelete`는 Store에 저장만 하고, worker loop는 poll ticker에서 `Claim`을 호출한다. 실제 재시도 정책은 Task 4에서 적용한다.

- [ ] **Step 5: GREEN 확인**

Run: `go test ./internal/provisioner -count=1`

Expected: PASS.

- [ ] **Step 6: 커밋**

```powershell
git add internal/provisioner
git commit -m "Refactor: 워커 작업 저장소 경계 분리"
```

### Task 3: PostgreSQL schema와 Store

**Files:**
- Create: `internal/provisioner/migrations/001_worker_mvp.sql`
- Create: `internal/provisioner/postgres_store.go`
- Create: `internal/provisioner/postgres_store_test.go`
- Create: `internal/provisioner/postgres_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Consumes: Task 2의 `operationStore`.
- Produces: `NewPostgresStore(ctx context.Context, dsn string) (operationStore, error)`와 embedded migration 실행.

- [ ] **Step 1: PostgreSQL 통합 테스트 helper 작성**

`PROVISIONER_TEST_DATABASE_URL`이 없으면 PostgreSQL 통합 테스트를 skip하고, 있으면 각 테스트 시작 전 `TRUNCATE operations, instances` 후 실제 DB를 사용한다.

```go
func requirePostgresStore(t *testing.T) operationStore {
    dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
    if dsn == "" { t.Skip("PROVISIONER_TEST_DATABASE_URL is not set") }
    store, err := NewPostgresStore(context.Background(), dsn)
    if err != nil { t.Fatal(err) }
    return store
}
```

- [ ] **Step 2: 멱등성·SKIP LOCKED·lease 실패 테스트 작성**

`TestPostgresStoreRequestIdempotency`, `TestPostgresStoreClaimsEachOperationOnce`, `TestPostgresStoreReclaimsExpiredLease`, `TestPostgresStoreClaimsDeleteFirst`를 작성한다.

- [ ] **Step 3: RED 확인**

Run: `$env:PROVISIONER_TEST_DATABASE_URL='postgres://provisioner:provisioner@127.0.0.1:55432/provisioner?sslmode=disable'; go test ./internal/provisioner -run 'TestPostgresStore' -count=1`

Expected: `NewPostgresStore` 미구현으로 compile failure.

- [ ] **Step 4: migration 구현**

`instances`/`operations` 컬럼, CHECK, foreign key, `request_id` unique, 활성 `(team_id, challenge_id)` partial unique, claim/TTL index를 `001_worker_mvp.sql`에 정의한다. `//go:embed migrations/*.sql`로 시작 시 한 번씩 적용한다.

- [ ] **Step 5: pgx `database/sql` Store 구현**

`AcceptCreate`/`AcceptDelete`는 transaction에서 Instance와 Operation을 저장한다. `Claim`은 하나의 statement/transaction에서 `FOR UPDATE SKIP LOCKED`, `priority DESC`, `created_at ASC`로 선점한다. 업데이트는 `lease_owner`가 일치할 때만 성공한다.

- [ ] **Step 6: GREEN 확인**

Run: `$env:PROVISIONER_TEST_DATABASE_URL='postgres://provisioner:provisioner@127.0.0.1:55432/provisioner?sslmode=disable'; go test ./internal/provisioner -run 'TestPostgresStore' -count=1`

Expected: PASS.

- [ ] **Step 7: 커밋**

```powershell
git add go.mod go.sum internal/provisioner
git commit -m "Feat: PostgreSQL 작업 저장소 구현"
```

### Task 4: Lease worker와 재시도 정책

**Files:**
- Modify: `internal/provisioner/service.go`
- Create: `internal/provisioner/worker_test.go`
- Modify: `internal/provisioner/fake_cluster.go`

**Interfaces:**
- Consumes: `operationStore.Claim/Succeed/Retry/Fail/RenewLease`.
- Produces: `WorkerOptions{Concurrency, PollInterval, LeaseDuration, MaximumRetries}`와 일시/영구 오류 분류.

- [ ] **Step 1: 실패하는 워커 행동 테스트 작성**

```go
type concurrencyProbeCluster struct {
    current atomic.Int32
    maximum atomic.Int32
    release <-chan struct{}
}

func (cluster *concurrencyProbeCluster) create(ctx context.Context, _ Instance, _ Challenge, _ Reservation) (RuntimeResources, error) {
    current := cluster.current.Add(1)
    defer cluster.current.Add(-1)
    for current > cluster.maximum.Load() && !cluster.maximum.CompareAndSwap(cluster.maximum.Load(), current) {}
    select {
    case <-ctx.Done(): return RuntimeResources{}, ctx.Err()
    case <-cluster.release: return RuntimeResources{Namespace: "ctf-test"}, nil
    }
}

func TestWorkerNeverExceedsConfiguredConcurrency(t *testing.T) {
    // 50개 CREATE를 등록하고 concurrency=10으로 Start한 뒤 probe.maximum <= 10을 검증한다.
}

func TestWorkerRetriesTemporaryFailureWithBackoff(t *testing.T) {
    // 주입한 clock으로 시간을 1s, 2s, 4s 전진하며 attempt_count=4와 FAILED를 검증한다.
}

func TestWorkerFailsPermanentErrorWithoutRetry(t *testing.T) {
    // reservation mismatch를 반환하고 attempt_count=1, status=FAILED를 검증한다.
}

func TestWorkerRecoversExpiredRunningOperation(t *testing.T) {
    // worker-1이 claim한 작업의 lease를 만료시킨 뒤 worker-2가 같은 operation_id를 완료함을 검증한다.
}
```

- [ ] **Step 2: RED 확인**

Run: `go test ./internal/provisioner -run 'TestWorker' -count=1`

Expected: 현재 worker가 channel/고정 retry를 사용하여 실패.

- [ ] **Step 3: WorkerOptions·worker ID·poll loop 구현**

각 worker에 `hostname-pid-index-random` 형식의 ID를 부여하고 Store에서 하나씩 claim한다. idle일 때만 poll interval을 기다리며 작업 완료 후 즉시 다음 작업을 claim한다.

- [ ] **Step 4: 재시도 분류·backoff 구현**

`permanentOperationError`로 요청/예약/RuntimeClass 오류를 표시한다. 기타 외부 통신 오류는 1s/2s/4s 후 재시도하고 총 4회 시도 후 `FAILED`로 저장한다.

- [ ] **Step 5: GREEN 및 전체 회귀 확인**

Run: `go test ./internal/provisioner -count=1`

Expected: PASS.

- [ ] **Step 6: 커밋**

```powershell
git add internal/provisioner
git commit -m "Feat: lease 기반 워커와 재시도 추가"
```

### Task 5: 실행 설정과 Docker Compose

**Files:**
- Modify: `cmd/provisioner/main.go`
- Modify: `.env.example`
- Modify: `README.md`
- Create: `compose.postgres.yaml`
- Create: `internal/provisioner/postgres_config_test.go`

**Interfaces:**
- Consumes: `NewPostgresStore`, `WorkerOptions`.
- Produces: `PROVISIONER_STORE_MODE`, `PROVISIONER_DATABASE_URL`, `PROVISIONER_WORKERS`, `PROVISIONER_POLL_INTERVAL`, `PROVISIONER_LEASE_DURATION`, `PROVISIONER_MAX_RETRIES`.

- [ ] **Step 1: 설정 parsing 실패 테스트 작성**

`postgres` mode에서 DSN이 없으면 시작 실패, memory mode는 DSN 없이 시작, 음수·0 worker 설정은 기본값 10을 사용하는지 검증한다.

- [ ] **Step 2: RED 확인**

Run: `go test ./internal/provisioner -run 'TestPostgresConfig' -count=1`

Expected: 설정 타입/함수 미구현.

- [ ] **Step 3: 실행 설정 구현**

Fake 개발 호환성을 위해 store mode 기본은 `memory`로 두고, PostgreSQL 워커 테스트/운영은 `PROVISIONER_STORE_MODE=postgres`를 명시한다. postgres mode에서 DB 초기화가 실패하면 프로세스를 종료한다.

- [ ] **Step 4: PostgreSQL Compose 작성**

PostgreSQL 17, host port 55432, database/user/password `provisioner`, healthcheck `pg_isready`, named volume을 정의한다. 로컬 테스트 DSN은 `postgres://provisioner:provisioner@127.0.0.1:55432/provisioner?sslmode=disable`로 고정한다.

- [ ] **Step 5: GREEN 확인**

Run: `go test ./internal/provisioner -run 'TestPostgresConfig' -count=1`

Expected: PASS.

- [ ] **Step 6: 커밋**

```powershell
git add cmd/provisioner/main.go .env.example README.md compose.postgres.yaml internal/provisioner/postgres_config_test.go
git commit -m "Chore: PostgreSQL 워커 실행 환경 추가"
```

### Task 6: 500개 동시 요청 통합 테스트

**Files:**
- Create: `tests/workerload/worker_load_test.go`
- Create: `scripts/test-worker-mvp.ps1`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: PostgreSQL Store, HTTP handler, Fake cluster.
- Produces: 500 concurrent request acceptance/recovery evidence.

- [ ] **Step 1: 실패하는 500-request 테스트 작성**

500개 goroutine이 고유 `request_id`, `instance_id`, `team_id`, `challenge_id`로 `POST /internal/v1/instances`를 호출한다. 모든 응답이 `202`, Operation row가 500개, 중복 테스트에서 row가 1개인지 검증한다.

- [ ] **Step 2: RED 확인**

Run: `$env:PROVISIONER_TEST_DATABASE_URL='postgres://provisioner:provisioner@127.0.0.1:55432/provisioner?sslmode=disable'; go test ./tests/workerload -run TestAccepts500ConcurrentRequests -count=1 -v`

Expected: PostgreSQL/API 연결 구현의 누락 지점에서 실패.

- [ ] **Step 3: 부하 테스트가 통과하는 최소 연결 코드 보완**

API 응답 전 DB commit, connection pool, transaction conflict 처리를 보완한다. DB pool 기본은 max open 30, max idle 10, connection lifetime 30분으로 설정한다.

- [ ] **Step 4: PowerShell 통합 스크립트 작성**

`docker compose -f compose.postgres.yaml up -d --wait`, 테스트 DSN 설정, `go test ./... -count=1`, `go vet ./...`, `go build ./...`를 순서대로 실행하고 실패 코드를 전파한다. DB 삭제는 자동화하지 않아 개발 데이터를 보존한다.

- [ ] **Step 5: GREEN 확인**

Run: `.\scripts\test-worker-mvp.ps1`

Expected: 500-request 테스트 포함 전체 PASS, vet/build exit 0.

- [ ] **Step 6: 커밋**

```powershell
git add tests/workerload scripts/test-worker-mvp.ps1 .gitignore
git commit -m "Test: 500개 동시 워커 요청 검증"
```

### Task 7: 최종 계약·품질 검증

**Files:**
- Verify: `internal/provisioner/*.go`
- Verify: `tests/workerload/worker_load_test.go`
- Verify: `scripts/test-worker-mvp.ps1`

**Interfaces:**
- Consumes: Tasks 1-6의 전체 구현.
- Produces: 전체 테스트·vet·build 검증 결과와 스펙 충족 체크.

- [ ] **Step 1: camelCase 잔존 검사**

Run: `rg -n 'json:"[^"]*[A-Z][^"]*"|"(requestId|instanceId|teamId|challengeId|clusterId|reservationId|operationId|expiresAt)"' --glob '*.go' --glob '*.json' .`

Expected: 외부 계약에 camelCase 0건. 테스트의 거부 입력은 예외.

- [ ] **Step 2: PostgreSQL 포함 전체 검증**

Run: `.\scripts\test-worker-mvp.ps1`

Expected: all tests PASS, `go vet` PASS, `go build` PASS.

- [ ] **Step 3: 설계 충족 점검**

`snake_case`, numeric `team_id`, 500 Operation rows, request idempotency, delete priority, lease recovery, retry 1s/2s/4s, restart recovery, worker concurrency 10을 각 테스트 이름과 결과에 대응시켜 점검한다.

- [ ] **Step 4: 검증 결과 기록**

Run: `git status --short`

Expected: Task 1-6의 의도한 변경 외에 검증 단계가 만든 추가 파일이 없음.
