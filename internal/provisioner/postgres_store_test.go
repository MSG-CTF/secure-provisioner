package provisioner

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestPostgresStoreRequestIdempotency(t *testing.T) {
	store := requirePostgresStore(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	request := memoryTestCreateRequest(1)

	first, _, duplicate, err := store.acceptCreate(ctx, request, now)
	if err != nil || duplicate {
		t.Fatalf("first accept: duplicate=%v err=%v", duplicate, err)
	}
	second, _, duplicate, err := store.acceptCreate(ctx, request, now.Add(time.Second))
	if err != nil || !duplicate {
		t.Fatalf("second accept: duplicate=%v err=%v", duplicate, err)
	}
	if first.OperationID != second.OperationID {
		t.Fatalf("operation IDs differ: %s != %s", first.OperationID, second.OperationID)
	}
}

func TestPostgresStoreClaimsEachOperationOnce(t *testing.T) {
	store := requirePostgresStore(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, _, _, err := store.acceptCreate(ctx, memoryTestCreateRequest(1), now)
	if err != nil {
		t.Fatal(err)
	}

	first, ok, err := store.claim(ctx, ClaimOptions{WorkerID: "worker-1", Now: now, LeaseDuration: 3 * time.Minute})
	if err != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, err)
	}
	second, ok, err := store.claim(ctx, ClaimOptions{WorkerID: "worker-2", Now: now.Add(time.Second), LeaseDuration: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("second worker claimed %s after %s", second.OperationID, first.OperationID)
	}
}

func TestPostgresStoreReclaimsExpiredLease(t *testing.T) {
	store := requirePostgresStore(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	operation, _, _, err := store.acceptCreate(ctx, memoryTestCreateRequest(1), now)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.claim(ctx, ClaimOptions{WorkerID: "worker-1", Now: now, LeaseDuration: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	reclaimed, ok, err := store.claim(ctx, ClaimOptions{WorkerID: "worker-2", Now: now.Add(3*time.Minute + time.Nanosecond), LeaseDuration: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || reclaimed.OperationID != operation.OperationID {
		t.Fatalf("reclaimed = %q, want %q", reclaimed.OperationID, operation.OperationID)
	}
}

func TestPostgresStoreClaimsDeleteFirst(t *testing.T) {
	store := requirePostgresStore(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	create, _, _, err := store.acceptCreate(ctx, memoryTestCreateRequest(1), now)
	if err != nil {
		t.Fatal(err)
	}
	deletion, _, _, err := store.acceptDelete(ctx, "delete-1", create.InstanceID, now.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}

	claimed, ok, err := store.claim(ctx, ClaimOptions{WorkerID: "worker-1", Now: now, LeaseDuration: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || claimed.OperationID != deletion.OperationID {
		t.Fatalf("claimed = %q, want delete %q", claimed.OperationID, deletion.OperationID)
	}
}

func TestPostgresStoreRejectsCompletionFromStaleWorker(t *testing.T) {
	store := requirePostgresStore(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	operation, _, _, err := store.acceptCreate(ctx, memoryTestCreateRequest(1), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.claim(ctx, ClaimOptions{WorkerID: "worker-1", Now: now, LeaseDuration: time.Second}); err != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.claim(ctx, ClaimOptions{WorkerID: "worker-2", Now: now.Add(2 * time.Second), LeaseDuration: time.Second}); err != nil || !ok {
		t.Fatalf("reclaim: ok=%v err=%v", ok, err)
	}
	if err := store.finishOperation(operation.OperationID, "worker-1", OperationSucceeded, "", now.Add(3*time.Second)); err == nil {
		t.Fatal("stale worker completed an operation owned by worker-2")
	}
}

func requirePostgresStore(t *testing.T) *postgresStore {
	t.Helper()
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	store, err := NewPostgresStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	if _, err := store.db.ExecContext(context.Background(), "TRUNCATE operations, instances"); err != nil {
		t.Fatal(err)
	}
	return store
}
