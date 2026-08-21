package provisioner

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestMemoryStoreClaimsDeleteBeforeCreate(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newMemoryStore()
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

func TestMemoryStoreDoesNotClaimActiveLeaseTwice(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newMemoryStore()
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
		t.Fatalf("second worker claimed active lease %s after %s", second.OperationID, first.OperationID)
	}
}

func TestMemoryStoreReclaimsExpiredLease(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newMemoryStore()
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

func TestMemoryStoreReturnsExistingOperationForRequestID(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newMemoryStore()
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

func TestMemoryStoreRejectsCompletionFromStaleWorker(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newMemoryStore()
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

func memoryTestCreateRequest(index int) CreateRequest {
	return CreateRequest{
		RequestID:     fmt.Sprintf("request-%d", index),
		InstanceID:    fmt.Sprintf("instance-%d", index),
		TeamID:        int64(index),
		ChallengeID:   fmt.Sprintf("challenge-%d", index),
		ClusterID:     "cluster-1",
		ReservationID: fmt.Sprintf("reservation-%d", index),
		CreatedBy:     "test",
		ExpiresAt:     time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC),
	}
}
