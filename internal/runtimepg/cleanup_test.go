package runtimepg

import (
	"context"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestPostgresPersistsCleanupProofAndRejectsReclaimedLeaseProof(t *testing.T) {
	for _, reclaim := range []bool{false, true} {
		database := openTestDatabase(t)
		store := database.Operations()
		op, _, err := store.EnqueueCreate(validResolvedPwnCommand(t), 3)
		if err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := store.Claim(context.Background(), operations.ClaimOptions{WorkerID: "first", Now: time.Unix(100, 0), LeaseDuration: time.Second})
		if err != nil || !ok {
			t.Fatalf("claim: %v", err)
		}
		failure := operations.Failure{Code: "WORKLOAD_NOT_READY", CreateCleanupCompleted: true}
		if reclaim {
			old := claimed
			claimed, ok, err = store.Claim(context.Background(), operations.ClaimOptions{WorkerID: "second", Now: time.Unix(102, 0), LeaseDuration: time.Minute})
			if err != nil || !ok {
				t.Fatalf("reclaim: %v", err)
			}
			if _, err := store.MarkLeaseFailed(old, failure, time.Unix(103, 0)); err != operations.ErrLeaseLost {
				t.Fatalf("stale write: %v", err)
			}
		}
		if _, err := store.MarkLeaseFailed(claimed, failure, time.Unix(103, 0)); err != nil {
			t.Fatal(err)
		}
		// Read from PostgreSQL through a new store, not the in-memory worker result.
		got, err := (&OperationStore{db: database.db}).Get(op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != operations.OperationStatusFailed || got.Result.CreateCleanupCompleted == reclaim || got.CreateLeaseReclaimed != reclaim {
			t.Fatalf("reclaim=%v status=%s proof=%v reclaimed=%v", reclaim, got.Status, got.Result.CreateCleanupCompleted, got.CreateLeaseReclaimed)
		}
	}
}

func TestPostgresRetainsCleanupTargetAcrossRetry(t *testing.T) {
	database := openTestDatabase(t)
	store := database.Operations()
	op, _, err := store.EnqueueCreate(validResolvedPwnCommand(t), 3)
	if err != nil {
		t.Fatal(err)
	}
	claimed, _, _ := store.Claim(context.Background(), operations.ClaimOptions{WorkerID: "first", Now: time.Unix(100, 0), LeaseDuration: time.Minute})
	failure := operations.Failure{Code: "ROLLBACK_FAILED", CreateCleanup: &provisioner.CreateCleanup{NamespaceUID: "created-uid", FailureCode: "WORKLOAD_NOT_READY"}}
	if _, err := store.MarkLeaseRetrying(claimed, failure, time.Unix(102, 0), time.Unix(101, 0)); err != nil {
		t.Fatal(err)
	}
	second, ok, err := (&OperationStore{db: database.db}).Claim(context.Background(), operations.ClaimOptions{WorkerID: "second", Now: time.Unix(103, 0), LeaseDuration: time.Minute})
	if err != nil || !ok || second.Operation.ID != op.ID {
		t.Fatalf("retry claim: %v", err)
	}
	if second.Operation.CreateLeaseReclaimed || second.Operation.Result.CreateCleanup == nil || *second.Operation.Result.CreateCleanup != *failure.CreateCleanup {
		t.Fatal("cleanup checkpoint was not restored")
	}
}
