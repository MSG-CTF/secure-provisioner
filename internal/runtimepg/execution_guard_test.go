package runtimepg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func claimExecution(t *testing.T, store *OperationStore, owner string, now time.Time) operations.ClaimedOperation {
	t.Helper()
	claimed, ok, err := store.Claim(t.Context(), operations.ClaimOptions{WorkerID: owner, Now: now, LeaseDuration: time.Minute})
	if err != nil || !ok {
		t.Fatalf("claim %s: ok=%t err=%v", owner, ok, err)
	}
	return claimed
}

func TestPostgresExecutionGuardExcludesExpiredLiveExecutionAndLeavesAPIConnectionsFree(t *testing.T) {
	database := openTestDatabase(t)
	// A held execution must not use the main pool or prevent status reads.
	database.db.SetMaxOpenConns(1)
	store := database.Operations()
	op, _, err := store.EnqueueCreate(validResolvedPwnCommand(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first := claimExecution(t, store, "old-worker", now)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err = store.WithLeaseExecution(ctx, first, func(ctx context.Context, guarded operations.ClaimedOperation) error {
		if !guarded.Operation.CreateCleanupFenced {
			t.Fatal("first execution did not record its protocol")
		}
		if got, err := store.Get(op.ID); err != nil || got.Status != operations.OperationStatusRunning {
			t.Fatalf("status read while executing: %+v %v", got, err)
		}
		// Advance the claimant clock beyond the old lease without stopping its
		// execution: a second worker must skip it, not overlap its side effects.
		if got, ok, err := store.Claim(ctx, operations.ClaimOptions{WorkerID: "other-worker", Now: now.Add(2 * time.Minute), LeaseDuration: time.Minute}); err != nil || ok {
			t.Fatalf("live execution reclaimed: %+v ok=%t err=%v", got, ok, err)
		}
		otherCommand := validResolvedPwnCommand(t)
		otherCommand.RequestID += "-independent"
		otherCommand.InstanceID = "22222222-2222-4222-8222-222222222222"
		other, _, err := store.EnqueueCreate(otherCommand, 4)
		if err != nil {
			t.Fatal(err)
		}
		independent := claimExecution(t, store, "independent-worker", now.Add(2*time.Minute))
		if independent.Operation.ID != other.ID {
			t.Fatal("locked execution blocked an unrelated queued operation")
		}
		if _, err := store.MarkLeaseFailed(independent, operations.Failure{Code: "ISOLATED_TEST"}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if err := store.WithLeaseExecution(ctx, first, func(context.Context, operations.ClaimedOperation) error {
			t.Error("overlapping executor ran")
			return nil
		}); !errors.Is(err, operations.ErrExecutionBusy) {
			t.Fatalf("overlapping guard = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	second := claimExecution(t, store, "new-worker", now.Add(2*time.Minute))
	if second.Operation.ID != op.ID || !second.Operation.CreateLeaseReclaimed {
		t.Fatalf("restart did not reclaim the original operation: %+v", second)
	}
	called := false
	if err := store.WithLeaseExecution(ctx, first, func(context.Context, operations.ClaimedOperation) error { called = true; return nil }); !errors.Is(err, operations.ErrLeaseLost) || called {
		t.Fatalf("stale claimant reached executor: called=%t err=%v", called, err)
	}
}

func TestPostgresReclaimedCleanupProofRequiresGuardedFirstAttempt(t *testing.T) {
	for _, guardedFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "guarded"}[guardedFirst], func(t *testing.T) {
			database := openTestDatabase(t)
			store := database.Operations()
			op, _, err := store.EnqueueCreate(validResolvedPwnCommand(t), 4)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			first := claimExecution(t, store, "before-restart", now)
			if guardedFirst {
				if err := store.WithLeaseExecution(t.Context(), first, func(context.Context, operations.ClaimedOperation) error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			// Leave the row RUNNING, like a process exiting before completion.
			second := claimExecution(t, store, "after-restart", now.Add(2*time.Minute))
			if err := store.WithLeaseExecution(t.Context(), second, func(_ context.Context, guarded operations.ClaimedOperation) error {
				if guarded.Operation.CreateCleanupFenced != guardedFirst {
					t.Fatalf("legacy execution upgraded to trusted proof: %+v", guarded.Operation)
				}
				_, err := store.MarkLeaseFailed(guarded, operations.Failure{Code: "RESOURCE_APPLY_FAILED", CreateCleanupCompleted: true}, time.Now().UTC())
				return err
			}); err != nil {
				t.Fatal(err)
			}
			got, err := (&OperationStore{db: database.db}).Get(op.ID)
			if err != nil || got.Result.CreateCleanupCompleted != guardedFirst || got.Status != operations.OperationStatusFailed {
				t.Fatalf("persisted proof: %+v %v", got, err)
			}
			if got.CreateCleanupFenced {
				t.Fatal("transient execution capability escaped the guard")
			}
		})
	}
}

type confirmedRollbackExecutor struct{}

func (confirmedRollbackExecutor) Execute(context.Context, operations.Operation) (operations.OperationResult, error) {
	return operations.OperationResult{}, provisioner.WithCreateCleanupCompleted(operations.NewExecutionError("RESOURCE_APPLY_FAILED", false, nil))
}

func TestPostgresWorkerPublishesConfirmedReclaimedRollback(t *testing.T) {
	database := openTestDatabase(t)
	store := database.Operations()
	op, _, err := store.EnqueueCreate(validResolvedPwnCommand(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	first := claimExecution(t, store, "crashed-worker", time.Now().UTC())
	if err := store.WithLeaseExecution(t.Context(), first, func(context.Context, operations.ClaimedOperation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE runtime_operations SET lease_until=clock_timestamp()-interval '1 second' WHERE operation_id=$1`, op.ID); err != nil {
		t.Fatal(err)
	}
	worker, err := operations.NewWorker(store, confirmedRollbackExecutor{}, operations.WorkerConfig{Concurrency: 2, WorkerID: "restarted-worker", PollInterval: time.Millisecond * 10, LeaseDuration: time.Minute, RenewInterval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	var got operations.Operation
	for ctx.Err() == nil {
		got, err = store.Get(op.ID)
		if err != nil || got.Status == operations.OperationStatusFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if runErr := <-done; runErr != nil {
		t.Fatal(runErr)
	}
	if err != nil || !got.Result.CreateCleanupCompleted || !got.CreateLeaseReclaimed || got.Attempt != 2 {
		t.Fatalf("worker did not publish reclaimed rollback proof: %+v %v", got, err)
	}
}

func TestPostgresExecutionGuardCancelsExecutorWhenLockConnectionDies(t *testing.T) {
	database := openTestDatabase(t)
	store := database.Operations()
	op, _, err := store.EnqueueCreate(validResolvedPwnCommand(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	first := claimExecution(t, store, "worker", time.Now().UTC())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var executionCancelled bool
	err = store.WithLeaseExecution(ctx, first, func(executeCtx context.Context, _ operations.ClaimedOperation) error {
		var killed bool
		if err := database.db.QueryRowContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_locks
			WHERE locktype='advisory' AND granted AND objsubid=1
			AND classid=((hashtextextended($1,83)>>32)&4294967295)::oid
			AND objid=(hashtextextended($1,83)&4294967295)::oid`, op.ID).Scan(&killed); err != nil || !killed {
			t.Fatalf("terminate isolated guard backend: killed=%t err=%v", killed, err)
		}
		<-executeCtx.Done()
		executionCancelled = ctx.Err() == nil
		return executeCtx.Err()
	})
	if err == nil || !executionCancelled {
		t.Fatalf("lost lock did not cancel executor: cancelled=%t err=%v", executionCancelled, err)
	}
	got, err := store.Get(op.ID)
	if err != nil || got.Result.CreateCleanupCompleted {
		t.Fatalf("lost guard manufactured cleanup proof: %+v %v", got, err)
	}
}
