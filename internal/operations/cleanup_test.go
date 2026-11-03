package operations

import (
	"context"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestWorkerPersistsOnlyConfirmedCreateCleanup(t *testing.T) {
	for _, leased := range []bool{false, true} {
		for _, confirmed := range []bool{false, true} {
			store := NewMemoryStore(sequenceIDs("op-cleanup"))
			op, _, _ := store.EnqueueCreate(validCreateCommand("req-cleanup"), 1)
			var failure error = NewExecutionError("WORKLOAD_NOT_READY", false, nil)
			if confirmed {
				failure = provisioner.WithCreateCleanupCompleted(failure)
			}
			worker, err := NewWorker(store, &scriptedExecutor{results: []execution{{err: failure}}}, WorkerConfig{Concurrency: 1})
			if err != nil {
				t.Fatal(err)
			}
			if leased {
				worker.leaseStore = store
				worker.renewInterval = time.Second
				claimed, _, err := store.Claim(context.Background(), ClaimOptions{WorkerID: "worker", Now: time.Now(), LeaseDuration: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				if err := worker.processLeased(context.Background(), claimed); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := worker.process(context.Background(), op); err != nil {
					t.Fatal(err)
				}
			}
			got, _ := store.Get(op.ID)
			if got.Status != OperationStatusFailed || got.LastErrorCode != "WORKLOAD_NOT_READY" || got.Result.CreateCleanupCompleted != confirmed {
				t.Fatalf("leased=%v confirmed=%v: status=%s code=%s cleanup=%v", leased, confirmed, got.Status, got.LastErrorCode, got.Result.CreateCleanupCompleted)
			}
		}
	}
}

func TestReclaimedCreateLeaseCannotConfirmCleanup(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-cleanup"))
	op, _, _ := store.EnqueueCreate(validCreateCommand("req-cleanup"), 3)
	first, _, _ := store.Claim(context.Background(), ClaimOptions{WorkerID: "first", Now: time.Unix(100, 0), LeaseDuration: time.Second})
	second, _, _ := store.Claim(context.Background(), ClaimOptions{WorkerID: "second", Now: time.Unix(102, 0), LeaseDuration: time.Minute})
	failure := Failure{Code: "WORKLOAD_NOT_READY", CreateCleanupCompleted: true}
	if _, err := store.MarkLeaseFailed(first, failure, time.Unix(103, 0)); err != ErrLeaseLost {
		t.Fatalf("stale lease: %v", err)
	}
	if _, err := store.MarkLeaseFailed(second, failure, time.Unix(103, 0)); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(op.ID)
	if !got.CreateLeaseReclaimed || got.Result.CreateCleanupCompleted {
		t.Fatal("reclaimed create claimed cleanup was complete")
	}
}

type interruptedCleanupExecutor struct {
	cancel context.CancelFunc
}

func TestFencedReclaimedCreateStillRequiresActualCleanupProof(t *testing.T) {
	op := Operation{Type: OperationTypeCreate, CreateLeaseReclaimed: true, CreateCleanupFenced: true}
	unknown := executionFailure(op, NewExecutionError("ROLLBACK_FAILED", false, nil))
	if unknown.Result(op).CreateCleanupCompleted {
		t.Fatal("execution exclusion was used as proof of resource absence")
	}
	confirmed := executionFailure(op, provisioner.WithCreateCleanupCompleted(NewExecutionError("RESOURCE_APPLY_FAILED", false, nil)))
	if !confirmed.Result(op).CreateCleanupCompleted {
		t.Fatal("fenced execution dropped actual rollback proof")
	}
}

func (e interruptedCleanupExecutor) Execute(context.Context, Operation) (OperationResult, error) {
	e.cancel()
	return OperationResult{}, provisioner.WithCreateCleanupPending(
		NewExecutionError("ROLLBACK_FAILED", true, context.Canceled),
		provisioner.CreateCleanup{NamespaceUID: "owned-namespace", FailureCode: "WORKLOAD_NOT_READY"},
	)
}

func TestWorkerRetainsCleanupCheckpointWhenShutdownInterruptsRollback(t *testing.T) {
	for _, leased := range []bool{false, true} {
		store := NewMemoryStore(sequenceIDs("op-interrupted-cleanup"))
		op, _, _ := store.EnqueueCreate(validCreateCommand("req-interrupted-cleanup"), 3)
		ctx, cancel := context.WithCancel(context.Background())
		worker, err := NewWorker(store, interruptedCleanupExecutor{cancel: cancel}, WorkerConfig{Concurrency: 1})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if leased {
			worker.leaseStore = store
			worker.renewInterval = time.Second
			claimed, _, err := store.Claim(ctx, ClaimOptions{WorkerID: "worker", Now: time.Now(), LeaseDuration: time.Minute})
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			err = worker.processLeased(ctx, claimed)
		} else {
			err = worker.process(ctx, op)
		}
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		got, _ := store.Get(op.ID)
		if got.Attempt != 1 || got.Result.CreateCleanup == nil || got.Result.CreateCleanup.NamespaceUID != "owned-namespace" || got.Result.CreateCleanupCompleted {
			t.Fatalf("leased=%v: interrupted rollback lost its cleanup checkpoint", leased)
		}
		if got.Status != OperationStatusQueued && got.Status != OperationStatusRetrying {
			t.Fatalf("leased=%v: cleanup was not queued for retry: %s", leased, got.Status)
		}
	}
}

func TestWorkerShutdownDuringCheckpointedCleanupDoesNotConsumeAttempt(t *testing.T) {
	for _, leased := range []bool{false, true} {
		store := NewMemoryStore(sequenceIDs("op-checkpointed-cleanup"))
		op, _, err := store.EnqueueCreate(validCreateCommand("req-checkpointed-cleanup"), 2)
		if err != nil {
			t.Fatal(err)
		}
		pendingCleanup := provisioner.CreateCleanup{NamespaceUID: "owned-namespace", FailureCode: "WORKLOAD_NOT_READY"}
		firstFailure := provisioner.WithCreateCleanupPending(
			NewExecutionError("ROLLBACK_FAILED", true, nil), pendingCleanup,
		)
		firstWorker, err := NewWorker(store, &scriptedExecutor{results: []execution{{err: firstFailure}}}, WorkerConfig{
			Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext,
		})
		if err != nil {
			t.Fatal(err)
		}
		if leased {
			firstWorker.leaseStore = store
			firstWorker.renewInterval = time.Second
			claimed, ok, err := store.Claim(context.Background(), ClaimOptions{WorkerID: "first", Now: time.Now(), LeaseDuration: time.Minute})
			if err != nil || !ok {
				t.Fatalf("leased=%v first claim: ok=%v err=%v", leased, ok, err)
			}
			err = firstWorker.processLeased(context.Background(), claimed)
		} else {
			err = firstWorker.process(context.Background(), op)
		}
		if err != nil {
			t.Fatal(err)
		}
		checkpointed, err := store.Get(op.ID)
		if err != nil || checkpointed.Attempt != 1 || checkpointed.Result.CreateCleanup == nil {
			t.Fatalf("leased=%v first cleanup checkpoint: %#v err=%v", leased, checkpointed, err)
		}

		for shutdown := range 3 {
			ctx, cancel := context.WithCancel(context.Background())
			worker, err := NewWorker(store, interruptedCleanupExecutor{cancel: cancel}, WorkerConfig{
				Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext,
			})
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			if leased {
				worker.leaseStore = store
				worker.renewInterval = time.Second
				claimed, ok, err := store.Claim(ctx, ClaimOptions{WorkerID: "cleanup", Now: time.Now().Add(time.Second), LeaseDuration: time.Minute})
				if err != nil || !ok {
					cancel()
					t.Fatalf("leased=%v shutdown=%d claim: ok=%v err=%v", leased, shutdown, ok, err)
				}
				err = worker.processLeased(ctx, claimed)
			} else {
				queued, nextErr := store.Next(ctx)
				if nextErr != nil {
					cancel()
					t.Fatal(nextErr)
				}
				err = worker.process(ctx, queued)
			}
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			got, err := store.Get(op.ID)
			if err != nil || got.Status != OperationStatusQueued || got.Attempt != 1 ||
				got.Result.CreateCleanup == nil || got.Result.CreateCleanup.NamespaceUID != "owned-namespace" {
				t.Fatalf("leased=%v shutdown=%d consumed attempt or lost checkpoint: %#v err=%v", leased, shutdown, got, err)
			}
		}
	}
}
