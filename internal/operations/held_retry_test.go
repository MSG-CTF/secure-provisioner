package operations

import (
	"testing"
	"time"
)

func TestHeldRemoteCleanupSurvivesAttemptBudget(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("held-op"))
	op, _, err := store.EnqueueDelete(validDeleteCommand("held-request"), 1)
	if err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: []execution{{err: NewHeldExecutionError("GATEWAY_DELETE_PENDING", nil)}, {result: successfulDeleteResult()}}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, WorkerID: "held", PollInterval: time.Millisecond, LeaseDuration: time.Second, RenewInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, worker, store, op.ID)
	got, err := store.Get(op.ID)
	if err != nil || got.Status != OperationStatusSucceeded || got.Attempt != 2 {
		t.Fatal(got, err)
	}
}
