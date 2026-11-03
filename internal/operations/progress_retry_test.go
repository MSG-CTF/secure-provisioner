package operations

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestNormalCleanupProgressUsesBoundedDelayAndRetainsOwnership(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want time.Duration
	}{
		{"progress", fmt.Errorf("wrapped: %w", NewProgressPendingError("GATEWAY_WORKLOAD_DELETE_PENDING", nil)), time.Second},
		{"gateway admission busy", NewProgressPendingError("GATEWAY_LIFECYCLE_BUSY", nil), time.Second},
		{"remote fault", NewHeldExecutionError("GATEWAY_UNAVAILABLE", errors.New("connection failed")), 32 * time.Second},
		{"pending text without typed progress", NewHeldExecutionError("GATEWAY_WORKLOAD_DELETE_PENDING", errors.New("forbidden")), 32 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryStore(sequenceIDs("pending-op"))
			op, _, err := store.EnqueueDelete(validDeleteCommand("request"), 1)
			if err != nil {
				t.Fatal(err)
			}
			claimed, ok, err := store.Claim(context.Background(), ClaimOptions{WorkerID: "test", Now: time.Now().UTC(), LeaseDuration: time.Minute})
			if err != nil || !ok {
				t.Fatal(claimed, ok, err)
			}
			worker, err := NewWorker(store, &scriptedExecutor{results: []execution{{err: test.err}}}, WorkerConfig{Concurrency: 1, WorkerID: "test", PollInterval: time.Millisecond, LeaseDuration: time.Minute, RenewInterval: time.Second, Backoff: func(int) time.Duration { return 32 * time.Second }})
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			if err := worker.processLeased(context.Background(), claimed); err != nil {
				t.Fatal(err)
			}
			got, err := store.Get(op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != OperationStatusRetrying || got.Result.DeleteCompleted {
				t.Fatalf("cleanup lost ownership or reported premature success: %#v", got)
			}
			delay := got.NextRetryAt.Sub(before)
			if delay < test.want || delay > test.want+time.Second {
				t.Fatalf("retry delay=%s want %s", delay, test.want)
			}
		})
	}
}

func TestLegacyCleanupProgressAndFailureUseDifferentDelays(t *testing.T) {
	for _, pending := range []bool{true, false} {
		store := NewMemoryStore(sequenceIDs("legacy"))
		op, _, err := store.EnqueueDelete(validDeleteCommand("request"), 1)
		if err != nil {
			t.Fatal(err)
		}
		var failure error = NewHeldExecutionError("GATEWAY_UNAVAILABLE", nil)
		want := 32 * time.Second
		if pending {
			failure = NewProgressPendingError("GATEWAY_WORKLOAD_STOP_PENDING", nil)
			want = time.Second
		}
		var delay time.Duration
		worker, err := NewWorker(store, &scriptedExecutor{results: []execution{{err: failure}}}, WorkerConfig{Concurrency: 1, Backoff: func(int) time.Duration { return 32 * time.Second }, Sleep: func(_ context.Context, d time.Duration) error { delay = d; return nil }})
		if err != nil {
			t.Fatal(err)
		}
		if err := worker.process(context.Background(), op); err != nil {
			t.Fatal(err)
		}
		got, _ := store.Get(op.ID)
		if delay != want || got.Status != OperationStatusQueued || got.Result.DeleteCompleted {
			t.Fatalf("pending=%v delay=%s status=%s", pending, delay, got.Status)
		}
	}
}
