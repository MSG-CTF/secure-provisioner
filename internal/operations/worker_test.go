package operations

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestWorkerExecutesAndStoresSuccess(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 3)
	if err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: []execution{{result: OperationResult{Create: &provisioner.CreateWorkloadResult{RuntimeWorkloadID: "default/inst-1", NamespaceUID: "namespace-uid-01", ServiceURL: "http://service.example"}}}}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, worker, store, operation.ID)
	stored, err := store.Get(operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != OperationStatusSucceeded || stored.Attempt != 1 || stored.Result.Create == nil {
		t.Fatalf("stored: %#v", stored)
	}
}

func TestWorkerExecutesDeleteAndStoresSuccess(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueDelete(validDeleteCommand("req-1"), 3)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorker(store, &scriptedExecutor{results: []execution{{result: successfulDeleteResult()}}}, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, worker, store, operation.ID)
	stored, err := store.Get(operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != OperationStatusSucceeded || stored.Attempt != 1 || stored.Result.Create != nil || !stored.Result.DeleteCompleted {
		t.Fatalf("stored: %#v", stored)
	}
}

func TestWorkerFailsInvalidSuccessResultAndContinues(t *testing.T) {
	testCases := []struct {
		name          string
		operationType OperationType
		invalidResult OperationResult
		validResult   OperationResult
	}{
		{name: "create empty result", operationType: OperationTypeCreate, validResult: successfulCreateResult()},
		{name: "create delete result", operationType: OperationTypeCreate, invalidResult: successfulDeleteResult(), validResult: successfulCreateResult()},
		{name: "delete create result", operationType: OperationTypeDelete, invalidResult: successfulCreateResult(), validResult: successfulDeleteResult()},
		{name: "delete incomplete result", operationType: OperationTypeDelete, validResult: successfulDeleteResult()},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store := NewMemoryStore(sequenceIDs("op-1", "op-2"))
			first := enqueueOperation(t, store, testCase.operationType, "req-1")
			second := enqueueOperation(t, store, testCase.operationType, "req-2")
			worker, err := NewWorker(store, &scriptedExecutor{results: []execution{
				{result: testCase.invalidResult},
				{result: testCase.validResult},
			}}, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- worker.Run(ctx) }()
			waitForTerminalOperations(t, store, 2)
			cancel()
			if err := receiveRun(t, done); err != nil {
				t.Fatal(err)
			}

			failed, err := store.Get(first.ID)
			if err != nil || failed.Status != OperationStatusFailed || failed.LastErrorCode != "INVALID_OPERATION_RESULT" {
				t.Fatalf("failed operation: %#v %v", failed, err)
			}
			succeeded, err := store.Get(second.ID)
			if err != nil || succeeded.Status != OperationStatusSucceeded {
				t.Fatalf("following operation: %#v %v", succeeded, err)
			}
		})
	}
}

func TestWorkerRetriesOnlyRetryableErrors(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 3)
	if err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: []execution{
		{err: NewExecutionError("RUNTIME_TIMEOUT", true, errors.New("secret endpoint"))},
		{err: NewExecutionError("RUNTIME_TIMEOUT", true, errors.New("secret endpoint"))},
		{result: successfulCreateResult()},
	}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, worker, store, operation.ID)
	stored, _ := store.Get(operation.ID)
	if stored.Status != OperationStatusSucceeded || stored.Attempt != 3 || stored.Result.Create == nil {
		t.Fatalf("stored: %#v", stored)
	}
}

func TestWorkerStopsAtMaxAttempts(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: []execution{
		{err: NewExecutionError("RUNTIME_TIMEOUT", true, errors.New("secret endpoint"))},
		{err: NewExecutionError("RUNTIME_TIMEOUT", true, errors.New("secret endpoint"))},
	}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, worker, store, operation.ID)
	stored, _ := store.Get(operation.ID)
	if stored.Status != OperationStatusFailed || stored.Attempt != 2 || stored.LastErrorCode != "RUNTIME_TIMEOUT" {
		t.Fatalf("stored: %#v", stored)
	}
}

func TestWorkerDoesNotRetryPermanentError(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 3)
	if err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: []execution{{err: NewExecutionError("TARGET_NOT_FOUND", false, errors.New("secret endpoint"))}}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, worker, store, operation.ID)
	stored, _ := store.Get(operation.ID)
	if stored.Status != OperationStatusFailed || stored.Attempt != 1 || stored.LastErrorCode != "TARGET_NOT_FOUND" {
		t.Fatalf("stored: %#v", stored)
	}
}

func TestWorkerStoresStableCodeWithoutRawCause(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: []execution{{err: NewExecutionError("RUNTIME_TIMEOUT", true, errors.New("secret endpoint"))}}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, worker, store, operation.ID)
	stored, _ := store.Get(operation.ID)
	if stored.LastErrorCode != "RUNTIME_TIMEOUT" || stored.LastErrorCode == "secret endpoint" {
		t.Fatalf("stored raw cause: %#v", stored)
	}
}

func TestWorkerNeverExceedsConfiguredConcurrency(t *testing.T) {
	const operationCount = 5
	store := NewMemoryStore(sequenceIDs("op-1", "op-2", "op-3", "op-4", "op-5"))
	for i := 0; i < operationCount; i++ {
		if _, _, err := store.EnqueueCreate(validCreateCommand(string(rune('a'+i))), 1); err != nil {
			t.Fatal(err)
		}
	}
	executor := newBlockingExecutor()
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 2, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	executor.waitForStarted(t, 2)
	if max := executor.maxInFlight(); max > 2 {
		t.Fatalf("maximum concurrent executions = %d, want <= 2", max)
	}
	executor.release()
	waitForTerminalOperations(t, store, operationCount)
	cancel()
	if err := receiveRun(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerCancellationRequeuesInFlightOperation(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	executor := newCancellationExecutor()
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	executor.waitForStarted(t, 1)
	cancel()
	if err := receiveRun(t, done); err != nil {
		t.Fatal(err)
	}
	stored, _ := store.Get(operation.ID)
	if stored.Status != OperationStatusQueued {
		t.Fatalf("stored: %#v", stored)
	}
	next, err := store.Next(context.Background())
	if err != nil || next.ID != operation.ID {
		t.Fatalf("requeued next: %#v %v", next, err)
	}
}

func TestWorkerCancellationDoesNotConsumeAttemptBeforeRestart(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	cancelledExecutor := newCancellationExecutor()
	firstWorker, err := NewWorker(store, cancelledExecutor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- firstWorker.Run(ctx) }()
	cancelledExecutor.waitForStarted(t, 1)
	cancel()
	if err := receiveRun(t, firstDone); err != nil {
		t.Fatal(err)
	}

	secondWorker, err := NewWorker(store, &scriptedExecutor{results: []execution{{result: successfulCreateResult()}}}, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, secondWorker, store, operation.ID)
	stored, err := store.Get(operation.ID)
	if err != nil || stored.Status != OperationStatusSucceeded || stored.Attempt != 1 || stored.Attempt > stored.MaxAttempts || stored.Result.Create == nil {
		t.Fatalf("stored after restart: %#v %v", stored, err)
	}
}

func TestWorkerCancellationAfterNextRequeuesClaimedOperation(t *testing.T) {
	memoryStore := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := memoryStore.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	store := &cancellingNextStore{Store: memoryStore, cancel: cancel}
	worker, err := NewWorker(store, &scriptedExecutor{}, WorkerConfig{Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(ctx); err != nil {
		t.Fatal(err)
	}
	type nextResult struct {
		operation Operation
		err       error
	}
	nextResultC := make(chan nextResult, 1)
	go func() {
		next, err := memoryStore.Next(context.Background())
		nextResultC <- nextResult{operation: next, err: err}
	}()
	select {
	case result := <-nextResultC:
		if result.err != nil || result.operation.ID != operation.ID {
			t.Fatalf("requeued next: %#v %v", result.operation, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("claimed operation was not requeued")
	}
}

func TestWorkerCancellationDuringRetrySleepRequeuesOperation(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	sleepStarted := make(chan struct{})
	sleep := func(ctx context.Context, duration time.Duration) error {
		close(sleepStarted)
		<-ctx.Done()
		return ctx.Err()
	}
	executor := &scriptedExecutor{results: []execution{{err: NewExecutionError("RUNTIME_TIMEOUT", true, errors.New("secret endpoint"))}}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleep})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case <-sleepStarted:
	case <-time.After(time.Second):
		t.Fatal("worker did not enter retry sleep")
	}
	cancel()
	if err := receiveRun(t, done); err != nil {
		t.Fatal(err)
	}
	next, err := store.Next(context.Background())
	if err != nil || next.ID != operation.ID {
		t.Fatalf("requeued next: %#v %v", next, err)
	}
}

func TestWorkerCancellationStopsAllWorkers(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	executor := newCancellationExecutor()
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 3, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	executor.waitForStarted(t, 0)
	cancel()
	if err := receiveRun(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerCancelsExecutorWhenLeaseRenewalFails(t *testing.T) {
	base := NewMemoryStore(sequenceIDs("op-1"))
	if _, _, err := base.EnqueueDelete(validDeleteCommand("request-1"), 4); err != nil {
		t.Fatal(err)
	}
	renewErr := errors.New("renew lease failed")
	store := &failingRenewLeaseStore{MemoryStore: base, err: renewErr}
	executor := newCancellationExecutor()
	worker, err := NewWorker(store, executor, WorkerConfig{
		Concurrency:   1,
		WorkerID:      "worker-a",
		PollInterval:  time.Millisecond,
		LeaseDuration: time.Minute,
		RenewInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- worker.Run(context.Background()) }()
	executor.waitForStarted(t, 1)
	select {
	case err := <-result:
		if !errors.Is(err, renewErr) {
			t.Fatalf("Run() error = %v, want %v", err, renewErr)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after lease renewal failure")
	}
}

func TestWorkerTreatsNextContextErrorAsNormalShutdown(t *testing.T) {
	worker, err := NewWorker(contextErrorStore{}, &scriptedExecutor{}, WorkerConfig{Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
}

func TestWorkerCreateCheckpointResumesFinalizationWithoutSecondExecute(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 3)
	if err != nil {
		t.Fatal(err)
	}
	executor := &checkpointFinalizingExecutor{finalizeErrors: []error{
		NewExecutionError("ROLLBACK_FAILED", true, errors.New("temporary cleanup failure")),
		nil,
	}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}

	first, err := store.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	checkpointed, err := store.Get(operation.ID)
	if err != nil || checkpointed.Status != OperationStatusQueued || checkpointed.CreateCheckpoint == nil || checkpointed.Result.Create != nil {
		t.Fatalf("checkpointed operation = %#v, %v", checkpointed, err)
	}

	second, err := store.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(operation.ID)
	if err != nil || stored.Status != OperationStatusSucceeded || stored.Attempt != 2 || stored.CreateCheckpoint != nil || stored.Result.Create == nil {
		t.Fatalf("stored operation = %#v, %v", stored, err)
	}
	if executeCalls, finalizeCalls := executor.calls(); executeCalls != 1 || finalizeCalls != 2 {
		t.Fatalf("executor calls = %d, finalizer calls = %d; want 1 and 2", executeCalls, finalizeCalls)
	}
}

func TestWorkerRequeuesCheckpointOnCancellationAndResumesWithoutExecute(t *testing.T) {
	memoryStore := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := memoryStore.EnqueueCreate(validCreateCommand("req-1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	store := &checkpointCancelingStore{Store: memoryStore, cancel: cancel}
	executor := &checkpointFinalizingExecutor{}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}

	first, err := store.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(ctx, first); err != nil {
		t.Fatal(err)
	}
	checkpointed, err := store.Get(operation.ID)
	if err != nil || checkpointed.Status != OperationStatusQueued || checkpointed.Attempt != 0 || checkpointed.CreateCheckpoint == nil {
		t.Fatalf("requeued checkpoint = %#v, %v", checkpointed, err)
	}

	second, err := store.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(operation.ID)
	if err != nil || stored.Status != OperationStatusSucceeded || stored.Attempt != 1 {
		t.Fatalf("stored operation = %#v, %v", stored, err)
	}
	if executeCalls, finalizeCalls := executor.calls(); executeCalls != 1 || finalizeCalls != 1 {
		t.Fatalf("executor calls = %d, finalizer calls = %d; want 1 and 1", executeCalls, finalizeCalls)
	}
}

func TestWorkerFinalizesCheckpointWithinRetryPolicy(t *testing.T) {
	for _, test := range []struct {
		name           string
		maxAttempts    int
		finalizeErrors []error
		wantAttempts   int
		wantFinalizes  int
	}{
		{
			name: "retryable stops at max attempts", maxAttempts: 2, wantAttempts: 2, wantFinalizes: 2,
			finalizeErrors: []error{
				NewExecutionError("ROLLBACK_FAILED", true, errors.New("temporary cleanup failure one")),
				NewExecutionError("ROLLBACK_FAILED", true, errors.New("temporary cleanup failure two")),
			},
		},
		{
			name: "nonretryable stops immediately", maxAttempts: 3, wantAttempts: 1, wantFinalizes: 1,
			finalizeErrors: []error{NewExecutionError("RUNTIME_BINDING_SAVE_FAILED", false, errors.New("binding save failed"))},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryStore(sequenceIDs("op-1"))
			operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), test.maxAttempts)
			if err != nil {
				t.Fatal(err)
			}
			executor := &checkpointFinalizingExecutor{finalizeErrors: test.finalizeErrors}
			worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < test.wantAttempts; attempt++ {
				next, nextErr := store.Next(context.Background())
				if nextErr != nil {
					t.Fatal(nextErr)
				}
				if processErr := worker.process(context.Background(), next); processErr != nil {
					t.Fatal(processErr)
				}
			}
			stored, err := store.Get(operation.ID)
			if err != nil || stored.Status != OperationStatusFailed || stored.Attempt != test.wantAttempts ||
				stored.LastErrorCode == "" || stored.CreateCheckpoint == nil || stored.Result.Create != nil {
				t.Fatalf("stored operation = %#v, %v", stored, err)
			}
			if executeCalls, finalizeCalls := executor.calls(); executeCalls != 1 || finalizeCalls != test.wantFinalizes {
				t.Fatalf("executor calls = %d, finalizer calls = %d; want 1 and %d", executeCalls, finalizeCalls, test.wantFinalizes)
			}
		})
	}
}

func TestWorkerCreateCheckpointIsNotSucceededUntilFinalizerCompletes(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	executor := &checkpointFinalizingExecutor{finalizeStarted: make(chan struct{}, 1), releaseFinalize: make(chan struct{})}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- worker.process(context.Background(), next) }()
	select {
	case <-executor.finalizeStarted:
	case <-time.After(time.Second):
		t.Fatal("finalizer did not start")
	}
	running, err := store.Get(operation.ID)
	if err != nil || running.Status != OperationStatusRunning || running.CreateCheckpoint == nil || running.Result.Create != nil {
		t.Fatalf("operation before finalizer completion = %#v, %v", running, err)
	}
	close(executor.releaseFinalize)
	if err := receiveRun(t, done); err != nil {
		t.Fatal(err)
	}
	succeeded, err := store.Get(operation.ID)
	if err != nil || succeeded.Status != OperationStatusSucceeded || succeeded.CreateCheckpoint != nil || succeeded.Result.Create == nil {
		t.Fatalf("operation after finalizer completion = %#v, %v", succeeded, err)
	}
}

func runUntilTerminal(t *testing.T, worker *Worker, store Store, operationID string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	for {
		operation, err := store.Get(operationID)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Status == OperationStatusSucceeded || operation.Status == OperationStatusFailed {
			cancel()
			if err := receiveRun(t, done); err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForTerminalOperations(t *testing.T, store Store, want int) {
	t.Helper()
	timeout := time.After(time.Second)
	for {
		terminal := 0
		for i := 1; i <= want; i++ {
			operation, err := store.Get("op-" + string(rune('0'+i)))
			if err != nil {
				t.Fatal(err)
			}
			if operation.Status == OperationStatusSucceeded || operation.Status == OperationStatusFailed {
				terminal++
			}
		}
		if terminal == want {
			return
		}
		select {
		case <-timeout:
			t.Fatalf("timed out waiting for %d terminal operations", want)
		case <-time.After(time.Millisecond):
		}
	}
}

func receiveRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
		return nil
	}
}

func noBackoff(int) time.Duration { return 0 }

func successfulCreateResult() OperationResult {
	return OperationResult{Create: &provisioner.CreateWorkloadResult{RuntimeWorkloadID: "default/inst-1", NamespaceUID: "namespace-uid-01", ServiceURL: "http://service.example"}}
}

func successfulDeleteResult() OperationResult {
	return OperationResult{DeleteCompleted: true}
}

func enqueueOperation(t *testing.T, store *MemoryStore, operationType OperationType, requestID string) Operation {
	t.Helper()
	if operationType == OperationTypeCreate {
		operation, _, err := store.EnqueueCreate(validCreateCommand(requestID), 2)
		if err != nil {
			t.Fatal(err)
		}
		return operation
	}
	operation, _, err := store.EnqueueDelete(validDeleteCommand(requestID), 2)
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type execution struct {
	result OperationResult
	err    error
}

type scriptedExecutor struct {
	mu      sync.Mutex
	results []execution
}

type checkpointFinalizingExecutor struct {
	mu              sync.Mutex
	executeCalls    int
	finalizeCalls   int
	finalizeErrors  []error
	finalizeStarted chan struct{}
	releaseFinalize chan struct{}
}

func (e *checkpointFinalizingExecutor) Execute(context.Context, Operation) (OperationResult, error) {
	e.mu.Lock()
	e.executeCalls++
	e.mu.Unlock()
	return successfulCreateResult(), nil
}

func (e *checkpointFinalizingExecutor) FinalizeCreate(_ context.Context, _ Operation, _ provisioner.CreateWorkloadResult) error {
	e.mu.Lock()
	e.finalizeCalls++
	var err error
	if len(e.finalizeErrors) > 0 {
		err = e.finalizeErrors[0]
		e.finalizeErrors = e.finalizeErrors[1:]
	}
	e.mu.Unlock()
	if e.finalizeStarted != nil {
		e.finalizeStarted <- struct{}{}
	}
	if e.releaseFinalize != nil {
		<-e.releaseFinalize
	}
	return err
}

func (e *checkpointFinalizingExecutor) calls() (int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.executeCalls, e.finalizeCalls
}

func (e *scriptedExecutor) Execute(context.Context, Operation) (OperationResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.results) == 0 {
		return OperationResult{}, errors.New("unexpected execution")
	}
	result := e.results[0]
	e.results = e.results[1:]
	return result.result, result.err
}

type blockingExecutor struct {
	mu       sync.Mutex
	inFlight int
	max      int
	started  chan struct{}
	releaseC chan struct{}
}

func newBlockingExecutor() *blockingExecutor {
	return &blockingExecutor{started: make(chan struct{}, 5), releaseC: make(chan struct{})}
}

func (e *blockingExecutor) Execute(ctx context.Context, operation Operation) (OperationResult, error) {
	e.mu.Lock()
	e.inFlight++
	if e.inFlight > e.max {
		e.max = e.inFlight
	}
	e.mu.Unlock()
	e.started <- struct{}{}
	select {
	case <-ctx.Done():
	case <-e.releaseC:
	}
	e.mu.Lock()
	e.inFlight--
	e.mu.Unlock()
	return successfulCreateResult(), nil
}

func (e *blockingExecutor) waitForStarted(t *testing.T, want int) {
	t.Helper()
	for range want {
		select {
		case <-e.started:
		case <-time.After(time.Second):
			t.Fatal("executor did not start expected executions")
		}
	}
}

func (e *blockingExecutor) maxInFlight() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.max
}

func (e *blockingExecutor) release() { close(e.releaseC) }

type cancellationExecutor struct{ started chan struct{} }

func newCancellationExecutor() *cancellationExecutor {
	return &cancellationExecutor{started: make(chan struct{}, 1)}
}

func (e *cancellationExecutor) Execute(ctx context.Context, operation Operation) (OperationResult, error) {
	e.started <- struct{}{}
	<-ctx.Done()
	return OperationResult{}, ctx.Err()
}

func (e *cancellationExecutor) waitForStarted(t *testing.T, want int) {
	t.Helper()
	if want == 0 {
		return
	}
	select {
	case <-e.started:
	case <-time.After(time.Second):
		t.Fatal("executor did not start")
	}
}

type contextErrorStore struct{}

type failingRenewLeaseStore struct {
	*MemoryStore
	err error
}

func (store *failingRenewLeaseStore) RenewLease(context.Context, ClaimedOperation, time.Time) (ClaimedOperation, error) {
	return ClaimedOperation{}, store.err
}

func (contextErrorStore) EnqueueCreate(provisioner.CreateWorkloadCommand, int) (Operation, bool, error) {
	return Operation{}, false, errors.New("not implemented")
}

func (contextErrorStore) EnqueueDelete(provisioner.DeleteWorkloadCommand, int) (Operation, bool, error) {
	return Operation{}, false, errors.New("not implemented")
}

func (contextErrorStore) Next(context.Context) (Operation, error) {
	return Operation{}, context.Canceled
}

func (contextErrorStore) Get(string) (Operation, error) {
	return Operation{}, errors.New("not implemented")
}

func (contextErrorStore) GetByRequestID(string) (Operation, error) {
	return Operation{}, errors.New("not implemented")
}

func (contextErrorStore) MarkRunning(string) (Operation, error) {
	return Operation{}, errors.New("not implemented")
}

func (contextErrorStore) CheckpointCreateResult(string, provisioner.CreateWorkloadResult) (Operation, error) {
	return Operation{}, errors.New("not implemented")
}

func (contextErrorStore) MarkRetrying(string, string) (Operation, error) {
	return Operation{}, errors.New("not implemented")
}

func (contextErrorStore) Requeue(string) error { return errors.New("not implemented") }

func (contextErrorStore) MarkSucceeded(string, OperationResult) (Operation, error) {
	return Operation{}, errors.New("not implemented")
}

func (contextErrorStore) MarkFailed(string, string) (Operation, error) {
	return Operation{}, errors.New("not implemented")
}

type cancellingNextStore struct {
	Store
	cancel context.CancelFunc
}

type checkpointCancelingStore struct {
	Store
	cancel context.CancelFunc
}

func (s *checkpointCancelingStore) CheckpointCreateResult(id string, result provisioner.CreateWorkloadResult) (Operation, error) {
	operation, err := s.Store.CheckpointCreateResult(id, result)
	if err == nil {
		s.cancel()
	}
	return operation, err
}

func (s *cancellingNextStore) Next(ctx context.Context) (Operation, error) {
	operation, err := s.Store.Next(ctx)
	if err == nil {
		s.cancel()
	}
	return operation, err
}
