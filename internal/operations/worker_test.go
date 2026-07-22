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
	executor := &scriptedExecutor{results: []execution{{result: OperationResult{Create: &provisioner.CreateWorkloadResult{RuntimeWorkloadID: "default/inst-1", ServiceURL: "http://service.example"}}}}}
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

func TestWorkerRetriesOnlyRetryableErrors(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 3)
	if err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: []execution{
		{err: NewExecutionError("RUNTIME_TIMEOUT", true, errors.New("secret endpoint"))},
		{err: NewExecutionError("RUNTIME_TIMEOUT", true, errors.New("secret endpoint"))},
		{result: OperationResult{DeleteCompleted: true}},
	}}
	worker, err := NewWorker(store, executor, WorkerConfig{Concurrency: 1, Backoff: noBackoff, Sleep: sleepWithContext})
	if err != nil {
		t.Fatal(err)
	}
	runUntilTerminal(t, worker, store, operation.ID)
	stored, _ := store.Get(operation.ID)
	if stored.Status != OperationStatusSucceeded || stored.Attempt != 3 {
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

func TestWorkerTreatsNextContextErrorAsNormalShutdown(t *testing.T) {
	worker, err := NewWorker(contextErrorStore{}, &scriptedExecutor{}, WorkerConfig{Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
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
		time.Sleep(time.Millisecond)
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
	return OperationResult{DeleteCompleted: true}, nil
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

func (contextErrorStore) MarkRunning(string) (Operation, error) {
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

func (s *cancellingNextStore) Next(ctx context.Context) (Operation, error) {
	operation, err := s.Store.Next(ctx)
	if err == nil {
		s.cancel()
	}
	return operation, err
}
