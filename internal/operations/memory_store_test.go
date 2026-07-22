package operations

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestMemoryStoreDeduplicatesSameRequest(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1", "op-2"))
	command := validCreateCommand("req-1")

	first, created, err := store.EnqueueCreate(command, 3)
	if err != nil || !created {
		t.Fatalf("first enqueue: %#v %v %v", first, created, err)
	}
	second, created, err := store.EnqueueCreate(command, 3)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("duplicate enqueue: %#v %v %v", second, created, err)
	}
}

func TestMemoryStoreRejectsIdempotencyConflict(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	command := validCreateCommand("req-1")
	if _, _, err := store.EnqueueCreate(command, 3); err != nil {
		t.Fatal(err)
	}

	command.Image = "different:tag"
	if _, _, err := store.EnqueueCreate(command, 3); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestMemoryStoreConcurrentDuplicateCreatesOneOperation(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1", "op-2"))
	command := validCreateCommand("req-1")

	const callers = 32
	operations := make(chan Operation, callers)
	created := make(chan bool, callers)
	errs := make(chan error, callers)
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	for range callers {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			operation, wasCreated, err := store.EnqueueCreate(command, 3)
			operations <- operation
			created <- wasCreated
			errs <- err
		}()
	}
	start.Done()
	done.Wait()
	close(operations)
	close(created)
	close(errs)

	createdCount := 0
	for wasCreated := range created {
		if wasCreated {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created %d operations, want 1", createdCount)
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for operation := range operations {
		if operation.ID != "op-1" {
			t.Fatalf("got operation %#v", operation)
		}
	}
}

func TestMemoryStoreNextIsFIFOAndHonorsCancellation(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1", "op-2"))
	first, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 3)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.EnqueueCreate(validCreateCommand("req-2"), 3)
	if err != nil {
		t.Fatal(err)
	}

	next, err := store.Next(context.Background())
	if err != nil || next.ID != first.ID {
		t.Fatalf("first next: %#v %v", next, err)
	}
	next, err = store.Next(context.Background())
	if err != nil || next.ID != second.ID {
		t.Fatalf("second next: %#v %v", next, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = store.Next(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestMemoryStoreDeliversQueuedOperationsToAllWaitingWorkers(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1", "op-2"))
	ctx := newWaitingContext(2)
	type nextResult struct {
		operation Operation
		err       error
	}
	results := make(chan nextResult, 2)
	for range 2 {
		go func() {
			operation, err := store.Next(ctx)
			results <- nextResult{operation: operation, err: err}
		}()
	}
	ctx.waitForWaiters(t)

	// A capacity-one channel holds one signal after two consecutive non-blocking
	// notifications. Populate both operations before releasing that coalesced signal.
	store.mu.Lock()
	_, created, err := store.enqueueCreate(validCreateCommand("req-1"), 3)
	if err != nil || !created {
		store.mu.Unlock()
		t.Fatalf("first enqueue: %v %v", created, err)
	}
	_, created, err = store.enqueueCreate(validCreateCommand("req-2"), 3)
	store.mu.Unlock()
	if err != nil || !created {
		t.Fatalf("second enqueue: %v %v", created, err)
	}
	store.notify()

	seen := make(map[string]bool)
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatal(result.err)
			}
			seen[result.operation.ID] = true
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for queued operation")
		}
	}
	if !seen["op-1"] || !seen["op-2"] {
		t.Fatalf("got operations %#v", seen)
	}
}

func TestMemoryStoreTransitionsAndReturnsCopies(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	original, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.MarkRunning(next.ID)
	if err != nil || running.Attempt != 1 || running.Status != OperationStatusRunning {
		t.Fatalf("running: %#v %v", running, err)
	}
	result := OperationResult{Create: &provisioner.CreateWorkloadResult{RuntimeWorkloadID: "default/inst-1", ServiceURL: "http://service.example"}}
	succeeded, err := store.MarkSucceeded(next.ID, result)
	if err != nil || succeeded.Status != OperationStatusSucceeded {
		t.Fatalf("succeeded: %#v %v", succeeded, err)
	}

	original.Status = OperationStatusFailed
	original.CreateCommand.Image = "mutated:tag"
	succeeded.Result.Create.ServiceURL = "http://mutated.example"
	stored, err := store.Get(next.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != OperationStatusSucceeded || stored.CreateCommand.Image != "nginx:1.27" || stored.Result.Create.ServiceURL != "http://service.example" {
		t.Fatalf("store leaked mutable state: %#v", stored)
	}
}

func TestMemoryStoreRejectsInvalidTransition(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSucceeded(operation.ID, OperationResult{}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("queued to succeeded: got %v", err)
	}
	if _, err := store.MarkRunning(operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRunning(operation.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("running to running: got %v", err)
	}
}

func TestMemoryStoreRequeueMakesCancelledOperationAvailable(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRunning(operation.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Requeue(operation.ID); err != nil {
		t.Fatal(err)
	}

	next, err := store.Next(context.Background())
	if err != nil || next.ID != operation.ID || next.Status != OperationStatusQueued {
		t.Fatalf("requeued next: %#v %v", next, err)
	}
}

func TestMemoryStoreRequeueRestoresClaimedQueuedOperationWithoutDuplicate(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Requeue(operation.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Requeue(operation.ID); err != nil {
		t.Fatal(err)
	}
	next, err := store.Next(context.Background())
	if err != nil || next.ID != operation.ID {
		t.Fatalf("requeued next: %#v %v", next, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("duplicate queued operation: %v", err)
	}
}

func TestMemoryStoreStoresStableErrorCodes(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	operation, _, err := store.EnqueueCreate(validCreateCommand("req-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRunning(operation.ID); err != nil {
		t.Fatal(err)
	}
	retrying, err := store.MarkRetrying(operation.ID, "TARGET_TEMPORARILY_UNAVAILABLE")
	if err != nil || retrying.Status != OperationStatusRetrying || retrying.LastErrorCode != "TARGET_TEMPORARILY_UNAVAILABLE" {
		t.Fatalf("retrying: %#v %v", retrying, err)
	}
	if err := store.Requeue(operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRunning(operation.ID); err != nil {
		t.Fatal(err)
	}
	failed, err := store.MarkFailed(operation.ID, "RUNTIME_NOT_FOUND")
	if err != nil || failed.Status != OperationStatusFailed || failed.LastErrorCode != "RUNTIME_NOT_FOUND" {
		t.Fatalf("failed: %#v %v", failed, err)
	}
}

func TestMemoryStoreNormalizesUnsafeErrorCodes(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1", "op-2"))
	unsafeCode := "https://user:secret@cluster.example/runtime"

	retrying := enqueueAndStart(t, store, "req-1")
	updated, err := store.MarkRetrying(retrying.ID, unsafeCode)
	if err != nil || updated.LastErrorCode != defaultExecutionErrorCode {
		t.Fatalf("retrying: %#v %v", updated, err)
	}

	failed := enqueueAndStart(t, store, "req-2")
	updated, err = store.MarkFailed(failed.ID, unsafeCode)
	if err != nil || updated.LastErrorCode != defaultExecutionErrorCode {
		t.Fatalf("failed: %#v %v", updated, err)
	}
}

func TestMemoryStoreReturnsNotFoundForUnknownOperation(t *testing.T) {
	store := NewMemoryStore(sequenceIDs("op-1"))
	if _, err := store.Get("missing"); !errors.Is(err, ErrOperationNotFound) {
		t.Fatalf("got %v", err)
	}
}

func validCreateCommand(requestID string) provisioner.CreateWorkloadCommand {
	return provisioner.CreateWorkloadCommand{
		RequestID: requestID, InstanceID: "inst-1", TeamID: 7,
		RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "target-1", Image: "nginx:1.27", ContainerPort: 8080,
		ResourceLimits: provisioner.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 256},
	}
}

func enqueueAndStart(t *testing.T, store *MemoryStore, requestID string) Operation {
	t.Helper()
	operation, _, err := store.EnqueueCreate(validCreateCommand(requestID), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRunning(operation.ID); err != nil {
		t.Fatal(err)
	}
	return operation
}

type waitingContext struct {
	context.Context
	done    chan struct{}
	waiters chan struct{}
}

func newWaitingContext(waiterCount int) *waitingContext {
	return &waitingContext{
		Context: context.Background(),
		done:    make(chan struct{}),
		waiters: make(chan struct{}, waiterCount),
	}
}

func (c *waitingContext) Done() <-chan struct{} {
	c.waiters <- struct{}{}
	return c.done
}

func (c *waitingContext) waitForWaiters(t *testing.T) {
	t.Helper()
	for range cap(c.waiters) {
		select {
		case <-c.waiters:
		case <-time.After(time.Second):
			t.Fatal("worker did not enter Next wait path")
		}
	}
}

func sequenceIDs(ids ...string) IDGenerator {
	var mu sync.Mutex
	index := 0
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if index == len(ids) {
			return "", fmt.Errorf("no more IDs")
		}
		id := ids[index]
		index++
		return id, nil
	}
}
