package operations

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrInvalidWorkerConfig = errors.New("invalid worker configuration")

const invalidOperationResultErrorCode = "INVALID_OPERATION_RESULT"

type BackoffFunc func(attempt int) time.Duration

type SleepFunc func(context.Context, time.Duration) error

type WorkerConfig struct {
	Concurrency   int
	Backoff       BackoffFunc
	Sleep         SleepFunc
	PollInterval  time.Duration
	LeaseDuration time.Duration
	RenewInterval time.Duration
	WorkerID      string
}

type Worker struct {
	store         Store
	legacyStore   LegacyStore
	executor      RuntimeExecutor
	concurrency   int
	backoff       BackoffFunc
	sleep         SleepFunc
	leaseStore    LeaseStore
	pollInterval  time.Duration
	leaseDuration time.Duration
	renewInterval time.Duration
	workerID      string
}

func NewWorker(store Store, executor RuntimeExecutor, config WorkerConfig) (*Worker, error) {
	if store == nil || executor == nil || config.Concurrency <= 0 {
		return nil, ErrInvalidWorkerConfig
	}
	if config.Backoff == nil {
		config.Backoff = func(int) time.Duration { return 0 }
	}
	if config.Sleep == nil {
		config.Sleep = sleepContext
	}
	var leaseStore LeaseStore
	var legacyStore LegacyStore
	if config.WorkerID != "" {
		var ok bool
		leaseStore, ok = store.(LeaseStore)
		if !ok || config.PollInterval <= 0 || config.LeaseDuration <= 0 || config.RenewInterval <= 0 || config.RenewInterval >= config.LeaseDuration {
			return nil, ErrInvalidWorkerConfig
		}
	} else {
		var ok bool
		legacyStore, ok = store.(LegacyStore)
		if !ok {
			return nil, ErrInvalidWorkerConfig
		}
	}
	return &Worker{
		store:         store,
		legacyStore:   legacyStore,
		executor:      executor,
		concurrency:   config.Concurrency,
		backoff:       config.Backoff,
		sleep:         config.Sleep,
		leaseStore:    leaseStore,
		pollInterval:  config.PollInterval,
		leaseDuration: config.LeaseDuration,
		renewInterval: config.RenewInterval,
		workerID:      config.WorkerID,
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidWorkerConfig
	}
	if w.leaseStore != nil {
		return w.runLeased(ctx)
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var workers sync.WaitGroup
	var errorOnce sync.Once
	var firstErr error
	recordError := func(err error) {
		if err == nil {
			return
		}
		errorOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	for range w.concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				if workCtx.Err() != nil {
					return
				}
				operation, err := w.legacyStore.Next(workCtx)
				if err != nil {
					if isContextError(err) {
						return
					}
					recordError(err)
					return
				}
				if err := w.process(workCtx, operation); err != nil {
					recordError(err)
					return
				}
				if workCtx.Err() != nil {
					return
				}
			}
		}()
	}
	workers.Wait()
	return firstErr
}

func (w *Worker) runLeased(ctx context.Context) error {
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	var errorOnce sync.Once
	var firstErr error
	recordError := func(err error) {
		if err == nil {
			return
		}
		errorOnce.Do(func() { firstErr = err; cancel() })
	}
	for index := range w.concurrency {
		workers.Add(1)
		go func(workerIndex int) {
			defer workers.Done()
			workerID := fmt.Sprintf("%s-%d", w.workerID, workerIndex+1)
			for workCtx.Err() == nil {
				claimed, ok, err := w.leaseStore.Claim(workCtx, ClaimOptions{WorkerID: workerID, Now: time.Now().UTC(), LeaseDuration: w.leaseDuration})
				if err != nil {
					if !isContextError(err) {
						recordError(err)
					}
					return
				}
				if !ok {
					if err := sleepContext(workCtx, w.pollInterval); err != nil {
						return
					}
					continue
				}
				if err := w.processLeased(workCtx, claimed); err != nil {
					recordError(err)
					return
				}
			}
		}(index)
	}
	workers.Wait()
	return firstErr
}

func (w *Worker) processLeased(ctx context.Context, claimed ClaimedOperation) error {
	executeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRenewal := make(chan struct{})
	renewalDone := make(chan error, 1)
	go func() { renewalDone <- w.renewLease(executeCtx, claimed, stopRenewal, cancel) }()
	result, executeErr := w.executeLeased(executeCtx, claimed)
	close(stopRenewal)
	if renewalErr := <-renewalDone; renewalErr != nil {
		_ = w.leaseStore.ReleaseLease(claimed, time.Now().UTC())
		return renewalErr
	}
	now := time.Now().UTC()
	if executeErr == nil {
		_, err := w.leaseStore.MarkLeaseSucceeded(claimed, result, now)
		if errors.Is(err, ErrInvalidOperationResult) {
			_, err = w.leaseStore.MarkLeaseFailed(claimed, invalidOperationResultErrorCode, now)
		}
		return err
	}
	if errors.Is(executeErr, ErrInvalidOperationResult) {
		_, err := w.leaseStore.MarkLeaseFailed(claimed, invalidOperationResultErrorCode, now)
		return err
	}
	if ctx.Err() != nil && isContextError(executeErr) {
		return w.leaseStore.ReleaseLease(claimed, now)
	}
	code, retryable := ClassifyExecutionError(executeErr)
	if !retryable || claimed.Operation.Attempt >= claimed.Operation.MaxAttempts {
		_, err := w.leaseStore.MarkLeaseFailed(claimed, code, now)
		return err
	}
	_, err := w.leaseStore.MarkLeaseRetrying(claimed, code, now.Add(w.backoff(claimed.Operation.Attempt)), now)
	return err
}

func (w *Worker) renewLease(ctx context.Context, claimed ClaimedOperation, stop <-chan struct{}, cancel context.CancelFunc) error {
	ticker := time.NewTicker(w.renewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-stop:
			return nil
		case now := <-ticker.C:
			if _, err := w.leaseStore.RenewLease(ctx, claimed, now.UTC().Add(w.leaseDuration)); err != nil {
				cancel()
				return err
			}
		}
	}
}

func (w *Worker) executeLeased(ctx context.Context, claimed ClaimedOperation) (OperationResult, error) {
	operation := claimed.Operation
	if operation.Type != OperationTypeCreate {
		return w.executor.Execute(ctx, operation)
	}
	if operation.CreateCheckpoint == nil {
		result, err := w.executor.Execute(ctx, operation)
		if err != nil {
			return OperationResult{}, err
		}
		if !operationResultMatchesType(OperationTypeCreate, result) {
			return OperationResult{}, ErrInvalidOperationResult
		}
		updated, err := w.leaseStore.CheckpointLeaseCreateResult(claimed, *result.Create, time.Now().UTC())
		if err != nil {
			return OperationResult{}, err
		}
		operation = updated.Operation
	}
	if operation.CreateCheckpoint == nil {
		return OperationResult{}, ErrInvalidOperationResult
	}
	createResult := copyCreateWorkloadResult(*operation.CreateCheckpoint)
	result := OperationResult{Create: &createResult}
	if finalizer, ok := w.executor.(CreateResultFinalizer); ok {
		if err := finalizer.FinalizeCreate(ctx, operation, copyCreateWorkloadResult(createResult)); err != nil {
			return result, err
		}
	}
	return result, ctx.Err()
}

func (w *Worker) process(ctx context.Context, operation Operation) error {
	if ctx.Err() != nil {
		return w.legacyStore.Requeue(operation.ID)
	}
	running, err := w.legacyStore.MarkRunning(operation.ID)
	if err != nil {
		return err
	}
	result, err := w.execute(ctx, running)
	if err == nil {
		_, err = w.legacyStore.MarkSucceeded(running.ID, result)
		if errors.Is(err, ErrInvalidOperationResult) {
			_, err = w.legacyStore.MarkFailed(running.ID, invalidOperationResultErrorCode)
		}
		return err
	}
	if errors.Is(err, ErrInvalidOperationResult) {
		_, err = w.legacyStore.MarkFailed(running.ID, invalidOperationResultErrorCode)
		return err
	}
	if ctx.Err() != nil && isContextError(err) {
		return w.legacyStore.Requeue(running.ID)
	}
	code, retryable := ClassifyExecutionError(err)
	if !retryable || running.Attempt >= running.MaxAttempts {
		_, markErr := w.legacyStore.MarkFailed(running.ID, code)
		return markErr
	}
	if _, err := w.legacyStore.MarkRetrying(running.ID, code); err != nil {
		return err
	}
	if err := w.sleep(ctx, w.backoff(running.Attempt)); err != nil {
		if ctx.Err() != nil && isContextError(err) {
			return w.legacyStore.Requeue(running.ID)
		}
		return err
	}
	return w.legacyStore.Requeue(running.ID)
}

func (w *Worker) execute(ctx context.Context, running Operation) (OperationResult, error) {
	if running.Type != OperationTypeCreate {
		return w.executor.Execute(ctx, running)
	}

	checkpointed := running
	if checkpointed.CreateCheckpoint == nil {
		result, err := w.executor.Execute(ctx, running)
		if err != nil {
			return OperationResult{}, err
		}
		if !operationResultMatchesType(OperationTypeCreate, result) {
			return OperationResult{}, ErrInvalidOperationResult
		}
		checkpointed, err = w.legacyStore.CheckpointCreateResult(running.ID, *result.Create)
		if err != nil {
			return OperationResult{}, err
		}
	}
	if checkpointed.CreateCheckpoint == nil {
		return OperationResult{}, ErrInvalidOperationResult
	}
	createResult := copyCreateWorkloadResult(*checkpointed.CreateCheckpoint)
	result := OperationResult{Create: &createResult}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if finalizer, ok := w.executor.(CreateResultFinalizer); ok {
		finalizerResult := copyCreateWorkloadResult(createResult)
		if err := finalizer.FinalizeCreate(ctx, checkpointed, finalizerResult); err != nil {
			return result, err
		}
	}
	return result, nil
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
