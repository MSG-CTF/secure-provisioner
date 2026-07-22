package operations

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrInvalidWorkerConfig = errors.New("invalid worker configuration")

type BackoffFunc func(attempt int) time.Duration

type SleepFunc func(context.Context, time.Duration) error

type WorkerConfig struct {
	Concurrency int
	Backoff     BackoffFunc
	Sleep       SleepFunc
}

type Worker struct {
	store       Store
	executor    RuntimeExecutor
	concurrency int
	backoff     BackoffFunc
	sleep       SleepFunc
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
	return &Worker{
		store:       store,
		executor:    executor,
		concurrency: config.Concurrency,
		backoff:     config.Backoff,
		sleep:       config.Sleep,
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidWorkerConfig
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
				operation, err := w.store.Next(workCtx)
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

func (w *Worker) process(ctx context.Context, operation Operation) error {
	if ctx.Err() != nil {
		return w.store.Requeue(operation.ID)
	}
	running, err := w.store.MarkRunning(operation.ID)
	if err != nil {
		return err
	}
	result, err := w.executor.Execute(ctx, running)
	if err == nil {
		_, err = w.store.MarkSucceeded(running.ID, result)
		return err
	}
	if ctx.Err() != nil && isContextError(err) {
		return w.store.Requeue(running.ID)
	}
	code, retryable := ClassifyExecutionError(err)
	if !retryable || running.Attempt >= running.MaxAttempts {
		_, markErr := w.store.MarkFailed(running.ID, code)
		return markErr
	}
	if _, err := w.store.MarkRetrying(running.ID, code); err != nil {
		return err
	}
	if err := w.sleep(ctx, w.backoff(running.Attempt)); err != nil {
		if ctx.Err() != nil && isContextError(err) {
			return w.store.Requeue(running.ID)
		}
		return err
	}
	return w.store.Requeue(running.ID)
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
