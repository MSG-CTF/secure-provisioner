package k3s

import (
	"context"

	"k8s.io/client-go/util/flowcontrol"
)

// This transport-level condition deliberately carries no cleanup ownership or
// retry policy. Create, readiness and resize requests share the same limiter.
// Only the delete adapter may turn it into held cleanup progress.
type lifecycleBudgetError struct{ cause error }

func (err *lifecycleBudgetError) Error() string { return "KUBERNETES_API_BUDGET_BUSY" }
func (err *lifecycleBudgetError) Unwrap() error { return err.cause }

// Only failures returned by the local limiter enter this path: the HTTP
// request has not been sent. Server errors and transport timeouts never do.
type lifecycleRateLimiter struct{ flowcontrol.RateLimiter }

func (limiter *lifecycleRateLimiter) Wait(ctx context.Context) error {
	err := limiter.RateLimiter.Wait(ctx)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return &lifecycleBudgetError{cause: err}
}
