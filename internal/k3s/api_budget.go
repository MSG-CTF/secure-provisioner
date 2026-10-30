package k3s

import (
	"context"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"k8s.io/client-go/util/flowcontrol"
)

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
	return operations.NewProgressPendingError("KUBERNETES_API_BUDGET_BUSY", err)
}
