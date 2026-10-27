package operations

import (
	"context"
	"errors"
	"time"
)

var ErrLeaseLost = errors.New("operation lease lost")
var ErrExecutionBusy = errors.New("operation execution is still active")

// LeaseExecutionGuard excludes older external executions, beyond DB lease fencing.
type LeaseExecutionGuard interface {
	WithLeaseExecution(context.Context, ClaimedOperation, func(context.Context, ClaimedOperation) error) error
}

type Lease struct {
	Owner   string
	Version int64
	Until   time.Time
}

type ClaimOptions struct {
	WorkerID      string
	Now           time.Time
	LeaseDuration time.Duration
}

type ClaimedOperation struct {
	Operation Operation
	Lease     Lease
}
