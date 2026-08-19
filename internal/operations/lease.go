package operations

import (
	"errors"
	"time"
)

var ErrLeaseLost = errors.New("operation lease lost")

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
