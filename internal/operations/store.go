package operations

import (
	"context"
	"errors"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

var (
	ErrOperationNotFound        = errors.New("operation not found")
	ErrIdempotencyConflict      = errors.New("idempotency conflict")
	ErrOperationIDConflict      = errors.New("operation ID conflict")
	ErrInvalidTransition        = errors.New("invalid operation transition")
	ErrInvalidOperationResult   = errors.New("invalid operation result")
	ErrCreateCheckpointConflict = errors.New("create checkpoint conflict")
)

type Store interface {
	EnqueueCreate(provisioner.CreateWorkloadCommand, int) (Operation, bool, error)
	EnqueueDelete(provisioner.DeleteWorkloadCommand, int) (Operation, bool, error)
	Get(string) (Operation, error)
	GetByRequestID(string) (Operation, error)
}

type LegacyStore interface {
	Store
	Next(context.Context) (Operation, error)
	MarkRunning(string) (Operation, error)
	CheckpointCreateResult(string, provisioner.CreateWorkloadResult) (Operation, error)
	MarkRetrying(string, string) (Operation, error)
	Requeue(string) error
	MarkSucceeded(string, OperationResult) (Operation, error)
	MarkFailed(string, string) (Operation, error)
}

type LeaseStore interface {
	Store
	Claim(context.Context, ClaimOptions) (ClaimedOperation, bool, error)
	RenewLease(context.Context, ClaimedOperation, time.Time) (ClaimedOperation, error)
	CheckpointLeaseCreateResult(ClaimedOperation, provisioner.CreateWorkloadResult, time.Time) (ClaimedOperation, error)
	MarkLeaseRetrying(ClaimedOperation, string, time.Time, time.Time) (Operation, error)
	ReleaseLease(ClaimedOperation, time.Time) error
	MarkLeaseSucceeded(ClaimedOperation, OperationResult, time.Time) (Operation, error)
	MarkLeaseFailed(ClaimedOperation, string, time.Time) (Operation, error)
}

type IDGenerator func() (string, error)
