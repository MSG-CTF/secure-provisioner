package operations

import (
	"context"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

var (
	ErrOperationNotFound      = errors.New("operation not found")
	ErrIdempotencyConflict    = errors.New("idempotency conflict")
	ErrOperationIDConflict    = errors.New("operation ID conflict")
	ErrInvalidTransition      = errors.New("invalid operation transition")
	ErrInvalidOperationResult = errors.New("invalid operation result")
)

type Store interface {
	EnqueueCreate(provisioner.CreateWorkloadCommand, int) (Operation, bool, error)
	EnqueueDelete(provisioner.DeleteWorkloadCommand, int) (Operation, bool, error)
	Next(context.Context) (Operation, error)
	Get(string) (Operation, error)
	MarkRunning(string) (Operation, error)
	MarkRetrying(string, string) (Operation, error)
	Requeue(string) error
	MarkSucceeded(string, OperationResult) (Operation, error)
	MarkFailed(string, string) (Operation, error)
}

type IDGenerator func() (string, error)
