package operations

import (
	"context"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

var (
	ErrOperationNotFound   = errors.New("operation not found")
	ErrIdempotencyConflict = errors.New("idempotency conflict")
	ErrInvalidTransition   = errors.New("invalid operation transition")
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
