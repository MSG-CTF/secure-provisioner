package operations

import (
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type OperationType string

const (
	OperationTypeCreate OperationType = "CREATE"
	OperationTypeDelete OperationType = "DELETE"
)

type OperationStatus string

const (
	OperationStatusQueued    OperationStatus = "QUEUED"
	OperationStatusRunning   OperationStatus = "RUNNING"
	OperationStatusRetrying  OperationStatus = "RETRYING"
	OperationStatusSucceeded OperationStatus = "SUCCEEDED"
	OperationStatusFailed    OperationStatus = "FAILED"
)

type OperationResult struct {
	Create          *provisioner.CreateWorkloadResult
	DeleteCompleted bool
}

type Operation struct {
	ID            string
	RequestID     string
	Type          OperationType
	Status        OperationStatus
	CreateCommand *provisioner.CreateWorkloadCommand
	DeleteCommand *provisioner.DeleteWorkloadCommand
	Attempt       int
	MaxAttempts   int
	Result        OperationResult
	LastErrorCode string
}

var ErrInvalidOperation = errors.New("invalid operation")

func NewCreateOperation(id string, command provisioner.CreateWorkloadCommand, maxAttempts int) (Operation, error) {
	if err := validateOperation(id, command.RequestID, maxAttempts); err != nil {
		return Operation{}, err
	}

	commandCopy := command
	return Operation{
		ID:            id,
		RequestID:     command.RequestID,
		Type:          OperationTypeCreate,
		Status:        OperationStatusQueued,
		CreateCommand: &commandCopy,
		MaxAttempts:   maxAttempts,
	}, nil
}

func NewDeleteOperation(id string, command provisioner.DeleteWorkloadCommand, maxAttempts int) (Operation, error) {
	if err := validateOperation(id, command.RequestID, maxAttempts); err != nil {
		return Operation{}, err
	}

	commandCopy := command
	return Operation{
		ID:            id,
		RequestID:     command.RequestID,
		Type:          OperationTypeDelete,
		Status:        OperationStatusQueued,
		DeleteCommand: &commandCopy,
		MaxAttempts:   maxAttempts,
	}, nil
}

func (o Operation) SameRequest(other Operation) bool {
	if o.Type != other.Type || o.RequestID != other.RequestID {
		return false
	}

	switch o.Type {
	case OperationTypeCreate:
		return o.CreateCommand != nil && other.CreateCommand != nil && *o.CreateCommand == *other.CreateCommand
	case OperationTypeDelete:
		return o.DeleteCommand != nil && other.DeleteCommand != nil && *o.DeleteCommand == *other.DeleteCommand
	default:
		return false
	}
}

func validateOperation(id, requestID string, maxAttempts int) error {
	if id == "" || requestID == "" || maxAttempts <= 0 {
		return ErrInvalidOperation
	}
	return nil
}
