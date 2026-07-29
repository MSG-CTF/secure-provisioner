package operations

import (
	"errors"
	"slices"

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

	commandCopy := copyCreateCommand(command)
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
		return o.CreateCommand != nil && other.CreateCommand != nil && sameCreateCommand(*o.CreateCommand, *other.CreateCommand)
	case OperationTypeDelete:
		return o.DeleteCommand != nil && other.DeleteCommand != nil && *o.DeleteCommand == *other.DeleteCommand
	default:
		return false
	}
}

func copyCreateCommand(command provisioner.CreateWorkloadCommand) provisioner.CreateWorkloadCommand {
	copied := command
	copied.Containers = make([]provisioner.WorkloadContainer, len(command.Containers))
	for index, container := range command.Containers {
		copied.Containers[index] = container
		copied.Containers[index].Ports = slices.Clone(container.Ports)
	}
	return copied
}

func sameCreateCommand(first, second provisioner.CreateWorkloadCommand) bool {
	if first.RequestID != second.RequestID ||
		first.InstanceID != second.InstanceID ||
		first.TeamID != second.TeamID ||
		first.RuntimeType != second.RuntimeType ||
		first.TargetID != second.TargetID ||
		first.ResourceLimits != second.ResourceLimits ||
		len(first.Containers) != len(second.Containers) {
		return false
	}
	for index := range first.Containers {
		firstContainer := first.Containers[index]
		secondContainer := second.Containers[index]
		if firstContainer.Name != secondContainer.Name ||
			firstContainer.Image != secondContainer.Image ||
			firstContainer.Expose != secondContainer.Expose ||
			!slices.Equal(firstContainer.Ports, secondContainer.Ports) {
			return false
		}
	}
	return true
}

func validateOperation(id, requestID string, maxAttempts int) error {
	if id == "" || requestID == "" || maxAttempts <= 0 {
		return ErrInvalidOperation
	}
	return nil
}
