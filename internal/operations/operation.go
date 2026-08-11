package operations

import (
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
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
	ID               string
	RequestID        string
	Type             OperationType
	Status           OperationStatus
	CreateCommand    *provisioner.CreateWorkloadCommand
	DeleteCommand    *provisioner.DeleteWorkloadCommand
	CreateCheckpoint *provisioner.CreateWorkloadResult
	Attempt          int
	MaxAttempts      int
	Result           OperationResult
	LastErrorCode    string
}

func validCreateWorkloadResult(result provisioner.CreateWorkloadResult) bool {
	return strings.TrimSpace(result.RuntimeWorkloadID) != "" && strings.TrimSpace(result.NamespaceUID) != ""
}

func copyCreateWorkloadResult(result provisioner.CreateWorkloadResult) provisioner.CreateWorkloadResult {
	copied := result
	copied.Endpoints = slices.Clone(result.Endpoints)
	return copied
}

func sameCreateWorkloadResult(first, second provisioner.CreateWorkloadResult) bool {
	return reflect.DeepEqual(first, second)
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
	copied.PolicyRequest = copyPolicyRequest(command.PolicyRequest)
	copied.Policy = copyResolvedPolicy(command.Policy)
	return copied
}

func sameCreateCommand(first, second provisioner.CreateWorkloadCommand) bool {
	if first.RequestID != second.RequestID ||
		first.InstanceID != second.InstanceID ||
		first.TeamID != second.TeamID ||
		first.ChallengeRef != second.ChallengeRef ||
		first.RuntimeType != second.RuntimeType ||
		first.TargetID != second.TargetID ||
		first.ResourceLimits != second.ResourceLimits ||
		!reflect.DeepEqual(first.PolicyRequest, second.PolicyRequest) ||
		!reflect.DeepEqual(first.Policy, second.Policy) ||
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

func copyPolicyRequest(request isolation.Request) isolation.Request {
	copied := request
	copied.Containers = copyContainerRequirements(request.Containers)
	copied.InternalConnections = append([]isolation.InternalConnection(nil), request.InternalConnections...)
	return copied
}

func copyResolvedPolicy(policy isolation.ResolvedPolicy) isolation.ResolvedPolicy {
	copied := policy
	copied.Containers = copyContainerRequirements(policy.Containers)
	copied.InternalConnections = append([]isolation.InternalConnection(nil), policy.InternalConnections...)
	return copied
}

func copyContainerRequirements(containers []isolation.ContainerRequirement) []isolation.ContainerRequirement {
	if containers == nil {
		return nil
	}
	copied := make([]isolation.ContainerRequirement, len(containers))
	for index, container := range containers {
		copied[index] = container
		copied[index].Ports = slices.Clone(container.Ports)
		copied[index].WritablePaths = slices.Clone(container.WritablePaths)
	}
	return copied
}

func validateOperation(id, requestID string, maxAttempts int) error {
	if id == "" || requestID == "" || maxAttempts <= 0 {
		return ErrInvalidOperation
	}
	return nil
}
