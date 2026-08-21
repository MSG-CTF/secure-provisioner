package runtimepg

import (
	"encoding/json"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

var errInvalidOperationPayload = errors.New("invalid operation payload")

func encodeOperationCommand(operation operations.Operation) ([]byte, error) {
	switch operation.Type {
	case operations.OperationTypeCreate:
		if operation.CreateCommand == nil {
			return nil, errInvalidOperationPayload
		}
		return json.Marshal(operation.CreateCommand)
	case operations.OperationTypeDelete:
		if operation.DeleteCommand == nil {
			return nil, errInvalidOperationPayload
		}
		return json.Marshal(operation.DeleteCommand)
	default:
		return nil, errInvalidOperationPayload
	}
}

func decodeOperationCommand(operationType operations.OperationType, payload []byte) (operations.Operation, error) {
	switch operationType {
	case operations.OperationTypeCreate:
		var command provisioner.CreateWorkloadCommand
		if err := json.Unmarshal(payload, &command); err != nil {
			return operations.Operation{}, err
		}
		return operations.Operation{RequestID: command.RequestID, Type: operationType, CreateCommand: &command}, nil
	case operations.OperationTypeDelete:
		var command provisioner.DeleteWorkloadCommand
		if err := json.Unmarshal(payload, &command); err != nil {
			return operations.Operation{}, err
		}
		return operations.Operation{RequestID: command.RequestID, Type: operationType, DeleteCommand: &command}, nil
	default:
		return operations.Operation{}, errInvalidOperationPayload
	}
}
