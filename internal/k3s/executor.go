package k3s

import (
	"context"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type CreateAdapter interface {
	CreateWorkload(context.Context, provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error)
}

type Executor struct {
	adapter CreateAdapter
}

func NewExecutor(adapter CreateAdapter) (*Executor, error) {
	if adapter == nil {
		return nil, errors.New("create adapter is required")
	}
	return &Executor{adapter: adapter}, nil
}

func (e *Executor) Execute(ctx context.Context, operation operations.Operation) (operations.OperationResult, error) {
	if operation.Type != operations.OperationTypeCreate || operation.CreateCommand == nil {
		return operations.OperationResult{}, operations.NewExecutionError("UNSUPPORTED_OPERATION", false, nil)
	}

	result, err := e.adapter.CreateWorkload(ctx, *operation.CreateCommand)
	if err != nil {
		var runtimeErr *RuntimeError
		if errors.As(err, &runtimeErr) {
			return operations.OperationResult{}, operations.NewExecutionError(runtimeErr.Code(), runtimeErr.Retryable(), err)
		}
		return operations.OperationResult{}, operations.NewExecutionError("EXECUTION_FAILED", false, err)
	}
	return operations.OperationResult{Create: &result}, nil
}
