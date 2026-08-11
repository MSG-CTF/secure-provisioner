package k3s

import (
	"context"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

type CreateAdapter interface {
	CreateWorkload(context.Context, provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error)
}

type CreateAdapterFinalizer interface {
	FinalizeCreate(context.Context, provisioner.CreateWorkloadCommand, provisioner.CreateWorkloadResult) error
}

type DeleteWorkloadAdapter interface {
	DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error
}

type BindingReader interface {
	Get(string) (runtimebinding.Binding, error)
}

type Executor struct {
	create   CreateAdapter
	delete   DeleteWorkloadAdapter
	bindings BindingReader
}

func NewExecutor(adapter CreateAdapter) (*Executor, error) {
	if adapter == nil {
		return nil, errors.New("create adapter is required")
	}
	return &Executor{create: adapter}, nil
}

func NewExecutorWithDelete(create CreateAdapter, delete DeleteWorkloadAdapter, bindings BindingReader) (*Executor, error) {
	if create == nil || delete == nil || bindings == nil {
		return nil, errors.New("create, delete, and binding adapters are required")
	}
	return &Executor{create: create, delete: delete, bindings: bindings}, nil
}

func (e *Executor) Execute(ctx context.Context, operation operations.Operation) (operations.OperationResult, error) {
	switch operation.Type {
	case operations.OperationTypeCreate:
		if operation.CreateCommand == nil {
			return operations.OperationResult{}, operations.NewExecutionError("UNSUPPORTED_OPERATION", false, nil)
		}
		result, err := e.create.CreateWorkload(ctx, *operation.CreateCommand)
		if err != nil {
			return operations.OperationResult{}, classifyRuntimeExecutionError(err)
		}
		return operations.OperationResult{Create: &result}, nil
	case operations.OperationTypeDelete:
		if operation.DeleteCommand == nil || e.delete == nil || e.bindings == nil {
			return operations.OperationResult{}, operations.NewExecutionError("UNSUPPORTED_OPERATION", false, nil)
		}
		binding, err := e.bindings.Get(operation.DeleteCommand.InstanceID)
		if err != nil {
			if errors.Is(err, runtimebinding.ErrNotFound) {
				return operations.OperationResult{}, operations.NewExecutionError("INSTANCE_NOT_FOUND", false, nil)
			}
			return operations.OperationResult{}, operations.NewExecutionError("EXECUTION_FAILED", false, err)
		}
		if err := e.delete.DeleteWorkload(ctx, *operation.DeleteCommand, binding); err != nil {
			return operations.OperationResult{}, classifyRuntimeExecutionError(err)
		}
		return operations.OperationResult{DeleteCompleted: true}, nil
	default:
		return operations.OperationResult{}, operations.NewExecutionError("UNSUPPORTED_OPERATION", false, nil)
	}
}

func (e *Executor) FinalizeCreate(ctx context.Context, operation operations.Operation, result provisioner.CreateWorkloadResult) error {
	if operation.Type != operations.OperationTypeCreate || operation.CreateCommand == nil {
		return operations.NewExecutionError("UNSUPPORTED_OPERATION", false, nil)
	}
	finalizer, ok := e.create.(CreateAdapterFinalizer)
	if !ok {
		return nil
	}
	if err := finalizer.FinalizeCreate(ctx, *operation.CreateCommand, result); err != nil {
		return classifyRuntimeExecutionError(err)
	}
	return nil
}

func classifyRuntimeExecutionError(err error) error {
	var executionErr *operations.ExecutionError
	if errors.As(err, &executionErr) {
		return executionErr
	}
	var runtimeErr *RuntimeError
	if errors.As(err, &runtimeErr) {
		return operations.NewExecutionError(runtimeErr.Code(), runtimeErr.Retryable(), err)
	}
	return operations.NewExecutionError("EXECUTION_FAILED", false, err)
}
