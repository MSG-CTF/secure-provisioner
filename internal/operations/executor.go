package operations

import (
	"context"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

const defaultExecutionErrorCode = "EXECUTION_FAILED"

type Failure struct {
	CreateCleanup          *provisioner.CreateCleanup
	Code                   string
	CreateCleanupCompleted bool
}

func executionFailure(operation Operation, err error) Failure {
	code, _ := ClassifyExecutionError(err)
	var cleanup interface{ CreateCleanupCompleted() bool }
	var pending interface {
		PendingCreateCleanup() provisioner.CreateCleanup
	}
	var target *provisioner.CreateCleanup
	if operation.Type == OperationTypeCreate && errors.As(err, &pending) {
		value := pending.PendingCreateCleanup()
		if value.NamespaceUID != "" {
			target = &value
		}
	}
	return Failure{
		CreateCleanup: target,
		Code:          code,
		CreateCleanupCompleted: operation.Type == OperationTypeCreate && createCleanupCanBeConfirmed(operation) &&
			errors.As(err, &cleanup) && cleanup.CreateCleanupCompleted(),
	}
}

func (f Failure) result(operationType OperationType) OperationResult {
	if operationType != OperationTypeCreate {
		return OperationResult{}
	}
	return OperationResult{CreateCleanup: f.CreateCleanup, CreateCleanupCompleted: f.CreateCleanupCompleted}
}

func (f Failure) Result(operation Operation) OperationResult {
	result := f.result(operation.Type)
	result.CreateCleanupCompleted = result.CreateCleanupCompleted && createCleanupCanBeConfirmed(operation)
	return result
}

func createCleanupCanBeConfirmed(operation Operation) bool {
	return !operation.CreateLeaseReclaimed || operation.CreateCleanupFenced
}

type RuntimeExecutor interface {
	Execute(context.Context, Operation) (OperationResult, error)
}

type CreateResultFinalizer interface {
	FinalizeCreate(context.Context, Operation, provisioner.CreateWorkloadResult) error
}

type ExecutionError struct {
	code      string
	retryable bool
	cause     error
}

// HeldExecutionError retains ownership of resources whose remote cleanup or
// mutation is uncertain. Attempt exhaustion is not evidence of absence.
type HeldExecutionError struct{ cause *ExecutionError }

func NewHeldExecutionError(code string, cause error) *HeldExecutionError {
	return &HeldExecutionError{NewExecutionError(code, true, cause)}
}
func (e *HeldExecutionError) Error() string   { return e.cause.Error() }
func (e *HeldExecutionError) Unwrap() error   { return e.cause }
func (e *HeldExecutionError) HoldRetry() bool { return true }
func heldRetry(err error) bool {
	var held interface{ HoldRetry() bool }
	return errors.As(err, &held) && held.HoldRetry()
}

func NewExecutionError(code string, retryable bool, cause error) *ExecutionError {
	if code == "" {
		code = defaultExecutionErrorCode
	}
	return &ExecutionError{code: code, retryable: retryable, cause: cause}
}

func (e *ExecutionError) Error() string {
	return e.code
}

func (e *ExecutionError) Unwrap() error {
	return e.cause
}

func ClassifyExecutionError(err error) (code string, retryable bool) {
	var executionError *ExecutionError
	if errors.As(err, &executionError) {
		return executionError.code, executionError.retryable
	}
	return defaultExecutionErrorCode, false
}

func normalizeStableErrorCode(code string) string {
	if len(code) == 0 || code[0] < 'A' || code[0] > 'Z' {
		return defaultExecutionErrorCode
	}
	for _, character := range code[1:] {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return defaultExecutionErrorCode
		}
	}
	return code
}
