package operations

import (
	"context"
	"errors"
)

const defaultExecutionErrorCode = "EXECUTION_FAILED"

type RuntimeExecutor interface {
	Execute(context.Context, Operation) (OperationResult, error)
}

type ExecutionError struct {
	code      string
	retryable bool
	cause     error
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
