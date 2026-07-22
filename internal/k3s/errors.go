package k3s

type RuntimeError struct {
	code      string
	retryable bool
	cause     error
}

func (e *RuntimeError) Error() string {
	return e.code
}

func (e *RuntimeError) Unwrap() error {
	return e.cause
}

func (e *RuntimeError) Code() string {
	return e.code
}

func (e *RuntimeError) Retryable() bool {
	return e.retryable
}

func newRuntimeError(code string, retryable bool, cause error) *RuntimeError {
	return &RuntimeError{code: code, retryable: retryable, cause: cause}
}
