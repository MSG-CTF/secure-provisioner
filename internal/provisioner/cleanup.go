package provisioner

// WithCreateCleanupCompleted is used only after the resources created by this
// attempt have been deleted and their absence has been confirmed by the runtime.
// A failed create, a missing binding, or an accepted delete is not that proof.
func WithCreateCleanupCompleted(cause error) error {
	return &createCleanupCompletedError{cause: cause}
}

type createCleanupCompletedError struct{ cause error }

func (e *createCleanupCompletedError) Error() string                { return e.cause.Error() }
func (e *createCleanupCompletedError) Unwrap() error                { return e.cause }
func (e *createCleanupCompletedError) CreateCleanupCompleted() bool { return true }

// CreateCleanup records the exact namespace generation created by the attempt.
// Retrying this work must finish deleting it, never start another create.
type CreateCleanup struct {
	RuntimeWorkloadID string
	NamespaceUID      string
	FailureCode       string
}

func WithCreateCleanupPending(cause error, target CreateCleanup) error {
	return &createCleanupPendingError{cause: cause, target: target}
}

type createCleanupPendingError struct {
	cause  error
	target CreateCleanup
}

func (e *createCleanupPendingError) Error() string                       { return e.cause.Error() }
func (e *createCleanupPendingError) Unwrap() error                       { return e.cause }
func (e *createCleanupPendingError) PendingCreateCleanup() CreateCleanup { return e.target }
