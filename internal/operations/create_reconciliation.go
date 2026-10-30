package operations

import "github.com/MSG-CTF/secure-provisioner/internal/provisioner"

// CreateReconciler returns an accepted create or atomically fences a request that
// has not been accepted. The fence shares the enqueue request_id uniqueness key.
type CreateReconciler interface {
	ReconcileCreate(provisioner.CreateWorkloadCommand, int) (Operation, bool, error)
}

func NewUnacceptedCreateOperation(id string, command provisioner.CreateWorkloadCommand, maxAttempts int) (Operation, error) {
	operation, err := NewCreateOperation(id, command, maxAttempts)
	if err != nil {
		return Operation{}, err
	}
	operation.Status = OperationStatusFailed
	operation.LastErrorCode = "CREATE_NOT_ACCEPTED"
	operation.Result.CreateCleanupCompleted = true
	return operation, nil
}
