package runtimepg

import (
	"encoding/json"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func (store *OperationStore) ReconcileCreate(command provisioner.CreateWorkloadCommand, maxAttempts int) (operations.Operation, bool, error) {
	operation, err := operations.NewUnacceptedCreateOperation(randomOperationID(), command, maxAttempts)
	if err != nil {
		return operations.Operation{}, false, err
	}
	payload, err := encodeOperationCommand(operation)
	if err != nil {
		return operations.Operation{}, false, err
	}
	result, err := json.Marshal(operation.Result)
	if err != nil {
		return operations.Operation{}, false, err
	}
	now := time.Now().UTC()
	// EnqueueCreate uses the same unique request_id. Whichever insert commits
	// first determines whether this request may execute, including across replicas.
	inserted, err := store.db.Exec(`INSERT INTO runtime_operations
		(operation_id,request_id,operation_type,status,priority,command_snapshot,result,
		 attempt,max_attempts,last_error_code,created_at,updated_at,finished_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,$9,$10,$10,$10)
		ON CONFLICT (request_id) DO NOTHING`, operation.ID, operation.RequestID, operation.Type,
		operation.Status, createPriority, payload, result, operation.MaxAttempts, operation.LastErrorCode, now)
	if err != nil {
		return operations.Operation{}, false, err
	}
	count, err := inserted.RowsAffected()
	if err != nil {
		return operations.Operation{}, false, err
	}
	if count == 1 {
		return operation, true, nil
	}
	existing, err := store.GetByRequestID(command.RequestID)
	if err != nil {
		return operations.Operation{}, false, err
	}
	if !existing.SameRequest(operation) {
		return operations.Operation{}, false, operations.ErrIdempotencyConflict
	}
	return existing, false, nil
}
