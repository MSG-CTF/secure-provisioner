package runtimepg

import (
	"database/sql"
	"errors"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

type DeleteCoordinator struct{ db *sql.DB }

func (coordinator *DeleteCoordinator) BeginDelete(command provisioner.DeleteWorkloadCommand, maxAttempts int, now time.Time) (operations.Operation, bool, error) {
	tx, err := coordinator.db.Begin()
	if err != nil {
		return operations.Operation{}, false, err
	}
	defer tx.Rollback()
	if existing, lookupErr := scanOperation(tx.QueryRow(operationSelect+" WHERE request_id=$1", command.RequestID)); lookupErr == nil {
		if existing.Type == operations.OperationTypeDelete && existing.DeleteCommand != nil && *existing.DeleteCommand == command {
			return existing, false, nil
		}
		return operations.Operation{}, false, operations.ErrIdempotencyConflict
	} else if !errors.Is(lookupErr, operations.ErrOperationNotFound) {
		return operations.Operation{}, false, lookupErr
	}
	binding, err := scanBinding(tx.QueryRow(bindingSelect+" WHERE instance_id=$1 FOR UPDATE", command.InstanceID))
	if err != nil {
		return operations.Operation{}, false, err
	}
	if command.TeamID != binding.TeamID || command.TargetID != binding.TargetID || command.RuntimeWorkloadID != binding.RuntimeWorkloadID {
		return operations.Operation{}, false, runtimebinding.ErrConflict
	}
	if binding.State == runtimebinding.StateDeleted {
		return operations.Operation{}, false, runtimebinding.ErrInvalidTransition
	}
	if _, err := tx.Exec(`UPDATE runtime_bindings SET state='DELETING',updated_at=$2 WHERE instance_id=$1 AND state IN ('CREATED','DELETING')`, binding.InstanceID, now); err != nil {
		return operations.Operation{}, false, err
	}
	operation, err := operations.NewDeleteOperation(randomOperationID(), command, maxAttempts)
	if err != nil {
		return operations.Operation{}, false, err
	}
	payload, err := encodeOperationCommand(operation)
	if err != nil {
		return operations.Operation{}, false, err
	}
	if _, err := tx.Exec(`INSERT INTO runtime_operations (operation_id,request_id,operation_type,status,priority,command_snapshot,attempt,max_attempts,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,0,$7,$8,$8)`, operation.ID, operation.RequestID, operation.Type, operation.Status, deletePriority, string(payload), operation.MaxAttempts, now); err != nil {
		return operations.Operation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return operations.Operation{}, false, err
	}
	return operation, true, nil
}
