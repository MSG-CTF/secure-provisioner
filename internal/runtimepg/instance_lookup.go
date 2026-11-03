package runtimepg

import "github.com/MSG-CTF/secure-provisioner/internal/operations"

func (s *OperationStore) GetCreateByInstance(instanceID string) (operations.Operation, error) {
	rows, err := s.db.Query(operationSelect+` WHERE operation_type='CREATE'
		AND command_snapshot->>'InstanceID'=$1 ORDER BY created_at DESC LIMIT 2`, instanceID)
	if err != nil {
		return operations.Operation{}, err
	}
	defer rows.Close()
	var found *operations.Operation
	for rows.Next() {
		if found != nil {
			return operations.Operation{}, operations.ErrIdempotencyConflict
		}
		op, err := scanOperation(rows)
		if err != nil {
			return operations.Operation{}, err
		}
		found = &op
	}
	if err := rows.Err(); err != nil {
		return operations.Operation{}, err
	}
	if found == nil {
		return operations.Operation{}, operations.ErrOperationNotFound
	}
	return *found, nil
}
