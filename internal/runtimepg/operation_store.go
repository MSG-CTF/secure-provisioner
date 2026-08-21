package runtimepg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

const createPriority = 10
const deletePriority = 100

type OperationStore struct{ db *sql.DB }

func (store *OperationStore) EnqueueCreate(command provisioner.CreateWorkloadCommand, maxAttempts int) (operations.Operation, bool, error) {
	operation, err := operations.NewCreateOperation(randomOperationID(), command, maxAttempts)
	if err != nil {
		return operations.Operation{}, false, err
	}
	return store.enqueue(operation, createPriority)
}

func (store *OperationStore) EnqueueDelete(command provisioner.DeleteWorkloadCommand, maxAttempts int) (operations.Operation, bool, error) {
	operation, err := operations.NewDeleteOperation(randomOperationID(), command, maxAttempts)
	if err != nil {
		return operations.Operation{}, false, err
	}
	return store.enqueue(operation, deletePriority)
}

func (store *OperationStore) enqueue(operation operations.Operation, priority int) (operations.Operation, bool, error) {
	payload, err := encodeOperationCommand(operation)
	if err != nil {
		return operations.Operation{}, false, err
	}
	now := time.Now().UTC()
	_, err = store.db.Exec(`INSERT INTO runtime_operations
        (operation_id,request_id,operation_type,status,priority,command_snapshot,attempt,max_attempts,created_at,updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,0,$7,$8,$8)`, operation.ID, operation.RequestID, operation.Type, operation.Status, priority, payload, operation.MaxAttempts, now)
	if err == nil {
		return operation, true, nil
	}
	existing, lookupErr := store.GetByRequestID(operation.RequestID)
	if lookupErr != nil {
		return operations.Operation{}, false, err
	}
	if existing.SameRequest(operation) {
		return existing, false, nil
	}
	return operations.Operation{}, false, operations.ErrIdempotencyConflict
}

func (store *OperationStore) Get(id string) (operations.Operation, error) {
	return scanOperation(store.db.QueryRow(operationSelect+" WHERE operation_id=$1", id))
}

func (store *OperationStore) GetByRequestID(requestID string) (operations.Operation, error) {
	return scanOperation(store.db.QueryRow(operationSelect+" WHERE request_id=$1", requestID))
}

func (store *OperationStore) Claim(ctx context.Context, options operations.ClaimOptions) (operations.ClaimedOperation, bool, error) {
	row := store.db.QueryRowContext(ctx, `WITH candidate AS (
        SELECT operation_id FROM runtime_operations
        WHERE status='QUEUED'
           OR (status='RETRYING' AND (next_retry_at IS NULL OR next_retry_at <= $1))
           OR (status='RUNNING' AND (lease_until IS NULL OR lease_until <= $1))
        ORDER BY priority DESC, created_at ASC
        FOR UPDATE SKIP LOCKED LIMIT 1
    )
    UPDATE runtime_operations operation
       SET status='RUNNING', attempt=operation.attempt+1, lease_owner=$2,
           lease_until=$3, lease_version=operation.lease_version+1,
           updated_at=$1, started_at=COALESCE(operation.started_at,$1)
      FROM candidate WHERE operation.operation_id=candidate.operation_id
    RETURNING operation.operation_id,operation.request_id,operation.operation_type,operation.status,
      operation.command_snapshot,operation.create_checkpoint,operation.result,operation.attempt,
      operation.max_attempts,operation.next_retry_at,operation.lease_owner,operation.lease_until,
      operation.lease_version,operation.last_error_code`, options.Now, options.WorkerID, options.Now.Add(options.LeaseDuration))
	operation, lease, err := scanClaimedOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return operations.ClaimedOperation{}, false, nil
	}
	if err != nil {
		return operations.ClaimedOperation{}, false, err
	}
	return operations.ClaimedOperation{Operation: operation, Lease: lease}, true, nil
}

func (store *OperationStore) RenewLease(ctx context.Context, claimed operations.ClaimedOperation, until time.Time) (operations.ClaimedOperation, error) {
	result, err := store.db.ExecContext(ctx, fencedUpdate(`lease_until=$4,updated_at=$5`), claimed.Operation.ID, claimed.Lease.Owner, claimed.Lease.Version, until, time.Now().UTC())
	if err != nil {
		return operations.ClaimedOperation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return operations.ClaimedOperation{}, err
	}
	claimed.Lease.Until = until
	return claimed, nil
}

func (store *OperationStore) CheckpointLeaseCreateResult(claimed operations.ClaimedOperation, checkpoint provisioner.CreateWorkloadResult, now time.Time) (operations.ClaimedOperation, error) {
	payload, err := json.Marshal(checkpoint)
	if err != nil {
		return operations.ClaimedOperation{}, err
	}
	result, err := store.db.Exec(fencedUpdate(`create_checkpoint=$4,updated_at=$5`), claimed.Operation.ID, claimed.Lease.Owner, claimed.Lease.Version, payload, now)
	if err != nil {
		return operations.ClaimedOperation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return operations.ClaimedOperation{}, err
	}
	claimed.Operation.CreateCheckpoint = &checkpoint
	return claimed, nil
}

func (store *OperationStore) MarkLeaseRetrying(claimed operations.ClaimedOperation, errorCode string, nextRetryAt, now time.Time) (operations.Operation, error) {
	result, err := store.db.Exec(fencedUpdate(`status='RETRYING',last_error_code=$4,next_retry_at=$5,lease_owner=NULL,lease_until=NULL,updated_at=$6`), claimed.Operation.ID, claimed.Lease.Owner, claimed.Lease.Version, errorCode, nextRetryAt, now)
	if err != nil {
		return operations.Operation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return operations.Operation{}, err
	}
	return store.Get(claimed.Operation.ID)
}

func (store *OperationStore) ReleaseLease(claimed operations.ClaimedOperation, now time.Time) error {
	result, err := store.db.Exec(fencedUpdate(`status='QUEUED',attempt=GREATEST(attempt-1,0),next_retry_at=NULL,lease_owner=NULL,lease_until=NULL,updated_at=$4`), claimed.Operation.ID, claimed.Lease.Owner, claimed.Lease.Version, now)
	if err != nil {
		return err
	}
	return requireOneRow(result)
}

func (store *OperationStore) MarkLeaseSucceeded(claimed operations.ClaimedOperation, operationResult operations.OperationResult, now time.Time) (operations.Operation, error) {
	payload, err := json.Marshal(operationResult)
	if err != nil {
		return operations.Operation{}, err
	}
	result, err := store.db.Exec(fencedUpdate(`status='SUCCEEDED',result=$4,create_checkpoint=NULL,lease_owner=NULL,lease_until=NULL,next_retry_at=NULL,updated_at=$5,finished_at=$5`), claimed.Operation.ID, claimed.Lease.Owner, claimed.Lease.Version, payload, now)
	if err != nil {
		return operations.Operation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return operations.Operation{}, err
	}
	return store.Get(claimed.Operation.ID)
}

func (store *OperationStore) MarkLeaseFailed(claimed operations.ClaimedOperation, errorCode string, now time.Time) (operations.Operation, error) {
	result, err := store.db.Exec(fencedUpdate(`status='FAILED',last_error_code=$4,lease_owner=NULL,lease_until=NULL,next_retry_at=NULL,updated_at=$5,finished_at=$5`), claimed.Operation.ID, claimed.Lease.Owner, claimed.Lease.Version, errorCode, now)
	if err != nil {
		return operations.Operation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return operations.Operation{}, err
	}
	return store.Get(claimed.Operation.ID)
}

func fencedUpdate(assignments string) string {
	return `UPDATE runtime_operations SET ` + assignments + ` WHERE operation_id=$1 AND status='RUNNING' AND lease_owner=$2 AND lease_version=$3`
}

func requireOneRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return operations.ErrLeaseLost
	}
	return nil
}

const operationSelect = `SELECT operation_id,request_id,operation_type,status,command_snapshot,
 create_checkpoint,result,attempt,max_attempts,next_retry_at,lease_owner,lease_until,lease_version,last_error_code FROM runtime_operations`

type rowScanner interface{ Scan(...any) error }

func scanOperation(row rowScanner) (operations.Operation, error) {
	operation, _, err := scanClaimedOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return operations.Operation{}, operations.ErrOperationNotFound
	}
	return operation, err
}

func scanClaimedOperation(row rowScanner) (operations.Operation, operations.Lease, error) {
	var operation operations.Operation
	var command, checkpoint, result []byte
	var nextRetry, leaseUntil sql.NullTime
	var leaseOwner sql.NullString
	var leaseVersion int64
	if err := row.Scan(&operation.ID, &operation.RequestID, &operation.Type, &operation.Status, &command, &checkpoint, &result,
		&operation.Attempt, &operation.MaxAttempts, &nextRetry, &leaseOwner, &leaseUntil, &leaseVersion, &operation.LastErrorCode); err != nil {
		return operations.Operation{}, operations.Lease{}, err
	}
	decoded, err := decodeOperationCommand(operation.Type, command)
	if err != nil {
		return operations.Operation{}, operations.Lease{}, err
	}
	operation.CreateCommand, operation.DeleteCommand = decoded.CreateCommand, decoded.DeleteCommand
	if len(checkpoint) > 0 {
		var value provisioner.CreateWorkloadResult
		if err := json.Unmarshal(checkpoint, &value); err != nil {
			return operations.Operation{}, operations.Lease{}, err
		}
		operation.CreateCheckpoint = &value
	}
	if len(result) > 0 {
		if err := json.Unmarshal(result, &operation.Result); err != nil {
			return operations.Operation{}, operations.Lease{}, err
		}
	}
	if nextRetry.Valid {
		operation.NextRetryAt = nextRetry.Time
	}
	lease := operations.Lease{Owner: leaseOwner.String, Version: leaseVersion}
	if leaseUntil.Valid {
		lease.Until = leaseUntil.Time
	}
	return operation, lease, nil
}

func randomOperationID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("generate operation ID: %v", err))
	}
	return hex.EncodeToString(buffer)
}

var _ operations.Store = (*OperationStore)(nil)
var _ operations.LeaseStore = (*OperationStore)(nil)
