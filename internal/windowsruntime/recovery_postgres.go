package windowsruntime

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

func (store *PostgresStore) ConfirmRecovery(ctx context.Context, targetID, executionID, eventID string) (RecoveryReceipt, error) {
	if store.db == nil {
		return RecoveryReceipt{}, ErrRecoveryUnavailable
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return RecoveryReceipt{}, ErrRecoveryUnavailable
	}
	defer tx.Rollback()
	var target, phase string
	var brokerPending bool
	var recordJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT target_id::text, phase, finished_pending, record_json
		FROM runtime_windows_executions WHERE execution_id = $1 FOR UPDATE`, executionID).
		Scan(&target, &phase, &brokerPending, &recordJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryReceipt{}, ErrNotFound
	}
	if err != nil {
		return RecoveryReceipt{}, ErrRecoveryUnavailable
	}
	if target != targetID {
		return RecoveryReceipt{}, ErrConflict
	}
	var persisted persistedWindowsRecord
	if json.Unmarshal(recordJSON, &persisted) != nil {
		return RecoveryReceipt{}, ErrRecoveryUnavailable
	}
	if !validRecoveryRecord(Record{TargetID: target, Phase: phase, BrokerPending: brokerPending, Checker: persisted.Checker}, targetID) {
		return RecoveryReceipt{}, ErrRecoveryNotReady
	}
	if persisted.Checker.ResultEventID == eventID {
		return RecoveryReceipt{}, ErrConflict
	}
	var recoveredAt time.Time
	cleanupState := "PENDING"
	err = tx.QueryRowContext(ctx, `INSERT INTO runtime_windows_recovery_events (execution_id, target_id, event_id)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING recovered_at`, executionID, targetID, eventID).
		Scan(&recoveredAt)
	replayed := false
	if errors.Is(err, sql.ErrNoRows) {
		var previousEvent, previousTarget string
		err = tx.QueryRowContext(ctx, `SELECT target_id::text, event_id::text, recovered_at, backend_cleanup_state
			FROM runtime_windows_recovery_events WHERE execution_id = $1`, executionID).
			Scan(&previousTarget, &previousEvent, &recoveredAt, &cleanupState)
		if errors.Is(err, sql.ErrNoRows) {
			return RecoveryReceipt{}, ErrConflict
		}
		if err != nil {
			return RecoveryReceipt{}, ErrRecoveryUnavailable
		}
		if previousTarget != targetID || previousEvent != eventID {
			return RecoveryReceipt{}, ErrConflict
		}
		replayed = true
	} else if err != nil {
		return RecoveryReceipt{}, ErrRecoveryUnavailable
	}
	if err := tx.Commit(); err != nil {
		return RecoveryReceipt{}, ErrRecoveryUnavailable
	}
	return RecoveryReceipt{TargetID: targetID, ExecutionID: executionID, EventID: eventID,
		VMState: "READY", CleanupDelivery: cleanupState, RecoveredAt: recoveredAt.UTC(), Replayed: replayed}, nil
}

func (store *PostgresStore) ClaimRecovery(ctx context.Context, owner string, lease time.Duration) (*RecoveryDelivery, error) {
	if store.db == nil || owner == "" || lease <= 0 {
		return nil, ErrRecoveryUnavailable
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrRecoveryUnavailable
	}
	defer tx.Rollback()
	var receipt RecoveryReceipt
	err = tx.QueryRowContext(ctx, `SELECT e.execution_id::text,e.target_id::text,e.event_id::text,e.recovered_at
		FROM runtime_windows_recovery_events e
		JOIN runtime_windows_executions x ON x.execution_id=e.execution_id
		WHERE e.backend_cleanup_state='PENDING'
		  AND (e.lease_owner IS NULL OR e.lease_until<=clock_timestamp())
		  AND (e.next_attempt IS NULL OR e.next_attempt<=clock_timestamp())
		  AND x.phase='FINISHED' AND x.finished_pending=FALSE
		  AND COALESCE(x.record_json->'checker'->>'result_pending','false')='false'
		  AND COALESCE(x.record_json->'checker'->>'result_event_id','')<>''
		ORDER BY e.recovered_at,e.execution_id LIMIT 1 FOR UPDATE OF e SKIP LOCKED`).
		Scan(&receipt.ExecutionID, &receipt.TargetID, &receipt.EventID, &receipt.RecoveredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrRecoveryUnavailable
	}
	_, err = tx.ExecContext(ctx, `UPDATE runtime_windows_recovery_events
		SET lease_owner=$1, lease_until=clock_timestamp()+$2::bigint*interval '1 microsecond',attempt=attempt+1
		WHERE execution_id=$3`, owner, leaseMicroseconds(lease), receipt.ExecutionID)
	if err != nil {
		return nil, ErrRecoveryUnavailable
	}
	if err := tx.Commit(); err != nil {
		return nil, ErrRecoveryUnavailable
	}
	record, err := store.Get(ctx, receipt.ExecutionID)
	if err != nil {
		return nil, ErrRecoveryUnavailable
	}
	if !recoveryResultDelivered(record) || record.TargetID != receipt.TargetID {
		return nil, ErrRecoveryUnavailable
	}
	receipt.VMState, receipt.CleanupDelivery = "READY", "PENDING"
	receipt.RecoveredAt = receipt.RecoveredAt.UTC()
	return &RecoveryDelivery{Receipt: receipt, Record: record}, nil
}

func (store *PostgresStore) CompleteRecovery(ctx context.Context, executionID, owner string, delivered bool, retryAt time.Time) error {
	if store.db == nil || owner == "" || !ValidID(executionID) {
		return ErrRecoveryUnavailable
	}
	state := "PENDING"
	var confirmedAt any
	if delivered {
		state, confirmedAt = "CONFIRMED", time.Now().UTC()
	}
	result, err := store.db.ExecContext(ctx, `UPDATE runtime_windows_recovery_events
		SET backend_cleanup_state=$1,backend_cleanup_confirmed_at=$2,lease_owner=NULL,lease_until=NULL,next_attempt=$3
		WHERE execution_id=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND backend_cleanup_state='PENDING'`,
		state, confirmedAt, optionalTime(retryAt), executionID, owner)
	if err != nil {
		return ErrRecoveryUnavailable
	}
	count, err := result.RowsAffected()
	if err != nil {
		return ErrRecoveryUnavailable
	}
	if count != 1 {
		return ErrLeaseLost
	}
	return nil
}
