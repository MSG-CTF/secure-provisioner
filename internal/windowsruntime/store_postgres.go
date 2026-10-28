package windowsruntime

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type PostgresStore struct{ db *sql.DB }

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{db: db} }

const windowsSelect = `SELECT execution_id::text, request_id::text, target_id::text,
 fingerprint, phase, finished_pending, record_json, payload, attempt,
 lease_owner, lease_until, next_attempt, created_at, updated_at
 FROM runtime_windows_executions`

func (store *PostgresStore) Check(ctx context.Context) error {
	if err := store.CheckBridge(ctx); err != nil {
		return err
	}
	recoveryRows, err := store.db.QueryContext(ctx, `SELECT execution_id FROM runtime_windows_recovery_events LIMIT 0`)
	if err != nil {
		return storageError(ctx)
	}
	return recoveryRows.Close()
}

// CheckBridge verifies only the schema available before this release. The
// deployment bridge serves queued HTTP work before the primary migrates 010.
func (store *PostgresStore) CheckBridge(ctx context.Context) error {
	if store.db == nil {
		return storageError(ctx)
	}
	rows, err := store.db.QueryContext(ctx, windowsSelect+" LIMIT 0")
	if err != nil {
		return storageError(ctx)
	}
	if err := rows.Close(); err != nil {
		return storageError(ctx)
	}
	return nil
}

// The public Record JSON deliberately hides these values. The private envelope
// keeps the exact outbox bytes and recovery data; payload and scheduling/lease
// metadata are held in authoritative columns in the same transaction.
type persistedWindowsRecord struct {
	Version        int         `json:"version"`
	Record         Record      `json:"record"`
	Checker        *CheckerJob `json:"checker,omitempty"`
	Stdout         []byte      `json:"stdout_bytes,omitempty"`
	Stderr         []byte      `json:"stderr_bytes,omitempty"`
	StartedBody    []byte      `json:"started_body"`
	FinishedBody   []byte      `json:"finished_body"`
	Connection     *Connection `json:"connection,omitempty"` // Version 1 only.
	ConnectionJSON []byte      `json:"connection_json,omitempty"`
	StartUncertain bool        `json:"start_uncertain"`
}

func encodeWindowsRecord(record Record) ([]byte, error) {
	privateRecord := record
	persisted := persistedWindowsRecord{Version: 2, Checker: record.Checker, StartedBody: record.StartedBody, FinishedBody: record.FinishedBody, StartUncertain: record.StartUncertain}
	// PostgreSQL JSONB rejects U+0000 even when escaped. Outputs are arbitrary
	// executable bytes, so preserve them losslessly as base64 JSON byte slices.
	// Only the private outcome copy is cleared; callers and the public API keep
	// the original strings, including embedded NUL and invalid UTF-8 bytes.
	if record.Outcome != nil {
		outcome := *record.Outcome
		persisted.Stdout, persisted.Stderr = []byte(outcome.Stdout), []byte(outcome.Stderr)
		outcome.Stdout, outcome.Stderr = "", ""
		privateRecord.Outcome = &outcome
	}
	if record.Connection != nil {
		connectionJSON, err := json.Marshal(record.Connection)
		if err != nil {
			return nil, err
		}
		// Name and the unused broker RDP file can contain the same JSONB-hostile
		// characters. A binary envelope preserves the complete connection too.
		persisted.ConnectionJSON = connectionJSON
	}
	persisted.Record = privateRecord
	return json.Marshal(persisted)
}

type windowsScanner interface{ Scan(...any) error }

func scanWindowsRecord(scanner windowsScanner) (Record, error) {
	var id, requestID, targetID, fingerprint, phase string
	var pending bool
	var recordJSON, payload []byte
	var attempt int
	var owner sql.NullString
	var leaseUntil, nextAttempt sql.NullTime
	var createdAt, updatedAt time.Time
	if err := scanner.Scan(&id, &requestID, &targetID, &fingerprint, &phase, &pending, &recordJSON, &payload, &attempt, &owner, &leaseUntil, &nextAttempt, &createdAt, &updatedAt); err != nil {
		return Record{}, err
	}
	var persisted persistedWindowsRecord
	if err := json.Unmarshal(recordJSON, &persisted); err != nil || (persisted.Version != 1 && persisted.Version != 2) {
		return Record{}, errors.New("invalid stored windows execution")
	}
	record := persisted.Record
	record.Checker = persisted.Checker
	record.ID = id
	record.RequestID = requestID
	record.TargetID = targetID
	record.Fingerprint = fingerprint
	record.Phase = phase
	record.BrokerPending = pending
	record.Payload = payload
	record.Attempt = attempt
	record.Owner = owner.String
	record.LeaseUntil = time.Time{}
	if leaseUntil.Valid {
		record.LeaseUntil = leaseUntil.Time.UTC()
	}
	record.NextAttempt = time.Time{}
	if nextAttempt.Valid {
		record.NextAttempt = nextAttempt.Time.UTC()
	}
	record.CreatedAt = createdAt.UTC()
	record.UpdatedAt = updatedAt.UTC()
	record.StartedBody = persisted.StartedBody
	record.FinishedBody = persisted.FinishedBody
	record.Connection = persisted.Connection
	if persisted.Version == 2 {
		if record.Outcome != nil {
			record.Outcome.Stdout = string(persisted.Stdout)
			record.Outcome.Stderr = string(persisted.Stderr)
		}
		if len(persisted.ConnectionJSON) != 0 {
			var connection Connection
			if err := json.Unmarshal(persisted.ConnectionJSON, &connection); err != nil {
				return Record{}, errors.New("invalid stored windows connection")
			}
			record.Connection = &connection
		}
	}
	record.StartUncertain = persisted.StartUncertain
	return record, nil
}

func storageError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("windows execution storage unavailable")
}

func optionalTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
func optionalOwner(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func storedPayload(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func (store *PostgresStore) Submit(ctx context.Context, record Record) (Record, bool, error) {
	if err := validateStoredRecord(record); err != nil {
		return Record{}, false, err
	}
	encoded, err := encodeWindowsRecord(record)
	if err != nil {
		return Record{}, false, errors.New("invalid windows execution record")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, false, storageError(ctx)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO runtime_windows_executions
 (execution_id,request_id,target_id,fingerprint,phase,finished_pending,record_json,payload,
  attempt,lease_owner,lease_until,next_attempt,created_at,updated_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT DO NOTHING`,
		record.ID, record.RequestID, record.TargetID, record.Fingerprint, record.Phase, record.BrokerPending, encoded, storedPayload(record.Payload), record.Attempt, optionalOwner(record.Owner), optionalTime(record.LeaseUntil), optionalTime(record.NextAttempt), record.CreatedAt, record.UpdatedAt)
	if err != nil {
		return Record{}, false, storageError(ctx)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Record{}, false, storageError(ctx)
	}
	original, err := scanWindowsRecord(tx.QueryRowContext(ctx, windowsSelect+" WHERE request_id=$1", record.RequestID))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, ErrConflict
	}
	if err != nil {
		return Record{}, false, storageError(ctx)
	}
	if original.TargetID != record.TargetID && !(record.TargetID == UnboundTargetID && original.Checker != nil && original.Checker.Request != nil && original.Checker.Request.SelectionMode == "broker_pool") || original.Fingerprint != record.Fingerprint {
		return Record{}, false, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Record{}, false, storageError(ctx)
	}
	return original, count == 1, nil
}

func (store *PostgresStore) Get(ctx context.Context, id string) (Record, error) {
	if !ValidID(id) {
		return Record{}, ErrNotFound
	}
	record, err := scanWindowsRecord(store.db.QueryRowContext(ctx, windowsSelect+" WHERE execution_id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, storageError(ctx)
	}
	return record, nil
}

func (store *PostgresStore) GetByRequest(ctx context.Context, requestID string) (Record, error) {
	if !ValidID(requestID) {
		return Record{}, ErrNotFound
	}
	record, err := scanWindowsRecord(store.db.QueryRowContext(ctx, windowsSelect+" WHERE request_id=$1", requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, storageError(ctx)
	}
	return record, nil
}

func leaseMicroseconds(lease time.Duration) int64 {
	value := lease.Microseconds()
	if value < 1 {
		return 1
	}
	return value
}

func (store *PostgresStore) Claim(ctx context.Context, owner string, lease time.Duration) (*Record, error) {
	if owner == "" || lease <= 0 {
		return nil, errors.New("windows execution claim requires an owner and positive lease")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storageError(ctx)
	}
	defer tx.Rollback()
	var cursorTime any
	cursorID := "00000000-0000-0000-0000-000000000000"
	for {
		var candidateID, targetID string
		var createdAt time.Time
		err := tx.QueryRowContext(ctx, `SELECT execution_id::text,target_id::text,created_at FROM runtime_windows_executions
 WHERE (phase IN ('FETCH_PENDING','QUEUED','START_PENDING','APPROVED','CONNECTING','RUNNING') OR (phase='FINISHED' AND (finished_pending OR record_json->'checker'->>'result_pending'='true')) OR (phase='REJECTED' AND record_json->'checker'->>'result_pending'='true'))
 AND (next_attempt IS NULL OR next_attempt<=clock_timestamp())
 AND (lease_owner IS NULL OR lease_until<=clock_timestamp())
 AND ($1::timestamptz IS NULL OR (created_at,execution_id)>($1::timestamptz,$2::uuid))
 ORDER BY created_at,execution_id LIMIT 1 FOR UPDATE SKIP LOCKED`, cursorTime, cursorID).Scan(&candidateID, &targetID, &createdAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, storageError(ctx)
		}
		cursorTime, cursorID = createdAt, candidateID
		// Row locks alone do not serialize two distinct queued rows for one VM.
		// Every claimant first takes the same transaction-scoped VM advisory lock,
		// then checks the latest committed reservations in a separate statement.
		var locked bool
		if err := tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))", "windows-runtime:"+targetID).Scan(&locked); err != nil {
			return nil, storageError(ctx)
		}
		if !locked {
			continue
		}
		if targetID == UnboundTargetID {
			// Unbound jobs do not occupy the nil-UUID placeholder VM.
			claimed, err := scanWindowsRecord(tx.QueryRowContext(ctx, `UPDATE runtime_windows_executions
 SET lease_owner=$1,lease_until=clock_timestamp()+$2::bigint*interval '1 microsecond',
 attempt=attempt+1,updated_at=clock_timestamp() WHERE execution_id=$3
 RETURNING execution_id::text,request_id::text,target_id::text,fingerprint,phase,finished_pending,
 record_json,payload,attempt,lease_owner,lease_until,next_attempt,created_at,updated_at`, owner, leaseMicroseconds(lease), candidateID))
			if err != nil {
				return nil, storageError(ctx)
			}
			if err := tx.Commit(); err != nil {
				return nil, storageError(ctx)
			}
			return &claimed, nil
		}
		var occupied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM runtime_windows_executions
 WHERE target_id=$1 AND execution_id<>$2 AND
 (phase IN ('START_PENDING','APPROVED','CONNECTING','RUNNING','BLOCKED') OR finished_pending
  OR (lease_owner IS NOT NULL AND lease_until>clock_timestamp())))`, targetID, candidateID).Scan(&occupied); err != nil {
			return nil, storageError(ctx)
		}
		if occupied {
			continue
		}
		claimed, err := scanWindowsRecord(tx.QueryRowContext(ctx, `UPDATE runtime_windows_executions
 SET lease_owner=$1,lease_until=clock_timestamp()+$2::bigint*interval '1 microsecond',
 attempt=attempt+1,updated_at=clock_timestamp() WHERE execution_id=$3
 RETURNING execution_id::text,request_id::text,target_id::text,fingerprint,phase,finished_pending,
 record_json,payload,attempt,lease_owner,lease_until,next_attempt,created_at,updated_at`, owner, leaseMicroseconds(lease), candidateID))
		if err != nil {
			return nil, storageError(ctx)
		}
		if err := tx.Commit(); err != nil {
			return nil, storageError(ctx)
		}
		return &claimed, nil
	}
}

func (store *PostgresStore) BindTarget(ctx context.Context, id, owner, targetID string) (bool, error) {
	if !ValidID(id) || !ValidID(targetID) || targetID == UnboundTargetID || owner == "" {
		return false, ErrConflict
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, storageError(ctx)
	}
	defer tx.Rollback()
	var currentTarget, phase, currentOwner, mode string
	var leaseUntil, createdAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT target_id::text,phase,lease_owner,lease_until,created_at,COALESCE(record_json#>>'{checker,request,selection_mode}','') FROM runtime_windows_executions WHERE execution_id=$1 FOR UPDATE`, id).Scan(&currentTarget, &phase, &currentOwner, &leaseUntil, &createdAt, &mode)
	if err != nil {
		return false, ErrLeaseLost
	}
	if currentTarget != UnboundTargetID || phase != "QUEUED" || currentOwner != owner || !leaseUntil.After(time.Now()) {
		return false, ErrLeaseLost
	}
	var locked bool
	if err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))", "windows-runtime:"+targetID).Scan(&locked); err != nil {
		return false, storageError(ctx)
	}
	if !locked {
		return false, nil
	}
	if mode == "broker_pool" {
		var ahead bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM runtime_windows_executions
 WHERE target_id=$1 AND phase='QUEUED'
 AND record_json#>>'{checker,request,selection_mode}'='broker_pool'
 AND (created_at,execution_id)<($2::timestamptz,$3::uuid))`, UnboundTargetID, createdAt, id).Scan(&ahead); err != nil {
			return false, storageError(ctx)
		}
		if ahead {
			return false, nil
		}
	}
	var occupied bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM runtime_windows_executions WHERE target_id=$1 AND execution_id<>$2 AND
 (phase IN ('FETCH_PENDING','QUEUED','START_PENDING','APPROVED','CONNECTING','RUNNING','BLOCKED') OR finished_pending OR
 (lease_owner IS NOT NULL AND lease_until>clock_timestamp())))`, targetID, id).Scan(&occupied); err != nil {
		return false, storageError(ctx)
	}
	if occupied {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE runtime_windows_executions SET target_id=$1,updated_at=clock_timestamp() WHERE execution_id=$2`, targetID, id)
	if err != nil {
		return false, storageError(ctx)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return false, storageError(ctx)
	}
	if err = tx.Commit(); err != nil {
		return false, storageError(ctx)
	}
	return true, nil
}

func (store *PostgresStore) Save(ctx context.Context, record Record, expectedOwner string) error {
	if expectedOwner == "" || (record.Owner != "" && record.Owner != expectedOwner) {
		return ErrLeaseLost
	}
	if err := validateStoredRecord(record); err != nil {
		return err
	}
	encoded, err := encodeWindowsRecord(record)
	if err != nil {
		return errors.New("invalid windows execution record")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE runtime_windows_executions
 SET phase=$1,finished_pending=$2,record_json=$3,payload=$4,next_attempt=$5,updated_at=$6,
 lease_owner=NULLIF($7,''),lease_until=CASE WHEN $7='' THEN NULL ELSE lease_until END
 WHERE execution_id=$8 AND lease_owner=$9 AND lease_until>clock_timestamp() AND attempt=$10
 AND request_id=$11 AND target_id=$12 AND fingerprint=$13`,
		record.Phase, record.BrokerPending, encoded, storedPayload(record.Payload), optionalTime(record.NextAttempt), record.UpdatedAt, record.Owner, record.ID, expectedOwner, record.Attempt, record.RequestID, record.TargetID, record.Fingerprint)
	if err != nil {
		return storageError(ctx)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return storageError(ctx)
	}
	if count != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (store *PostgresStore) Renew(ctx context.Context, id, owner string, lease time.Duration) error {
	if owner == "" || lease <= 0 || !ValidID(id) {
		return ErrLeaseLost
	}
	result, err := store.db.ExecContext(ctx, `UPDATE runtime_windows_executions
 SET lease_until=clock_timestamp()+$1::bigint*interval '1 microsecond',updated_at=clock_timestamp()
 WHERE execution_id=$2 AND lease_owner=$3 AND lease_until>clock_timestamp()`, leaseMicroseconds(lease), id, owner)
	if err != nil {
		return storageError(ctx)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return storageError(ctx)
	}
	if count != 1 {
		return ErrLeaseLost
	}
	return nil
}
