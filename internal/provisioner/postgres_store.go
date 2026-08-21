package provisioner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var workerMigrations embed.FS

type postgresStore struct {
	db *sql.DB
}

func NewPostgresStore(ctx context.Context, dsn string) (*postgresStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL: %w", err)
	}
	db.SetMaxOpenConns(30)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	store := &postgresStore{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (store *postgresStore) migrate(ctx context.Context) error {
	entries, err := workerMigrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		migration, err := workerMigrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		if _, err := store.db.ExecContext(ctx, string(migration)); err != nil {
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func (store *postgresStore) acceptCreate(ctx context.Context, request CreateRequest, now time.Time) (Operation, Instance, bool, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, Instance{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", postgresLockKey(activeAllocationKey(request.TeamID, request.ChallengeID))); err != nil {
		return Operation{}, Instance{}, false, err
	}
	if operation, instance, found, err := postgresOperationByRequest(ctx, tx, request.RequestID); err != nil {
		return Operation{}, Instance{}, false, err
	} else if found {
		return operation, instance, true, nil
	}

	if instance, found, err := postgresActiveInstance(ctx, tx, request.TeamID, request.ChallengeID); err != nil {
		return Operation{}, Instance{}, false, err
	} else if found {
		operation, err := postgresLatestOperation(ctx, tx, instance.InstanceID)
		return operation, instance, true, err
	}

	var instanceIDExists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM instances WHERE instance_id=$1)", request.InstanceID).Scan(&instanceIDExists); err != nil {
		return Operation{}, Instance{}, false, err
	}
	if instanceIDExists {
		return Operation{}, Instance{}, false, ErrInstanceIDInUse
	}

	instance := Instance{
		InstanceID: request.InstanceID, TeamID: request.TeamID, ChallengeID: request.ChallengeID,
		ClusterID: request.ClusterID, ReservationID: request.ReservationID, Phase: PhaseRequested,
		DesiredState: DesiredRunning, Generation: 1, CreatedBy: request.CreatedBy,
		CreatedAt: now, ExpiresAt: request.ExpiresAt, UpdatedAt: now,
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO instances
        (instance_id, team_id, challenge_id, cluster_id, reservation_id, phase, desired_state, generation, created_by, expires_at, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		instance.InstanceID, instance.TeamID, instance.ChallengeID, instance.ClusterID, instance.ReservationID,
		instance.Phase, instance.DesiredState, instance.Generation, instance.CreatedBy, instance.ExpiresAt, now, now); err != nil {
		return Operation{}, Instance{}, false, err
	}
	operation := newPersistentOperation(request.RequestID, instance, OperationCreate, now)
	if err := insertPostgresOperation(ctx, tx, operation); err != nil {
		return Operation{}, Instance{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, Instance{}, false, err
	}
	return operation, instance, false, nil
}

func (store *postgresStore) acceptDelete(ctx context.Context, requestID string, instanceID string, now time.Time) (Operation, Instance, bool, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, Instance{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", postgresLockKey("delete\x00"+instanceID)); err != nil {
		return Operation{}, Instance{}, false, err
	}
	if operation, instance, found, err := postgresOperationByRequest(ctx, tx, requestID); err != nil {
		return Operation{}, Instance{}, false, err
	} else if found {
		return operation, instance, true, nil
	}
	instance, err := postgresInstanceByID(ctx, tx, instanceID)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, Instance{}, false, ErrInstanceNotFound
	}
	if err != nil {
		return Operation{}, Instance{}, false, err
	}

	if instance.Phase != PhaseTerminated {
		var existingID string
		err := tx.QueryRowContext(ctx, `SELECT operation_id FROM operations
            WHERE instance_id=$1 AND operation_type='DELETE' AND status <> 'FAILED'
            ORDER BY created_at DESC LIMIT 1`, instanceID).Scan(&existingID)
		if err == nil {
			operation, err := postgresOperationByID(ctx, tx, existingID)
			return operation, instance, true, err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Operation{}, Instance{}, false, err
		}
	}

	operation := newPersistentOperation(requestID, instance, OperationDelete, now)
	if instance.Phase == PhaseTerminated {
		operation.Status = OperationSucceeded
	}
	if err := insertPostgresOperation(ctx, tx, operation); err != nil {
		return Operation{}, Instance{}, false, err
	}
	if instance.Phase != PhaseTerminated {
		if _, err := tx.ExecContext(ctx, "UPDATE instances SET desired_state=$2, updated_at=$3 WHERE instance_id=$1", instanceID, DesiredTerminated, now); err != nil {
			return Operation{}, Instance{}, false, err
		}
		instance.DesiredState = DesiredTerminated
		instance.UpdatedAt = now
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, Instance{}, false, err
	}
	return operation, instance, instance.Phase == PhaseTerminated, nil
}

func (store *postgresStore) claim(ctx context.Context, options ClaimOptions) (Operation, bool, error) {
	leaseDuration := options.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 3 * time.Minute
	}
	row := store.db.QueryRowContext(ctx, `WITH candidate AS (
        SELECT operation_id FROM operations
        WHERE status='PENDING'
           OR (status='RETRY_WAIT' AND (next_retry_at IS NULL OR next_retry_at <= $1))
           OR (status='RUNNING' AND (lease_until IS NULL OR lease_until <= $1))
        ORDER BY priority DESC, created_at ASC
        FOR UPDATE SKIP LOCKED LIMIT 1
    )
    UPDATE operations o SET status='RUNNING', attempt_count=o.attempt_count+1,
        lease_owner=$2, lease_until=$3, updated_at=$1, started_at=COALESCE(o.started_at,$1)
    FROM candidate WHERE o.operation_id=candidate.operation_id
    RETURNING o.operation_id,o.request_id,o.instance_id,o.operation_type,o.status,o.priority,
        o.attempt_count,o.max_attempts,o.next_retry_at,o.lease_owner,o.lease_until,
        o.last_error_message,o.created_at,o.updated_at`, options.Now, options.WorkerID, options.Now.Add(leaseDuration))
	operation, err := scanPostgresOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, false, nil
	}
	if err != nil {
		return Operation{}, false, err
	}
	return operation, true, nil
}

func (store *postgresStore) getInstance(instanceID string) (Instance, error) {
	instance, err := postgresInstanceByID(context.Background(), store.db, instanceID)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, ErrInstanceNotFound
	}
	return instance, err
}

func (store *postgresStore) getOperation(operationID string) (Operation, bool) {
	operation, err := postgresOperationByID(context.Background(), store.db, operationID)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, false
	}
	return operation, err == nil
}

func (store *postgresStore) incrementAttempt(operationID string, now time.Time) {
	_, _ = store.db.ExecContext(context.Background(), "UPDATE operations SET attempt_count=attempt_count+1, updated_at=$2 WHERE operation_id=$1", operationID, now)
}

func (store *postgresStore) finishOperation(operationID string, workerID string, status OperationStatus, lastError string, now time.Time) error {
	result, err := store.db.ExecContext(context.Background(), `UPDATE operations SET status=$3,last_error_message=$4,
        lease_owner='',lease_until=NULL,next_retry_at=NULL,updated_at=$5,finished_at=$5
        WHERE operation_id=$1 AND lease_owner=$2 AND status='RUNNING'`, operationID, workerID, status, lastError, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("operation lease is not owned by worker")
	}
	return nil
}

func (store *postgresStore) retryOperation(operationID string, workerID string, nextRetryAt time.Time, lastError string, now time.Time) error {
	result, err := store.db.ExecContext(context.Background(), `UPDATE operations SET status='RETRY_WAIT',next_retry_at=$3,
        last_error_message=$4,lease_owner='',lease_until=NULL,updated_at=$5
        WHERE operation_id=$1 AND lease_owner=$2 AND status='RUNNING'`, operationID, workerID, nextRetryAt, lastError, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("operation lease is not owned by worker")
	}
	return nil
}

func (store *postgresStore) renewLease(operationID string, workerID string, leaseUntil time.Time) error {
	result, err := store.db.ExecContext(context.Background(), `UPDATE operations SET lease_until=$3,updated_at=NOW()
        WHERE operation_id=$1 AND lease_owner=$2 AND status='RUNNING'`, operationID, workerID, leaseUntil)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("operation lease is not owned by worker")
	}
	return nil
}

func (store *postgresStore) updateInstance(instanceID string, update func(*Instance), now time.Time) (Instance, error) {
	ctx := context.Background()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Instance{}, err
	}
	defer func() { _ = tx.Rollback() }()
	instance, err := postgresInstanceByID(ctx, tx, instanceID)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, ErrInstanceNotFound
	}
	if err != nil {
		return Instance{}, err
	}
	update(&instance)
	instance.UpdatedAt = now
	var readyAt, terminatedAt any
	if instance.Phase == PhaseReady {
		readyAt = now
	}
	if instance.Phase == PhaseTerminated {
		terminatedAt = now
	}
	_, err = tx.ExecContext(ctx, `UPDATE instances SET phase=$2,desired_state=$3,generation=$4,
        security_profile=$5,resource_profile=$6,network_profile=$7,namespace=$8,endpoint=$9,
        last_error_message=$10,updated_at=$11,ready_at=COALESCE(ready_at,$12),terminated_at=COALESCE(terminated_at,$13)
        WHERE instance_id=$1`, instance.InstanceID, instance.Phase, instance.DesiredState, instance.Generation,
		instance.SecurityProfile, instance.ResourceProfile, instance.NetworkProfile, instance.Namespace,
		instance.Endpoint, instance.LastError, now, readyAt, terminatedAt)
	if err != nil {
		return Instance{}, err
	}
	if err := tx.Commit(); err != nil {
		return Instance{}, err
	}
	return instance, nil
}

func (store *postgresStore) expiredInstances(now time.Time) []string {
	rows, err := store.db.QueryContext(context.Background(), "SELECT instance_id FROM instances WHERE phase='READY' AND expires_at <= $1", now)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var instanceID string
		if rows.Scan(&instanceID) == nil {
			result = append(result, instanceID)
		}
	}
	return result
}

func (store *postgresStore) close() error { return store.db.Close() }

func newPersistentOperation(requestID string, instance Instance, operationType OperationType, now time.Time) Operation {
	priority := createPriority
	if operationType == OperationDelete {
		priority = deletePriority
	}
	return Operation{OperationID: randomOperationID(), RequestID: requestID, InstanceID: instance.InstanceID,
		OperationType: operationType, Status: OperationPending, Priority: priority, MaxAttempts: maximumRetries + 1,
		CreatedAt: now, UpdatedAt: now}
}

func randomOperationID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "op-" + hex.EncodeToString(buffer)
}

func postgresLockKey(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func insertPostgresOperation(ctx context.Context, tx *sql.Tx, operation Operation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO operations
        (operation_id,request_id,instance_id,cluster_id,operation_type,status,priority,attempt_count,max_attempts,created_at,updated_at)
        SELECT $1,$2,$3,cluster_id,$4,$5,$6,$7,$8,$9,$10 FROM instances WHERE instance_id=$3`,
		operation.OperationID, operation.RequestID, operation.InstanceID, operation.OperationType, operation.Status,
		operation.Priority, operation.AttemptCount, operation.MaxAttempts, operation.CreatedAt, operation.UpdatedAt)
	return err
}

type postgresQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func postgresOperationByRequest(ctx context.Context, query postgresQuerier, requestID string) (Operation, Instance, bool, error) {
	operation, err := scanPostgresOperation(query.QueryRowContext(ctx, `SELECT operation_id,request_id,instance_id,operation_type,status,priority,
        attempt_count,max_attempts,next_retry_at,lease_owner,lease_until,last_error_message,created_at,updated_at
        FROM operations WHERE request_id=$1`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, Instance{}, false, nil
	}
	if err != nil {
		return Operation{}, Instance{}, false, err
	}
	instance, err := postgresInstanceByID(ctx, query, operation.InstanceID)
	return operation, instance, err == nil, err
}

func postgresLatestOperation(ctx context.Context, query postgresQuerier, instanceID string) (Operation, error) {
	return scanPostgresOperation(query.QueryRowContext(ctx, `SELECT operation_id,request_id,instance_id,operation_type,status,priority,
        attempt_count,max_attempts,next_retry_at,lease_owner,lease_until,last_error_message,created_at,updated_at
        FROM operations WHERE instance_id=$1 ORDER BY created_at DESC LIMIT 1`, instanceID))
}

func postgresOperationByID(ctx context.Context, query postgresQuerier, operationID string) (Operation, error) {
	return scanPostgresOperation(query.QueryRowContext(ctx, `SELECT operation_id,request_id,instance_id,operation_type,status,priority,
        attempt_count,max_attempts,next_retry_at,lease_owner,lease_until,last_error_message,created_at,updated_at
        FROM operations WHERE operation_id=$1`, operationID))
}

type rowScanner interface{ Scan(...any) error }

func scanPostgresOperation(row rowScanner) (Operation, error) {
	var operation Operation
	var nextRetryAt, leaseUntil sql.NullTime
	err := row.Scan(&operation.OperationID, &operation.RequestID, &operation.InstanceID, &operation.OperationType,
		&operation.Status, &operation.Priority, &operation.AttemptCount, &operation.MaxAttempts, &nextRetryAt,
		&operation.LeaseOwner, &leaseUntil, &operation.LastError, &operation.CreatedAt, &operation.UpdatedAt)
	if nextRetryAt.Valid {
		operation.NextRetryAt = &nextRetryAt.Time
	}
	if leaseUntil.Valid {
		operation.LeaseUntil = &leaseUntil.Time
	}
	return operation, err
}

func postgresActiveInstance(ctx context.Context, query postgresQuerier, teamID int64, challengeID string) (Instance, bool, error) {
	instance, err := scanPostgresInstance(query.QueryRowContext(ctx, `SELECT instance_id,team_id,challenge_id,cluster_id,reservation_id,
        phase,desired_state,generation,created_by,security_profile,resource_profile,network_profile,namespace,endpoint,
        expires_at,last_error_message,created_at,updated_at FROM instances
        WHERE team_id=$1 AND challenge_id=$2 AND phase IN ('REQUESTED','PROVISIONING','VERIFYING','READY','TERMINATING')
        LIMIT 1`, teamID, challengeID))
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, false, nil
	}
	return instance, err == nil, err
}

func postgresInstanceByID(ctx context.Context, query postgresQuerier, instanceID string) (Instance, error) {
	return scanPostgresInstance(query.QueryRowContext(ctx, `SELECT instance_id,team_id,challenge_id,cluster_id,reservation_id,
        phase,desired_state,generation,created_by,security_profile,resource_profile,network_profile,namespace,endpoint,
        expires_at,last_error_message,created_at,updated_at FROM instances WHERE instance_id=$1`, instanceID))
}

func scanPostgresInstance(row rowScanner) (Instance, error) {
	var instance Instance
	err := row.Scan(&instance.InstanceID, &instance.TeamID, &instance.ChallengeID, &instance.ClusterID,
		&instance.ReservationID, &instance.Phase, &instance.DesiredState, &instance.Generation, &instance.CreatedBy,
		&instance.SecurityProfile, &instance.ResourceProfile, &instance.NetworkProfile, &instance.Namespace,
		&instance.Endpoint, &instance.ExpiresAt, &instance.LastError, &instance.CreatedAt, &instance.UpdatedAt)
	return instance, err
}
