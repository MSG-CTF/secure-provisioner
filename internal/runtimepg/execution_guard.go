package runtimepg

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

// WithLeaseExecution serializes external side effects independently of the DB
// lease. Claim skips this session lock, even when its lease has expired.
// PostgreSQL releases it if the Runtime process exits.
func (store *OperationStore) WithLeaseExecution(ctx context.Context, claimed operations.ClaimedOperation, execute func(context.Context, operations.ClaimedOperation) error) error {
	if store.executionLocks == nil {
		return errors.New("operation execution lock pool is required")
	}
	conn, err := store.executionLocks.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,83))`, claimed.Operation.ID).Scan(&locked); err != nil {
		// Never pool a session whose lock acquisition response was lost.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		return err
	}
	if !locked {
		return operations.ErrExecutionBusy
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		if err := conn.QueryRowContext(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1,83))`, claimed.Operation.ID).Scan(&unlocked); err != nil || !unlocked {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	// A paused claimant must not execute after another owner reclaimed it.
	// Upgrade the protocol marker only on the first attempt: an old unguarded
	// execution cannot acquire cleanup proof merely by reading it as absent.
	err = conn.QueryRowContext(ctx, `UPDATE runtime_operations
		SET create_execution_fenced=create_execution_fenced OR (operation_type='CREATE' AND attempt=1 AND lease_version=1)
		WHERE operation_id=$1 AND status='RUNNING' AND lease_owner=$2 AND lease_version=$3
		  AND lease_until > clock_timestamp()
		RETURNING create_execution_fenced`, claimed.Operation.ID, claimed.Lease.Owner, claimed.Lease.Version).Scan(&claimed.Operation.CreateCleanupFenced)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return operations.ErrLeaseLost
		}
		return err
	}
	executeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-executeCtx.Done():
				done <- nil
				return
			case <-ticker.C:
				checkCtx, end := context.WithTimeout(executeCtx, time.Second)
				err := conn.PingContext(checkCtx)
				end()
				if err != nil {
					cancel()
					done <- err
					return
				}
			}
		}
	}()
	err = execute(executeCtx, claimed)
	close(stop)
	return errors.Join(err, <-done)
}
