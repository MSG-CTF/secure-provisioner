package runtimepg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// AcquireDeploymentHandoff waits for active executions to finish, then fences
// legacy as well as new workers until systemd has stopped the primary. A plain
// idle count has a race with Claim; the SHARE lock also fences future claims.
// Reads continue. Queue writes wait only for the bounded primary stop, never for
// its replacement to initialize. No workload, operation, or binding is changed.
func (database *Database) AcquireDeploymentHandoff(ctx context.Context) (func() error, error) {
	for ctx.Err() == nil {
		tx, err := database.db.BeginTx(context.Background(), nil)
		if err != nil {
			return nil, errors.New("deployment handoff transaction failed")
		}
		_, err = tx.ExecContext(ctx, "LOCK TABLE runtime_operations IN SHARE MODE NOWAIT")
		if err == nil {
			var running int
			err = tx.QueryRowContext(ctx, "SELECT count(*) FROM runtime_operations WHERE status='RUNNING'").Scan(&running)
			if err != nil {
				_ = tx.Rollback()
				return nil, errors.New("runtime operation state could not be verified")
			}
			if running == 0 {
				// Release even if the deployer or its pipe disappears. This also
				// bounds the short wait experienced by an arriving queue write.
				if _, err = tx.ExecContext(ctx, "SET LOCAL idle_in_transaction_session_timeout='3s'"); err == nil {
					return tx.Rollback, nil
				}
			}
		}
		_ = tx.Rollback()
		if err != nil {
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
				return nil, errors.New("runtime handoff lock could not be acquired")
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, errors.New("active runtime operations did not drain; primary was not stopped")
}
