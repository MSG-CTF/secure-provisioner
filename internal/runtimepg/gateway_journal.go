package runtimepg

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/gateway"
	"time"
)

const gatewayLockConnections = 8

type GatewayJournal struct {
	db     *sql.DB
	locks  *sql.DB
	budget chan struct{}
}

func (d *Database) GatewayJournal() *GatewayJournal {
	return &GatewayJournal{db: d.db, locks: d.gatewayLocks, budget: d.gatewayLockBudget}
}
func (j *GatewayJournal) HasLiveRoutes(ctx context.Context) (bool, error) {
	var exists bool
	if err := j.db.QueryRowContext(ctx, `SELECT to_regclass('runtime_gateway_routes') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return false, err
	}
	var live bool
	err := j.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM runtime_gateway_routes WHERE phase <> 'DELETED')`).Scan(&live)
	return live, err
}
func (j *GatewayJournal) Get(ctx context.Context, id string) (gateway.Record, error) {
	var raw []byte
	err := j.db.QueryRowContext(ctx, `SELECT snapshot FROM runtime_gateway_routes WHERE instance_id=$1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return gateway.Record{}, gateway.ErrNotFound
	}
	if err != nil {
		return gateway.Record{}, err
	}
	var r gateway.Record
	err = json.Unmarshal(raw, &r)
	return r, err
}
func (j *GatewayJournal) HasPendingCleanup(ctx context.Context, target string) (bool, error) {
	var pending bool
	err := j.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM runtime_gateway_routes WHERE target_id=$1 AND phase IN ('DELETE_PENDING','ROUTE_DELETED','CONFLICT_HOLD'))`, target).Scan(&pending)
	return pending, err
}
func (j *GatewayJournal) WithLock(ctx context.Context, id string, fn func(gateway.Session) error) error {
	select {
	case j.budget <- struct{}{}:
		defer func() { <-j.budget }()
	default:
		return errors.New("Gateway lifecycle lock budget busy")
	}
	conn, err := j.locks.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// A session lock deliberately survives each autocommit Save. A transaction
	// lock would leave the intent invisible until after the remote HTTP request.
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1,73))`, id); err != nil {
		return err
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		if err := conn.QueryRowContext(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1,73))`, id).Scan(&unlocked); err != nil || !unlocked {
			// Never return a connection holding a session lock to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	return fn(&gatewaySession{ctx: ctx, conn: conn, id: id})
}

type gatewaySession struct {
	ctx  context.Context
	conn *sql.Conn
	id   string
}

func (s *gatewaySession) Load() (gateway.Record, error) {
	var raw []byte
	err := s.conn.QueryRowContext(s.ctx, `SELECT snapshot FROM runtime_gateway_routes WHERE instance_id=$1`, s.id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return gateway.Record{}, gateway.ErrNotFound
	}
	if err != nil {
		return gateway.Record{}, err
	}
	var r gateway.Record
	err = json.Unmarshal(raw, &r)
	return r, err
}
func (s *gatewaySession) Save(r gateway.Record) error {
	if r.Command.InstanceID != s.id {
		return gateway.ErrConflict
	}
	r.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// Old commands predate these optional tracing fields. Defaults go on the
	// left so persisted nonempty identities win; every other field, including
	// unknown future fields, remains part of the immutable command comparison.
	result, err := s.conn.ExecContext(s.ctx, `INSERT INTO runtime_gateway_routes(instance_id,target_id,namespace_uid,service_uid,target_ip,target_port,protocol,phase,snapshot,updated_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(instance_id) DO UPDATE SET phase=EXCLUDED.phase,snapshot=EXCLUDED.snapshot,updated_at=EXCLUDED.updated_at
 WHERE runtime_gateway_routes.target_id=EXCLUDED.target_id AND runtime_gateway_routes.namespace_uid=EXCLUDED.namespace_uid AND runtime_gateway_routes.service_uid=EXCLUDED.service_uid
 AND runtime_gateway_routes.target_ip=EXCLUDED.target_ip AND runtime_gateway_routes.target_port=EXCLUDED.target_port AND runtime_gateway_routes.protocol=EXCLUDED.protocol
	 AND ('{"ReleaseID":"","Architecture":""}'::jsonb || (runtime_gateway_routes.snapshot->'Command'))
	     = ('{"ReleaseID":"","Architecture":""}'::jsonb || (EXCLUDED.snapshot->'Command'))
	 AND runtime_gateway_routes.snapshot->'Result'=EXCLUDED.snapshot->'Result'
 AND (runtime_gateway_routes.phase=EXCLUDED.phase
 OR (runtime_gateway_routes.phase='APPLY_PENDING' AND EXCLUDED.phase IN ('APPLIED','DELETE_PENDING','CONFLICT_HOLD'))
 OR (runtime_gateway_routes.phase='CONFLICT_HOLD' AND EXCLUDED.phase='DELETE_PENDING')
 OR (runtime_gateway_routes.phase='APPLIED' AND EXCLUDED.phase='DELETE_PENDING')
 OR (runtime_gateway_routes.phase='DELETE_PENDING' AND EXCLUDED.phase='ROUTE_DELETED')
 OR (runtime_gateway_routes.phase='ROUTE_DELETED' AND EXCLUDED.phase='DELETED'))`, s.id, r.Command.TargetID, r.Result.NamespaceUID, r.ServiceUID, r.Destination.TargetIP, r.Destination.TargetPort, r.Destination.Protocol, r.Phase, string(raw), r.UpdatedAt)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err == nil && rows != 1 {
		return gateway.ErrConflict
	}
	return err
}
