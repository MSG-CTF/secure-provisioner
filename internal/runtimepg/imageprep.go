package runtimepg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"github.com/google/uuid"
)

type ImagePreparationStore struct{ db *sql.DB }

var _ imageprep.Store = (*ImagePreparationStore)(nil)

func (d *Database) ImagePreparations() *ImagePreparationStore {
	return &ImagePreparationStore{db: d.db}
}
func decodePreparation(row interface{ Scan(...any) error }) (imageprep.Record, error) {
	var b []byte
	err := row.Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return imageprep.Record{}, imageprep.ErrNotFound
	}
	var r imageprep.Record
	if err == nil {
		err = json.Unmarshal(b, &r)
	}
	return r, err
}
func (s *ImagePreparationStore) Find(ctx context.Context, scope, endpoint, id string) (imageprep.Record, bool, error) {
	r, err := decodePreparation(s.db.QueryRowContext(ctx, "SELECT body FROM image_preparation_operations WHERE scope=$1 AND endpoint=$2 AND request_id=$3", scope, endpoint, id))
	if errors.Is(err, imageprep.ErrNotFound) {
		return r, false, nil
	}
	return r, err == nil, err
}
func (s *ImagePreparationStore) Get(ctx context.Context, id string) (imageprep.Record, error) {
	return decodePreparation(s.db.QueryRowContext(ctx, "SELECT body FROM image_preparation_operations WHERE operation_id=$1", id))
}
func (s *ImagePreparationStore) Insert(ctx context.Context, r imageprep.Record) (imageprep.Record, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO image_preparation_operations(operation_id,scope,endpoint,request_id,fingerprint,status,next_attempt_at,body) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(scope,endpoint,request_id) DO NOTHING`, r.Operation.ID, r.Scope, r.Endpoint, r.Operation.RequestID, r.Fingerprint, r.Operation.Status, r.Next, b)
	if err != nil {
		return imageprep.Record{}, err
	}
	old, _, err := s.Find(ctx, r.Scope, r.Endpoint, r.Operation.RequestID)
	if err == nil && old.Fingerprint != r.Fingerprint {
		return imageprep.Record{}, imageprep.ErrConflict
	}
	return old, err
}
func (s *ImagePreparationStore) Claim(ctx context.Context, now time.Time, d time.Duration) (imageprep.Record, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return imageprep.Record{}, false, err
	}
	defer tx.Rollback()
	r, err := decodePreparation(tx.QueryRowContext(ctx, `SELECT body FROM image_preparation_operations WHERE status IN ('QUEUED','RUNNING') AND next_attempt_at <= $1 AND lease_until <= $1 ORDER BY next_attempt_at,operation_id FOR UPDATE SKIP LOCKED LIMIT 1`, now))
	if errors.Is(err, imageprep.ErrNotFound) {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	r.Lease = uuid.NewString()
	r.LeaseUntil = now.Add(d)
	b, err := json.Marshal(r)
	if err != nil {
		return r, false, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE image_preparation_operations SET lease_token=$2,lease_until=$3,body=$4 WHERE operation_id=$1`, r.Operation.ID, r.Lease, r.LeaseUntil, b)
	if err != nil {
		return r, false, err
	}
	err = tx.Commit()
	return r, err == nil, err
}
func (s *ImagePreparationStore) Save(ctx context.Context, r imageprep.Record, release bool) error {
	token := r.Lease
	leaseUntil := r.LeaseUntil
	if release {
		r.Lease = ""
		r.LeaseUntil = time.Time{}
		leaseUntil = time.Unix(0, 0)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE image_preparation_operations SET status=$3,next_attempt_at=$4,lease_token=$5,lease_until=$6,body=$7 WHERE operation_id=$1 AND lease_token=$2 AND lease_until > CURRENT_TIMESTAMP`, r.Operation.ID, token, r.Operation.Status, r.Next, r.Lease, leaseUntil, b)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return imageprep.ErrLeaseLost
	}
	return err
}
func (s *ImagePreparationStore) Watch(ctx context.Context) ([]imageprep.Query, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT body->'Request' FROM image_preparation_operations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	queries := []imageprep.Query{}
	seen := map[string]bool{}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var r imageprep.Request
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		for _, target := range r.TargetIDs {
			key := target + imageprep.ImageSetID(r.Architecture, r.Images())
			if !seen[key] {
				queries = append(queries, imageprep.Query{Architecture: r.Architecture, Images: r.Images(), TargetIDs: []string{target}})
				seen[key] = true
			}
		}
	}
	return queries, rows.Err()
}
func (s *ImagePreparationStore) PutObservation(ctx context.Context, o imageprep.Observation) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO image_preparation_observations(target_id,image_set_id,observed_at,body) VALUES($1,$2,$3,$4) ON CONFLICT(target_id,image_set_id) DO UPDATE SET observed_at=EXCLUDED.observed_at,body=EXCLUDED.body WHERE image_preparation_observations.observed_at <= EXCLUDED.observed_at`, o.TargetID, o.ImageSetID, o.ObservedAt, b)
	return err
}
func (s *ImagePreparationStore) Observation(ctx context.Context, target, id string) (imageprep.Observation, bool, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, "SELECT body FROM image_preparation_observations WHERE target_id=$1 AND image_set_id=$2", target, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return imageprep.Observation{}, false, nil
	}
	var o imageprep.Observation
	if err == nil {
		err = json.Unmarshal(b, &o)
	}
	return o, err == nil, err
}
func (s *ImagePreparationStore) LockNode(ctx context.Context, node, owner string, now time.Time, d time.Duration) (bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO image_preparation_node_locks(node_uid,owner,lease_until) VALUES($1,$2,$3) ON CONFLICT(node_uid) DO UPDATE SET owner=EXCLUDED.owner,lease_until=EXCLUDED.lease_until WHERE image_preparation_node_locks.lease_until <= $4`, node, owner, now.Add(d), now)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}
func (s *ImagePreparationStore) UnlockNode(ctx context.Context, node, owner string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM image_preparation_node_locks WHERE node_uid=$1 AND owner=$2", node, owner)
	return err
}
