CREATE TABLE IF NOT EXISTS image_preparation_operations (
 operation_id text PRIMARY KEY,
 scope text NOT NULL,
 endpoint text NOT NULL,
 request_id text NOT NULL,
 fingerprint text NOT NULL,
 status text NOT NULL,
 next_attempt_at timestamptz NOT NULL,
 lease_token text NOT NULL DEFAULT '',
 lease_until timestamptz NOT NULL DEFAULT '-infinity',
 body jsonb NOT NULL,
 UNIQUE(scope, endpoint, request_id)
);
CREATE INDEX IF NOT EXISTS image_preparation_pending ON image_preparation_operations(next_attempt_at) WHERE status IN ('QUEUED','RUNNING');
CREATE TABLE IF NOT EXISTS image_preparation_observations (
 target_id text NOT NULL,
 image_set_id text NOT NULL,
 observed_at timestamptz NOT NULL,
 body jsonb NOT NULL,
 PRIMARY KEY(target_id,image_set_id)
);
CREATE TABLE IF NOT EXISTS image_preparation_node_locks (
 node_uid text PRIMARY KEY,
 owner text NOT NULL,
 lease_until timestamptz NOT NULL
);
