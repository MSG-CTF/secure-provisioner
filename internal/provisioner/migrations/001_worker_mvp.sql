CREATE TABLE IF NOT EXISTS instances (
    instance_id TEXT PRIMARY KEY,
    team_id BIGINT NOT NULL CHECK (team_id > 0),
    challenge_id TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    runtime_workload_id TEXT,
    spec_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    phase TEXT NOT NULL CHECK (phase IN ('REQUESTED', 'PROVISIONING', 'VERIFYING', 'READY', 'FAILED', 'TERMINATING', 'TERMINATED', 'DELETE_FAILED')),
    desired_state TEXT NOT NULL CHECK (desired_state IN ('RUNNING', 'TERMINATED')),
    generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_by TEXT NOT NULL DEFAULT '',
    security_profile TEXT NOT NULL DEFAULT '',
    resource_profile TEXT NOT NULL DEFAULT '',
    network_profile TEXT NOT NULL DEFAULT '',
    namespace TEXT NOT NULL DEFAULT '',
    endpoint TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    last_error_code TEXT NOT NULL DEFAULT '',
    last_error_message TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    ready_at TIMESTAMPTZ,
    terminated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS instances_active_team_challenge_idx
    ON instances (team_id, challenge_id)
    WHERE phase IN ('REQUESTED', 'PROVISIONING', 'VERIFYING', 'READY', 'TERMINATING');

CREATE INDEX IF NOT EXISTS instances_expiration_idx ON instances (phase, expires_at);
CREATE INDEX IF NOT EXISTS instances_cluster_phase_idx ON instances (cluster_id, phase);

CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    cluster_id TEXT NOT NULL,
    operation_type TEXT NOT NULL CHECK (operation_type IN ('CREATE', 'DELETE')),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'RETRY_WAIT', 'SUCCEEDED', 'FAILED')),
    priority INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 4 CHECK (max_attempts > 0),
    next_retry_at TIMESTAMPTZ,
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_until TIMESTAMPTZ,
    last_error_code TEXT NOT NULL DEFAULT '',
    last_error_message TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS operations_claim_idx
    ON operations (priority DESC, created_at ASC)
    WHERE status IN ('PENDING', 'RUNNING', 'RETRY_WAIT');

CREATE INDEX IF NOT EXISTS operations_cluster_status_idx ON operations (cluster_id, status);
CREATE INDEX IF NOT EXISTS operations_instance_created_idx ON operations (instance_id, created_at DESC);
