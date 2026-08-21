CREATE TABLE IF NOT EXISTS runtime_operations (
    operation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    operation_type TEXT NOT NULL CHECK (operation_type IN ('CREATE','DELETE')),
    status TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','RETRYING','SUCCEEDED','FAILED')),
    priority INTEGER NOT NULL,
    command_snapshot JSONB NOT NULL,
    create_checkpoint JSONB,
    result JSONB,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    next_retry_at TIMESTAMPTZ,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    lease_version BIGINT NOT NULL DEFAULT 0,
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS runtime_operations_claim_idx
    ON runtime_operations (priority DESC, created_at ASC, next_retry_at, lease_until)
    WHERE status IN ('QUEUED','RUNNING','RETRYING');

CREATE TABLE IF NOT EXISTS runtime_bindings (
    instance_id TEXT PRIMARY KEY,
    team_id BIGINT NOT NULL CHECK (team_id > 0),
    target_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    namespace_uid TEXT NOT NULL,
    runtime_workload_id TEXT NOT NULL,
    endpoints JSONB NOT NULL DEFAULT '[]'::jsonb,
    policy_snapshot JSONB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('CREATED','DELETING','DELETED')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ
);
