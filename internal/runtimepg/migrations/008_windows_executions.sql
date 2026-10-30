CREATE TABLE IF NOT EXISTS runtime_windows_executions (
    execution_id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE,
    target_id UUID NOT NULL,
    fingerprint TEXT NOT NULL,
    phase TEXT NOT NULL CONSTRAINT runtime_windows_executions_phase_v2_check
        CHECK (phase IN ('FETCH_PENDING','QUEUED','START_PENDING','APPROVED','CONNECTING','RUNNING','FINISHED','REJECTED','BLOCKED')),
    finished_pending BOOLEAN NOT NULL DEFAULT FALSE,
    record_json JSONB NOT NULL,
    payload BYTEA NOT NULL CHECK (octet_length(payload) <= 10485760),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    next_attempt TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK ((lease_owner IS NULL AND lease_until IS NULL) OR
           (lease_owner IS NOT NULL AND lease_owner <> '' AND lease_until IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS runtime_windows_executions_claim_v2_idx
    ON runtime_windows_executions (created_at, execution_id, next_attempt, lease_until)
    WHERE phase IN ('FETCH_PENDING','QUEUED','START_PENDING','APPROVED','CONNECTING','RUNNING')
       OR (phase = 'FINISHED' AND (finished_pending OR record_json->'checker'->>'result_pending' = 'true'))
       OR (phase = 'REJECTED' AND record_json->'checker'->>'result_pending' = 'true');

CREATE INDEX IF NOT EXISTS runtime_windows_executions_vm_idx
    ON runtime_windows_executions (target_id, phase, finished_pending, lease_until);
