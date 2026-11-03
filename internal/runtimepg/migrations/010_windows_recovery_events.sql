CREATE TABLE IF NOT EXISTS runtime_windows_recovery_events (
    execution_id UUID PRIMARY KEY REFERENCES runtime_windows_executions(execution_id),
    target_id UUID NOT NULL,
    event_id UUID NOT NULL UNIQUE,
    recovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    backend_cleanup_state TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (backend_cleanup_state IN ('PENDING', 'CONFIRMED')),
    backend_cleanup_confirmed_at TIMESTAMPTZ,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    next_attempt TIMESTAMPTZ,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    CHECK ((lease_owner IS NULL AND lease_until IS NULL) OR
           (lease_owner IS NOT NULL AND lease_owner <> '' AND lease_until IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS runtime_windows_recovery_pending_idx
    ON runtime_windows_recovery_events (recovered_at, execution_id)
    WHERE backend_cleanup_state = 'PENDING';
