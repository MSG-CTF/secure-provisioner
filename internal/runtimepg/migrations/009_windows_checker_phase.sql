-- Existing installations created by earlier Windows schema drafts may still have the original phase
-- constraint. The runtime applies migrations on every start, so this upgrade
-- must be idempotent and avoid a table scan after the first successful run.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'runtime_windows_executions'::regclass
          AND conname = 'runtime_windows_executions_phase_v2_check'
    ) THEN
        ALTER TABLE runtime_windows_executions
            DROP CONSTRAINT IF EXISTS runtime_windows_executions_phase_check;
        ALTER TABLE runtime_windows_executions
            ADD CONSTRAINT runtime_windows_executions_phase_v2_check
            CHECK (phase IN ('FETCH_PENDING','QUEUED','START_PENDING','APPROVED','CONNECTING','RUNNING','FINISHED','REJECTED','BLOCKED'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS runtime_windows_executions_claim_v2_idx
    ON runtime_windows_executions (created_at, execution_id, next_attempt, lease_until)
    WHERE phase IN ('FETCH_PENDING','QUEUED','START_PENDING','APPROVED','CONNECTING','RUNNING')
       OR (phase = 'FINISHED' AND (finished_pending OR record_json->'checker'->>'result_pending' = 'true'))
       OR (phase = 'REJECTED' AND record_json->'checker'->>'result_pending' = 'true');

DROP INDEX IF EXISTS runtime_windows_executions_claim_idx;
