-- A reclaimed create lease leaves an older worker's side effects uncertain.
-- Do not use a later attempt's rollback as proof that all workers have stopped.
ALTER TABLE runtime_operations
    ADD COLUMN IF NOT EXISTS create_lease_reclaimed BOOLEAN NOT NULL DEFAULT FALSE;
