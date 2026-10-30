-- Only a create guarded from its first execution can confirm reclaimed cleanup.
-- Historical unguarded attempts must not be upgraded from absence alone.
ALTER TABLE runtime_operations
    ADD COLUMN IF NOT EXISTS create_execution_fenced BOOLEAN NOT NULL DEFAULT FALSE;
