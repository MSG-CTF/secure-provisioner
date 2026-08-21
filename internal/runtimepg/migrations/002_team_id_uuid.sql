DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'runtime_bindings'
          AND column_name = 'team_id'
          AND data_type = 'bigint'
    ) THEN
        IF EXISTS (SELECT 1 FROM runtime_bindings) OR
           EXISTS (SELECT 1 FROM runtime_operations) THEN
            RAISE EXCEPTION
                'cannot migrate team_id from BIGINT to UUID while legacy runtime state exists';
        END IF;

        ALTER TABLE runtime_bindings
            DROP CONSTRAINT IF EXISTS runtime_bindings_team_id_check;
        ALTER TABLE runtime_bindings
            ALTER COLUMN team_id TYPE UUID USING team_id::text::uuid;
    END IF;
END
$$;
