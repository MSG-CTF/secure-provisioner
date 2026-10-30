CREATE INDEX IF NOT EXISTS runtime_operations_create_instance_lookup
    ON runtime_operations ((command_snapshot->>'InstanceID'))
    WHERE operation_type = 'CREATE';
