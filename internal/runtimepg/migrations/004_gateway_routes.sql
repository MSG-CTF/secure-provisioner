CREATE TABLE IF NOT EXISTS runtime_gateway_routes (
 instance_id TEXT PRIMARY KEY,
 target_id TEXT NOT NULL,
 namespace_uid TEXT NOT NULL,
 service_uid TEXT NOT NULL,
 target_ip TEXT NOT NULL,
 target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
 protocol TEXT NOT NULL CHECK(protocol IN ('http','tcp')),
 phase TEXT NOT NULL CHECK(phase IN ('APPLY_PENDING','APPLIED','DELETE_PENDING','ROUTE_DELETED','DELETED')),
 snapshot JSONB NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS runtime_gateway_port_claim
 ON runtime_gateway_routes(target_ip,target_port) WHERE phase <> 'DELETED';
CREATE INDEX IF NOT EXISTS runtime_gateway_pending_target
 ON runtime_gateway_routes(target_id) WHERE phase IN ('DELETE_PENDING','ROUTE_DELETED');
