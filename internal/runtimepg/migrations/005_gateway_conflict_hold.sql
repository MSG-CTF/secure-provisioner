ALTER TABLE runtime_gateway_routes DROP CONSTRAINT IF EXISTS runtime_gateway_routes_phase_check;
ALTER TABLE runtime_gateway_routes ADD CONSTRAINT runtime_gateway_routes_phase_check
 CHECK(phase IN ('APPLY_PENDING','APPLIED','CONFLICT_HOLD','DELETE_PENDING','ROUTE_DELETED','DELETED'));
CREATE INDEX IF NOT EXISTS runtime_gateway_target_idx ON runtime_gateway_routes(target_id);
