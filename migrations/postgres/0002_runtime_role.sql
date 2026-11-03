-- +goose Up
-- The runtime role is created by the deployment so its password never appears
-- in a migration. It must have NOBYPASSRLS, which the integration tests assert.
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO dg_runtime;
GRANT DELETE ON source_capabilities TO dg_runtime;
GRANT EXECUTE ON FUNCTION platform_list_tenants() TO dg_runtime;
GRANT EXECUTE ON FUNCTION current_tenant_id() TO dg_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO dg_runtime;

-- +goose Down
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT, INSERT, UPDATE ON TABLES FROM dg_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM dg_runtime;
REVOKE ALL ON FUNCTION platform_list_tenants() FROM dg_runtime;
REVOKE ALL ON FUNCTION current_tenant_id() FROM dg_runtime;
