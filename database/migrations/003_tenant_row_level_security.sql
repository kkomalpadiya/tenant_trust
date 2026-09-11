DO $create_runtime_role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_app') THEN
    CREATE ROLE tenant_trust_app;
  END IF;
END
$create_runtime_role$;

ALTER ROLE tenant_trust_app
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS
  PASSWORD NULL;

CREATE FUNCTION identity.current_tenant_id()
RETURNS identity.tenant_id
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, identity
AS $function$
  SELECT NULLIF(current_setting('tenant_trust.tenant_id', true), '')::identity.tenant_id
$function$;

CREATE FUNCTION identity.set_tenant_context(p_tenant_id identity.tenant_id)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM identity.tenants
    WHERE tenant_id = p_tenant_id
      AND state = 'active'
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = 'Tenant context denied.';
  END IF;

  PERFORM set_config('tenant_trust.tenant_id', p_tenant_id::text, true);
END
$function$;

REVOKE ALL ON FUNCTION identity.current_tenant_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.set_tenant_context(identity.tenant_id) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.current_tenant_id() TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION identity.set_tenant_context(identity.tenant_id) TO tenant_trust_app;

ALTER TABLE identity.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_current_tenant
  ON identity.tenants
  FOR ALL
  TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id())
  WITH CHECK (tenant_id = identity.current_tenant_id());

ALTER TABLE identity.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.tenant_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY memberships_current_tenant
  ON identity.tenant_memberships
  FOR ALL
  TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id())
  WITH CHECK (tenant_id = identity.current_tenant_id());

ALTER TABLE identity.tenant_role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.tenant_role_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_roles_current_tenant
  ON identity.tenant_role_assignments
  FOR ALL
  TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id())
  WITH CHECK (tenant_id = identity.current_tenant_id());

ALTER TABLE identity.subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.subjects FORCE ROW LEVEL SECURITY;
CREATE POLICY subjects_visible_by_current_membership
  ON identity.subjects
  FOR SELECT
  TO tenant_trust_app
  USING (
    EXISTS (
      SELECT 1
      FROM identity.tenant_memberships AS membership
      WHERE membership.tenant_id = identity.current_tenant_id()
        AND membership.subject_id = subjects.subject_id
    )
  );

REVOKE ALL ON ALL TABLES IN SCHEMA identity FROM tenant_trust_app;
GRANT USAGE ON SCHEMA identity TO tenant_trust_app;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON identity.tenants, identity.tenant_memberships, identity.tenant_role_assignments
  TO tenant_trust_app;
GRANT SELECT ON identity.subjects TO tenant_trust_app;

COMMENT ON ROLE tenant_trust_app IS 'NOLOGIN runtime privilege set; assume only after trusted tenant context resolution';
COMMENT ON FUNCTION identity.current_tenant_id() IS 'Returns the transaction-local tenant binding used by row-level security';
COMMENT ON FUNCTION identity.set_tenant_context(identity.tenant_id) IS 'Binds one active tenant to the current transaction; call immediately after BEGIN';
