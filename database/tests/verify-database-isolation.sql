\set ON_ERROR_STOP on

DO $verify_isolation_configuration$
DECLARE
  runtime_role record;
  protected_tables integer;
  tenant_policies integer;
BEGIN
  SELECT rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolbypassrls
  INTO STRICT runtime_role
  FROM pg_roles
  WHERE rolname = 'tenant_trust_app';

  IF runtime_role.rolsuper
     OR runtime_role.rolcreaterole
     OR runtime_role.rolcreatedb
     OR runtime_role.rolcanlogin
     OR runtime_role.rolbypassrls THEN
    RAISE EXCEPTION 'tenant_trust_app has an unsafe role attribute';
  END IF;

  SELECT count(*) INTO protected_tables
  FROM pg_class AS relation
  JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'identity'
    AND relation.relname IN ('tenants', 'subjects', 'tenant_memberships', 'tenant_role_assignments')
    AND relation.relrowsecurity
    AND relation.relforcerowsecurity;

  IF protected_tables <> 4 THEN
    RAISE EXCEPTION 'expected four forced-RLS identity tables, found %', protected_tables;
  END IF;

  SELECT count(*) INTO tenant_policies
  FROM pg_policies
  WHERE schemaname = 'identity'
    AND policyname IN (
      'tenants_current_tenant',
      'memberships_current_tenant',
      'tenant_roles_current_tenant',
      'subjects_visible_by_current_membership'
    )
    AND 'tenant_trust_app' = ANY(roles);

  IF tenant_policies <> 4 THEN
    RAISE EXCEPTION 'expected four tenant isolation policies, found %', tenant_policies;
  END IF;

  IF has_table_privilege('tenant_trust_app', 'identity.platform_role_assignments', 'SELECT') THEN
    RAISE EXCEPTION 'tenant runtime role can read platform role assignments';
  END IF;
END
$verify_isolation_configuration$;

SET ROLE tenant_trust_app;
CREATE TEMP TABLE isolation_connection_probe (
  backend_pid integer PRIMARY KEY
) ON COMMIT PRESERVE ROWS;
INSERT INTO isolation_connection_probe VALUES (pg_backend_pid());

BEGIN;
SELECT identity.set_tenant_context('tnt_018f1234-5678-7abc-8def-0123456789ab');

DO $verify_alpha_scope$
DECLARE
  affected integer;
BEGIN
  IF identity.current_tenant_id() <> 'tnt_018f1234-5678-7abc-8def-0123456789ab' THEN
    RAISE EXCEPTION 'Tenant Alpha context was not installed';
  END IF;
  IF (SELECT count(*) FROM identity.tenants) <> 1
     OR (SELECT count(*) FROM identity.tenant_memberships) <> 2
     OR (SELECT count(*) FROM identity.tenant_role_assignments) <> 2
     OR (SELECT count(*) FROM identity.subjects) <> 2 THEN
    RAISE EXCEPTION 'Tenant Alpha did not receive exactly its own identity rows';
  END IF;

  UPDATE identity.tenants
  SET display_name = display_name
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 1 THEN
    RAISE EXCEPTION 'Tenant Alpha could not update its own scoped row';
  END IF;

  UPDATE identity.tenants
  SET display_name = display_name
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 0 THEN
    RAISE EXCEPTION 'Tenant Alpha updated a Tenant Beta row';
  END IF;

  BEGIN
    INSERT INTO identity.tenant_memberships (tenant_id, subject_id)
    VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ac',
      'sub_018f1234-5678-7abc-8def-0123456789ab'
    );
    RAISE EXCEPTION 'Tenant Alpha inserted a Tenant Beta row';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_alpha_scope$;
ROLLBACK;

BEGIN;
DO $verify_reused_connection_is_empty$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM isolation_connection_probe WHERE backend_pid = pg_backend_pid()
  ) THEN
    RAISE EXCEPTION 'verification did not reuse the same database session';
  END IF;
  IF identity.current_tenant_id() IS NOT NULL THEN
    RAISE EXCEPTION 'transaction-local tenant context leaked into a reused transaction';
  END IF;
  IF (SELECT count(*) FROM identity.tenants) <> 0
     OR (SELECT count(*) FROM identity.tenant_memberships) <> 0
     OR (SELECT count(*) FROM identity.tenant_role_assignments) <> 0
     OR (SELECT count(*) FROM identity.subjects) <> 0 THEN
    RAISE EXCEPTION 'a reused connection without context could read tenant rows';
  END IF;
END
$verify_reused_connection_is_empty$;
ROLLBACK;

BEGIN;
SELECT identity.set_tenant_context('tnt_018f1234-5678-7abc-8def-0123456789ac');

DO $verify_beta_scope$
BEGIN
  IF identity.current_tenant_id() <> 'tnt_018f1234-5678-7abc-8def-0123456789ac' THEN
    RAISE EXCEPTION 'Tenant Beta context was not installed';
  END IF;
  IF (SELECT count(*) FROM identity.tenants) <> 1
     OR (SELECT count(*) FROM identity.tenant_memberships) <> 2
     OR (SELECT count(*) FROM identity.tenant_role_assignments) <> 2
     OR (SELECT count(*) FROM identity.subjects) <> 2 THEN
    RAISE EXCEPTION 'Tenant Beta did not receive exactly its own identity rows';
  END IF;
END
$verify_beta_scope$;
ROLLBACK;

RESET ROLE;

\echo 'PASS forced RLS scopes reads and writes and clears tenant state on connection reuse'
