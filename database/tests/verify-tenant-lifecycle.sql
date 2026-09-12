\set ON_ERROR_STOP on

DO $verify_lifecycle_configuration$
DECLARE
  platform_role record;
BEGIN
  SELECT rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolbypassrls
  INTO STRICT platform_role
  FROM pg_roles
  WHERE rolname = 'tenant_trust_platform_admin';

  IF platform_role.rolsuper
     OR platform_role.rolcreaterole
     OR platform_role.rolcreatedb
     OR platform_role.rolcanlogin
     OR platform_role.rolbypassrls THEN
    RAISE EXCEPTION 'tenant_trust_platform_admin has an unsafe role attribute';
  END IF;
  IF to_regclass('audit.tenant_lifecycle_events') IS NULL THEN
    RAISE EXCEPTION 'tenant lifecycle audit table is missing';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'identity'
      AND table_name = 'tenants'
      AND column_name = 'retired_at'
  ) THEN
    RAISE EXCEPTION 'tenant irreversible retirement marker is missing';
  END IF;
  IF NOT has_function_privilege(
    'tenant_trust_platform_admin',
    'identity.suspend_tenant(identity.tenant_id,text)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'tenant_trust_platform_admin',
    'identity.reactivate_tenant(identity.tenant_id,text)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'tenant_trust_platform_admin',
    'identity.teardown_tenant(identity.tenant_id,text)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'platform lifecycle role is missing a required function grant';
  END IF;
  IF has_function_privilege(
    'tenant_trust_app',
    'identity.suspend_tenant(identity.tenant_id,text)',
    'EXECUTE'
  ) OR has_column_privilege(
    'tenant_trust_app',
    'identity.tenants',
    'state',
    'UPDATE'
  ) THEN
    RAISE EXCEPTION 'tenant runtime role can change tenant lifecycle state';
  END IF;
  IF NOT has_column_privilege(
    'tenant_trust_app',
    'identity.tenants',
    'display_name',
    'UPDATE'
  ) THEN
    RAISE EXCEPTION 'tenant administrators lost metadata update permission';
  END IF;
  IF NOT has_table_privilege(
    'tenant_trust_platform_admin',
    'audit.tenant_lifecycle_events',
    'SELECT'
  ) OR has_table_privilege(
    'tenant_trust_platform_admin',
    'audit.tenant_lifecycle_events',
    'UPDATE'
  ) THEN
    RAISE EXCEPTION 'platform lifecycle audit privileges are unsafe';
  END IF;
END
$verify_lifecycle_configuration$;

CREATE TEMP TABLE lifecycle_connection_probe (
  backend_pid integer PRIMARY KEY
) ON COMMIT PRESERVE ROWS;
INSERT INTO lifecycle_connection_probe VALUES (pg_backend_pid());
GRANT SELECT ON lifecycle_connection_probe TO tenant_trust_platform_admin;

BEGIN;
SET LOCAL ROLE tenant_trust_platform_admin;
DO $verify_non_platform_subject_denied$
BEGIN
  BEGIN
    PERFORM identity.set_platform_actor_context(
      'sub_018f1234-5678-7abc-8def-0123456789ac'
    );
    RAISE EXCEPTION 'tenant administrator received platform lifecycle authority';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_non_platform_subject_denied$;
ROLLBACK;

BEGIN;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
DO $verify_alpha_initial_access$
BEGIN
  IF NOT identity.current_actor_is_active()
     OR (SELECT count(*) FROM app.resources) <> 2 THEN
    RAISE EXCEPTION 'Alpha administrator did not start with active tenant access';
  END IF;
END
$verify_alpha_initial_access$;

RESET ROLE;
SET LOCAL ROLE tenant_trust_platform_admin;
SELECT identity.set_platform_actor_context(
  'sub_018f1234-5678-7abc-8def-0123456789af'
);
SELECT identity.suspend_tenant(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'TENANT_SECURITY_HOLD'
);

DO $verify_suspension_audit$
BEGIN
  IF (SELECT count(*) FROM audit.tenant_lifecycle_events
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND action = 'suspended'
        AND reason_code = 'TENANT_SECURITY_HOLD'
        AND requested_by_subject_id = 'sub_018f1234-5678-7abc-8def-0123456789af') <> 1 THEN
    RAISE EXCEPTION 'tenant suspension audit event is incomplete';
  END IF;
END
$verify_suspension_audit$;

RESET ROLE;
SET LOCAL ROLE tenant_trust_app;
DO $verify_existing_context_loses_access$
BEGIN
  IF identity.current_tenant_id() <> 'tnt_018f1234-5678-7abc-8def-0123456789ab'
     OR identity.current_subject_id() <> 'sub_018f1234-5678-7abc-8def-0123456789ac' THEN
    RAISE EXCEPTION 'test did not retain the original actor binding';
  END IF;
  IF identity.current_actor_is_active()
     OR (SELECT count(*) FROM identity.tenants) <> 0
     OR (SELECT count(*) FROM identity.tenant_memberships) <> 0
     OR (SELECT count(*) FROM app.resources) <> 0
     OR (SELECT count(*) FROM identity.tenant_issuer_mappings) <> 0
     OR (SELECT count(*) FROM trust.evidence_sources) <> 0
     OR (SELECT count(*) FROM trust.trust_configurations) <> 0
     OR (SELECT count(*) FROM trust.policy_versions) <> 0 THEN
    RAISE EXCEPTION 'suspended tenant retained activity through an existing context';
  END IF;
  BEGIN
    PERFORM identity.set_tenant_actor_context(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ac'
    );
    RAISE EXCEPTION 'suspended tenant received a new actor context';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_existing_context_loses_access$;

RESET ROLE;
SET LOCAL ROLE tenant_trust_platform_admin;
SELECT identity.reactivate_tenant(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'TENANT_SECURITY_REVIEW_COMPLETE'
);

RESET ROLE;
SET LOCAL ROLE tenant_trust_app;
DO $verify_reactivation_restores_existing_context$
BEGIN
  IF NOT identity.current_actor_is_active()
     OR (SELECT count(*) FROM app.resources) <> 2 THEN
    RAISE EXCEPTION 'governed reactivation did not restore Alpha access';
  END IF;
END
$verify_reactivation_restores_existing_context$;
ROLLBACK;

BEGIN;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
DO $verify_tenant_admin_cannot_suspend_tenant$
BEGIN
  BEGIN
    UPDATE identity.tenants
    SET state = 'suspended', version = version + 1, updated_at = clock_timestamp()
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab';
    RAISE EXCEPTION 'tenant administrator directly changed tenant lifecycle state';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_tenant_admin_cannot_suspend_tenant$;
ROLLBACK;

BEGIN;
SET LOCAL ROLE tenant_trust_platform_admin;
SELECT identity.set_platform_actor_context(
  'sub_018f1234-5678-7abc-8def-0123456789af'
);
SELECT identity.suspend_tenant(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'TENANT_OFFBOARDING_REQUESTED'
);
SELECT identity.teardown_tenant(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'TENANT_RETENTION_STARTED'
);

DO $verify_teardown_audit_visibility$
BEGIN
  IF (SELECT count(*) FROM audit.tenant_lifecycle_events
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac') <> 2 THEN
    RAISE EXCEPTION 'platform lifecycle history is incomplete after teardown';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM audit.tenant_lifecycle_events
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
      AND action = 'teardown_completed'
      AND details @> '{"membershipsRetained":2,"rolesRemoved":2,"resourcesRetained":2,"issuersRetired":1,"evidenceSourcesRetired":5,"trustConfigurationsRetained":1,"policyVersionsRetained":1}'::jsonb
  ) THEN
    RAISE EXCEPTION 'teardown retention counts were not audited';
  END IF;

  BEGIN
    PERFORM identity.reactivate_tenant(
      'tnt_018f1234-5678-7abc-8def-0123456789ac',
      'UNAUTHORIZED_RETIREMENT_REVERSAL'
    );
    RAISE EXCEPTION 'retired tenant was reactivated';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$verify_teardown_audit_visibility$;

RESET ROLE;
DO $verify_teardown_retention_and_revocation$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM identity.tenants
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
      AND state = 'suspended'
      AND retired_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'teardown did not irreversibly retire Tenant Beta';
  END IF;
  IF (SELECT count(*) FROM identity.tenant_memberships
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
        AND state = 'suspended') <> 2 THEN
    RAISE EXCEPTION 'teardown did not retain and suspend Beta memberships';
  END IF;
  IF EXISTS (
    SELECT 1 FROM identity.tenant_role_assignments
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
  ) THEN
    RAISE EXCEPTION 'teardown retained an effective Beta tenant role';
  END IF;
  IF (SELECT count(*) FROM app.resources
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac') <> 2
     OR (SELECT count(*) FROM identity.tenant_issuer_mappings
         WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
           AND state = 'retired') <> 1
     OR (SELECT count(*) FROM trust.evidence_sources
         WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
           AND state = 'retired') <> 5
     OR (SELECT count(*) FROM trust.trust_configurations
         WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac') <> 1
     OR (SELECT count(*) FROM trust.policy_versions
         WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac') <> 1 THEN
    RAISE EXCEPTION 'teardown lost retained tenant-owned history';
  END IF;
  IF (SELECT count(*) FROM identity.subjects
      WHERE subject_id IN (
        'sub_018f1234-5678-7abc-8def-0123456789ad',
        'sub_018f1234-5678-7abc-8def-0123456789ae'
      )) <> 2 THEN
    RAISE EXCEPTION 'teardown deleted platform subject identities';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM identity.tenants
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND state = 'active'
      AND retired_at IS NULL
  ) OR (SELECT count(*) FROM identity.tenant_role_assignments
        WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab') <> 2 THEN
    RAISE EXCEPTION 'Beta teardown changed Alpha tenant state or privileges';
  END IF;

  BEGIN
    UPDATE audit.tenant_lifecycle_events
    SET reason_code = 'ALTERED_AUDIT_HISTORY'
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac';
    RAISE EXCEPTION 'tenant lifecycle audit event was mutable';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    DELETE FROM identity.tenants
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac';
    RAISE EXCEPTION 'retired tenant was physically deleted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_teardown_retention_and_revocation$;
ROLLBACK;

BEGIN;
SET LOCAL ROLE tenant_trust_platform_admin;
DO $verify_reused_platform_connection_is_unbound$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM lifecycle_connection_probe WHERE backend_pid = pg_backend_pid()
  ) THEN
    RAISE EXCEPTION 'lifecycle verification did not reuse the database session';
  END IF;
  IF identity.current_platform_subject_id() IS NOT NULL
     OR identity.current_platform_actor_is_admin() THEN
    RAISE EXCEPTION 'platform actor context leaked into a reused transaction';
  END IF;
END
$verify_reused_platform_connection_is_unbound$;
ROLLBACK;

\echo 'PASS tenant suspension blocks existing and new activity while audited teardown revokes privileges and retains history'
