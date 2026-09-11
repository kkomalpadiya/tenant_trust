\set ON_ERROR_STOP on

DO $verify_resource_configuration$
DECLARE
  resource_policies integer;
BEGIN
  IF to_regclass('app.resources') IS NULL THEN
    RAISE EXCEPTION 'tenant resource table is missing';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'app'
      AND relation.relname = 'resources'
      AND relation.relrowsecurity
      AND relation.relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'app.resources does not enforce row-level security';
  END IF;

  SELECT count(*) INTO resource_policies
  FROM pg_policies
  WHERE schemaname = 'app'
    AND tablename = 'resources'
    AND policyname IN (
      'resources_current_actor_select',
      'resources_current_actor_insert',
      'resources_current_actor_update',
      'resources_current_actor_delete'
    )
    AND 'tenant_trust_app' = ANY(roles);

  IF resource_policies <> 4 THEN
    RAISE EXCEPTION 'expected four actor-aware resource policies, found %', resource_policies;
  END IF;

  IF (
    SELECT count(*)
    FROM app.resources
    WHERE resource_id IN (
      'res_018f1234-5678-7abc-8def-0123456789b0',
      'res_018f1234-5678-7abc-8def-0123456789b1',
      'res_018f1234-5678-7abc-8def-0123456789b2',
      'res_018f1234-5678-7abc-8def-0123456789b3'
    )
  ) <> 4 THEN
    RAISE EXCEPTION 'expected four deterministic tenant resources';
  END IF;
END
$verify_resource_configuration$;

SET ROLE tenant_trust_app;
CREATE TEMP TABLE resource_connection_probe (
  backend_pid integer PRIMARY KEY
) ON COMMIT PRESERVE ROWS;
INSERT INTO resource_connection_probe VALUES (pg_backend_pid());

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $verify_alpha_member_scope$
DECLARE
  affected integer;
BEGIN
  IF identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION 'ordinary Alpha member received tenant-admin authority';
  END IF;
  IF (SELECT count(*) FROM app.resources) <> 1
     OR NOT EXISTS (
       SELECT 1 FROM app.resources
       WHERE resource_id = 'res_018f1234-5678-7abc-8def-0123456789b0'
     ) THEN
    RAISE EXCEPTION 'Alpha member did not receive exactly their owned resource';
  END IF;
  IF EXISTS (
    SELECT 1 FROM app.resources
    WHERE resource_id IN (
      'res_018f1234-5678-7abc-8def-0123456789b1',
      'res_018f1234-5678-7abc-8def-0123456789b2',
      'res_018f1234-5678-7abc-8def-0123456789b3'
    )
  ) THEN
    RAISE EXCEPTION 'Alpha member read an administrator or foreign-tenant resource';
  END IF;

  UPDATE app.resources
  SET resource_name = resource_name
  WHERE resource_id = 'res_018f1234-5678-7abc-8def-0123456789b2';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 0 THEN
    RAISE EXCEPTION 'Alpha member updated a guessed Beta resource';
  END IF;

  BEGIN
    INSERT INTO app.resources (tenant_id, resource_id, owner_subject_id, resource_name)
    VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'res_018f1234-5678-7abc-8def-0123456789b4',
      'sub_018f1234-5678-7abc-8def-0123456789ac',
      'Unauthorized delegated record'
    );
    RAISE EXCEPTION 'Alpha member created a resource for another subject';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    INSERT INTO identity.tenant_role_assignments (tenant_id, subject_id, role_name)
    VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'tenant-admin'
    );
    RAISE EXCEPTION 'Alpha member granted tenant-admin to themselves';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_alpha_member_scope$;
ROLLBACK;

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_alpha_admin_scope$
BEGIN
  IF NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION 'Alpha administrator did not receive tenant-admin authority';
  END IF;
  IF (SELECT count(*) FROM app.resources) <> 2
     OR EXISTS (
       SELECT 1 FROM app.resources
       WHERE tenant_id <> 'tnt_018f1234-5678-7abc-8def-0123456789ab'
     ) THEN
    RAISE EXCEPTION 'Alpha administrator did not receive exactly the Alpha resources';
  END IF;
END
$verify_alpha_admin_scope$;

INSERT INTO identity.tenant_role_assignments (tenant_id, subject_id, role_name)
VALUES (
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'tenant-admin'
);
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $verify_promoted_member_scope$
BEGIN
  IF NOT identity.current_actor_is_tenant_admin()
     OR (SELECT count(*) FROM app.resources) <> 2 THEN
    RAISE EXCEPTION 'new tenant-admin role did not expose the tenant resource set';
  END IF;
END
$verify_promoted_member_scope$;

DELETE FROM identity.tenant_role_assignments
WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab'
  AND role_name = 'tenant-admin';

DO $verify_demoted_member_scope$
BEGIN
  IF identity.current_actor_is_tenant_admin()
     OR (SELECT count(*) FROM app.resources) <> 1 THEN
    RAISE EXCEPTION 'tenant-admin removal did not restore owner-only resource access';
  END IF;
END
$verify_demoted_member_scope$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_last_admin_rule$
BEGIN
  BEGIN
    DELETE FROM identity.tenant_role_assignments
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ac'
      AND role_name = 'tenant-admin';
    RAISE EXCEPTION 'last active tenant administrator was removed';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$verify_last_admin_rule$;

UPDATE identity.tenant_memberships
SET state = 'suspended', version = version + 1, updated_at = clock_timestamp()
WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab';

DO $verify_suspended_membership_denial$
BEGIN
  BEGIN
    PERFORM identity.set_tenant_actor_context(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab'
    );
    RAISE EXCEPTION 'suspended membership received an actor context';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_suspended_membership_denial$;
ROLLBACK;

BEGIN;
DO $verify_unbound_connection_scope$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM resource_connection_probe WHERE backend_pid = pg_backend_pid()
  ) THEN
    RAISE EXCEPTION 'resource verification did not reuse the database session';
  END IF;
  IF identity.current_tenant_id() IS NOT NULL
     OR identity.current_subject_id() IS NOT NULL
     OR (SELECT count(*) FROM app.resources) <> 0 THEN
    RAISE EXCEPTION 'actor context or resource visibility leaked into a reused transaction';
  END IF;
END
$verify_unbound_connection_scope$;
ROLLBACK;

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ad'
);
DO $verify_beta_member_scope$
BEGIN
  IF (SELECT count(*) FROM app.resources) <> 1
     OR NOT EXISTS (
       SELECT 1 FROM app.resources
       WHERE resource_id = 'res_018f1234-5678-7abc-8def-0123456789b2'
     ) THEN
    RAISE EXCEPTION 'Beta member did not receive exactly their owned resource';
  END IF;
END
$verify_beta_member_scope$;
ROLLBACK;

RESET ROLE;

\echo 'PASS tenant members see owned resources, tenant admins see tenant resources, and membership or role changes fail closed'
