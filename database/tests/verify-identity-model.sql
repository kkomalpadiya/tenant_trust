\set ON_ERROR_STOP on

BEGIN;

CREATE TEMP TABLE identity_model_test_ids ON COMMIT DROP AS
SELECT
  ('tnt_' || gen_random_uuid()::text)::identity.tenant_id AS tenant_alpha_id,
  ('tnt_' || gen_random_uuid()::text)::identity.tenant_id AS tenant_beta_id,
  ('tnt_' || gen_random_uuid()::text)::identity.tenant_id AS tenant_unused_id,
  ('sub_' || gen_random_uuid()::text)::identity.subject_id AS tenant_subject_id,
  ('sub_' || gen_random_uuid()::text)::identity.subject_id AS platform_subject_id,
  ('sub_' || gen_random_uuid()::text)::identity.subject_id AS subject_unused_id,
  'verify-alpha-' || gen_random_uuid()::text AS tenant_alpha_slug,
  'verify-beta-' || gen_random_uuid()::text AS tenant_beta_slug,
  'verify-subject-' || gen_random_uuid()::text AS provider_subject;

DO $verify_schema$
BEGIN
  IF to_regclass('identity.tenants') IS NULL
     OR to_regclass('identity.subjects') IS NULL
     OR to_regclass('identity.tenant_memberships') IS NULL
     OR to_regclass('identity.platform_role_assignments') IS NULL
     OR to_regclass('identity.tenant_role_assignments') IS NULL THEN
    RAISE EXCEPTION 'identity model tables are missing';
  END IF;
END
$verify_schema$;

INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name)
SELECT tenant_alpha_id, tenant_alpha_slug, 'Verification Tenant Alpha'
FROM identity_model_test_ids
UNION ALL
SELECT tenant_beta_id, tenant_beta_slug, 'Verification Tenant Beta'
FROM identity_model_test_ids;

INSERT INTO identity.subjects (
  subject_id,
  identity_provider,
  provider_subject,
  subject_kind,
  display_name
)
SELECT tenant_subject_id, 'identity-model-verifier', provider_subject, 'human'::identity.subject_kind, 'Verification Tenant Subject'
FROM identity_model_test_ids
UNION ALL
SELECT platform_subject_id, 'identity-model-verifier', provider_subject || '-platform', 'human'::identity.subject_kind, 'Verification Platform Subject'
FROM identity_model_test_ids;

INSERT INTO identity.tenant_memberships (tenant_id, subject_id)
SELECT tenant_alpha_id, tenant_subject_id
FROM identity_model_test_ids
UNION ALL
SELECT tenant_beta_id, tenant_subject_id
FROM identity_model_test_ids;

INSERT INTO identity.tenant_role_assignments (tenant_id, subject_id, role_name)
SELECT tenant_alpha_id, tenant_subject_id, 'tenant-admin'::identity.tenant_role_name
FROM identity_model_test_ids
UNION ALL
SELECT tenant_beta_id, tenant_subject_id, 'tenant-member'::identity.tenant_role_name
FROM identity_model_test_ids;

INSERT INTO identity.platform_role_assignments (subject_id, role_name)
SELECT platform_subject_id, 'platform-admin'
FROM identity_model_test_ids;

DO $verify_constraints$
DECLARE
  ids identity_model_test_ids%ROWTYPE;
  membership_count integer;
BEGIN
  SELECT * INTO STRICT ids FROM identity_model_test_ids;

  SELECT count(*) INTO membership_count
  FROM identity.tenant_memberships
  WHERE subject_id = ids.tenant_subject_id;

  IF membership_count <> 2 THEN
    RAISE EXCEPTION 'expected two independently tenant-qualified memberships, found %', membership_count;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM identity.tenant_memberships
    WHERE subject_id = ids.platform_subject_id
  ) THEN
    RAISE EXCEPTION 'a platform role must not create an implicit tenant membership';
  END IF;

  BEGIN
    INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name)
    VALUES (ids.tenant_unused_id, ids.tenant_alpha_slug, 'Duplicate Verification Tenant');
    RAISE EXCEPTION 'duplicate tenant slug was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO identity.subjects (subject_id, identity_provider, provider_subject, display_name)
    VALUES (ids.subject_unused_id, 'identity-model-verifier', ids.provider_subject, 'Duplicate Verification Subject');
    RAISE EXCEPTION 'duplicate external identity was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name)
    VALUES ('tenant-alpha', 'invalid-identifier', 'Invalid Identifier');
    RAISE EXCEPTION 'malformed tenant identifier was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO identity.tenant_role_assignments (tenant_id, subject_id, role_name)
    VALUES (
      ids.tenant_alpha_id,
      ids.subject_unused_id,
      'tenant-member'
    );
    RAISE EXCEPTION 'tenant role without matching membership was accepted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM 'platform-admin'::identity.tenant_role_name;
    RAISE EXCEPTION 'platform role was accepted as a tenant role';
  EXCEPTION WHEN invalid_text_representation THEN
    NULL;
  END;

  BEGIN
    PERFORM 'tenant-admin'::identity.platform_role_name;
    RAISE EXCEPTION 'tenant role was accepted as a platform role';
  EXCEPTION WHEN invalid_text_representation THEN
    NULL;
  END;

  BEGIN
    DELETE FROM identity.tenant_memberships
    WHERE tenant_id = ids.tenant_alpha_id
      AND subject_id = ids.tenant_subject_id;
    RAISE EXCEPTION 'membership with an assigned tenant role was deleted';
  EXCEPTION WHEN foreign_key_violation THEN
    NULL;
  END;
END
$verify_constraints$;

ROLLBACK;

\echo 'PASS tenant, subject, membership, uniqueness and role-scope constraints'
