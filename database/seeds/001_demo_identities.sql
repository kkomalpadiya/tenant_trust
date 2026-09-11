\set ON_ERROR_STOP on

BEGIN;

INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name, state)
VALUES
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'tenant-alpha', 'Tenant Alpha', 'active'),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'tenant-beta', 'Tenant Beta', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO identity.subjects (
  subject_id,
  identity_provider,
  provider_subject,
  subject_kind,
  display_name,
  state
)
VALUES
  ('sub_018f1234-5678-7abc-8def-0123456789ab', 'local-demo', 'alice', 'human', 'Alice', 'active'),
  ('sub_018f1234-5678-7abc-8def-0123456789ac', 'local-demo', 'tenant-alpha-admin', 'human', 'Tenant Alpha Admin', 'active'),
  ('sub_018f1234-5678-7abc-8def-0123456789ad', 'local-demo', 'bob', 'human', 'Bob', 'active'),
  ('sub_018f1234-5678-7abc-8def-0123456789ae', 'local-demo', 'tenant-beta-admin', 'human', 'Tenant Beta Admin', 'active'),
  ('sub_018f1234-5678-7abc-8def-0123456789af', 'local-demo', 'platform-operator', 'human', 'Platform Operator', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO identity.tenant_memberships (tenant_id, subject_id, state)
VALUES
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'active'),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ac', 'active'),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ad', 'active'),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ae', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO identity.tenant_role_assignments (tenant_id, subject_id, role_name)
VALUES
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'tenant-member'),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ac', 'tenant-admin'),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ad', 'tenant-member'),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ae', 'tenant-admin')
ON CONFLICT DO NOTHING;

INSERT INTO identity.platform_role_assignments (subject_id, role_name)
VALUES ('sub_018f1234-5678-7abc-8def-0123456789af', 'platform-admin')
ON CONFLICT DO NOTHING;

DO $verify_seed_conflicts$
BEGIN
  IF (
    SELECT count(*)
    FROM identity.tenants
    WHERE (tenant_id, tenant_slug, display_name) IN (
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'tenant-alpha', 'Tenant Alpha'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'tenant-beta', 'Tenant Beta')
    )
  ) <> 2 THEN
    RAISE EXCEPTION 'deterministic tenant IDs or slugs conflict with existing data';
  END IF;

  IF (
    SELECT count(*)
    FROM identity.subjects
    WHERE (subject_id, identity_provider, provider_subject, subject_kind, display_name) IN (
      ('sub_018f1234-5678-7abc-8def-0123456789ab', 'local-demo', 'alice', 'human', 'Alice'),
      ('sub_018f1234-5678-7abc-8def-0123456789ac', 'local-demo', 'tenant-alpha-admin', 'human', 'Tenant Alpha Admin'),
      ('sub_018f1234-5678-7abc-8def-0123456789ad', 'local-demo', 'bob', 'human', 'Bob'),
      ('sub_018f1234-5678-7abc-8def-0123456789ae', 'local-demo', 'tenant-beta-admin', 'human', 'Tenant Beta Admin'),
      ('sub_018f1234-5678-7abc-8def-0123456789af', 'local-demo', 'platform-operator', 'human', 'Platform Operator')
    )
  ) <> 5 THEN
    RAISE EXCEPTION 'deterministic subject IDs or provider identities conflict with existing data';
  END IF;

  IF (
    SELECT count(*)
    FROM identity.tenant_memberships
    WHERE (tenant_id, subject_id) IN (
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ac'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ad'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ae')
    )
  ) <> 4 THEN
    RAISE EXCEPTION 'one or more deterministic tenant memberships could not be provisioned';
  END IF;

  IF (
    SELECT count(*)
    FROM identity.tenant_role_assignments
    WHERE (tenant_id, subject_id, role_name) IN (
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'tenant-member'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ac', 'tenant-admin'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ad', 'tenant-member'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ae', 'tenant-admin')
    )
  ) <> 4 THEN
    RAISE EXCEPTION 'one or more deterministic tenant role assignments could not be provisioned';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM identity.platform_role_assignments
    WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789af'
      AND role_name = 'platform-admin'
  ) THEN
    RAISE EXCEPTION 'the deterministic platform administrator could not be provisioned';
  END IF;
END
$verify_seed_conflicts$;

COMMIT;

\echo 'Provisioned deterministic Tenant Alpha and Tenant Beta identities.'
