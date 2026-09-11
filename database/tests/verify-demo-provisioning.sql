\set ON_ERROR_STOP on

BEGIN;

DO $verify_demo_provisioning$
DECLARE
  tenant_count integer;
  subject_count integer;
  membership_count integer;
  tenant_role_count integer;
  resource_count integer;
  issuer_mapping_count integer;
  evidence_source_count integer;
  trust_configuration_count integer;
  policy_version_count integer;
BEGIN
  SELECT count(*) INTO tenant_count
  FROM identity.tenants
  WHERE tenant_id IN (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'tnt_018f1234-5678-7abc-8def-0123456789ac'
  )
    AND state = 'active';

  IF tenant_count <> 2 THEN
    RAISE EXCEPTION 'expected two active deterministic tenants, found %', tenant_count;
  END IF;

  SELECT count(*) INTO subject_count
  FROM identity.subjects
  WHERE identity_provider = 'local-demo'
    AND subject_id IN (
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ac',
      'sub_018f1234-5678-7abc-8def-0123456789ad',
      'sub_018f1234-5678-7abc-8def-0123456789ae',
      'sub_018f1234-5678-7abc-8def-0123456789af'
    )
    AND state = 'active';

  IF subject_count <> 5 THEN
    RAISE EXCEPTION 'expected five active deterministic subjects, found %', subject_count;
  END IF;

  SELECT count(*) INTO membership_count
  FROM identity.tenant_memberships
  WHERE (tenant_id, subject_id) IN (
    ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ac'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ad'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ae')
  )
    AND state = 'active';

  IF membership_count <> 4 THEN
    RAISE EXCEPTION 'expected four active tenant memberships, found %', membership_count;
  END IF;

  SELECT count(*) INTO tenant_role_count
  FROM identity.tenant_role_assignments
  WHERE (tenant_id, subject_id, role_name) IN (
    ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'tenant-member'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ac', 'tenant-admin'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ad', 'tenant-member'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'sub_018f1234-5678-7abc-8def-0123456789ae', 'tenant-admin')
  );

  IF tenant_role_count <> 4 THEN
    RAISE EXCEPTION 'expected four tenant role assignments, found %', tenant_role_count;
  END IF;

  SELECT count(*) INTO resource_count
  FROM app.resources
  WHERE (tenant_id, resource_id, owner_subject_id) IN (
    ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'res_018f1234-5678-7abc-8def-0123456789b0', 'sub_018f1234-5678-7abc-8def-0123456789ab'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'res_018f1234-5678-7abc-8def-0123456789b1', 'sub_018f1234-5678-7abc-8def-0123456789ac'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'res_018f1234-5678-7abc-8def-0123456789b2', 'sub_018f1234-5678-7abc-8def-0123456789ad'),
    ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'res_018f1234-5678-7abc-8def-0123456789b3', 'sub_018f1234-5678-7abc-8def-0123456789ae')
  );

  IF resource_count <> 4 THEN
    RAISE EXCEPTION 'expected four tenant-owned demonstration resources, found %', resource_count;
  END IF;

  SELECT count(*) INTO issuer_mapping_count
  FROM identity.tenant_issuer_mappings
  WHERE issuer_id IN (
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'iss_018f1234-5678-7abc-8def-0123456789b5'
  );

  IF issuer_mapping_count <> 2 THEN
    RAISE EXCEPTION 'expected two tenant issuer mappings, found %', issuer_mapping_count;
  END IF;

  SELECT count(*) INTO evidence_source_count
  FROM trust.evidence_sources
  WHERE source_id IN (
    'src_018f1234-5678-7abc-8def-0123456789b6',
    'src_018f1234-5678-7abc-8def-0123456789b7',
    'src_018f1234-5678-7abc-8def-0123456789b8',
    'src_018f1234-5678-7abc-8def-0123456789b9',
    'src_018f1234-5678-7abc-8def-0123456789ba',
    'src_018f1234-5678-7abc-8def-0123456789bb',
    'src_018f1234-5678-7abc-8def-0123456789bc',
    'src_018f1234-5678-7abc-8def-0123456789bd',
    'src_018f1234-5678-7abc-8def-0123456789be',
    'src_018f1234-5678-7abc-8def-0123456789bf'
  );

  IF evidence_source_count <> 10 THEN
    RAISE EXCEPTION 'expected ten tenant evidence sources, found %', evidence_source_count;
  END IF;

  SELECT count(*) INTO trust_configuration_count
  FROM trust.trust_configurations
  WHERE tenant_id IN (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'tnt_018f1234-5678-7abc-8def-0123456789ac'
  )
    AND configuration_version = 1;

  IF trust_configuration_count <> 2 THEN
    RAISE EXCEPTION 'expected two tenant trust configurations, found %', trust_configuration_count;
  END IF;

  SELECT count(*) INTO policy_version_count
  FROM trust.policy_versions
  WHERE policy_version_id IN (
    'pol_018f1234-5678-7abc-8def-0123456789c0',
    'pol_018f1234-5678-7abc-8def-0123456789c1'
  );

  IF policy_version_count <> 2 THEN
    RAISE EXCEPTION 'expected two tenant policy versions, found %', policy_version_count;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM identity.tenant_memberships
    WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789af'
  ) THEN
    RAISE EXCEPTION 'platform administrator has an unexpected tenant membership';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM identity.platform_role_assignments
    WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789af'
      AND role_name = 'platform-admin'
  ) THEN
    RAISE EXCEPTION 'platform administrator role assignment is missing';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM identity.tenant_memberships
    WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab'
      AND tenant_id <> 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  ) THEN
    RAISE EXCEPTION 'Alice has an unexpected cross-tenant membership';
  END IF;
END
$verify_demo_provisioning$;

CREATE TEMP TABLE demo_lifecycle_versions ON COMMIT DROP AS
SELECT
  tenant.version AS tenant_version,
  subject.version AS subject_version,
  membership.version AS membership_version
FROM identity.tenants AS tenant
CROSS JOIN identity.subjects AS subject
CROSS JOIN identity.tenant_memberships AS membership
WHERE tenant.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
  AND subject.subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ad'
  AND membership.tenant_id = tenant.tenant_id
  AND membership.subject_id = subject.subject_id;

UPDATE identity.tenants
SET state = 'suspended', version = version + 1, updated_at = clock_timestamp()
WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac';

UPDATE identity.subjects
SET state = 'suspended', version = version + 1, updated_at = clock_timestamp()
WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ad';

UPDATE identity.tenant_memberships
SET state = 'suspended', version = version + 1, updated_at = clock_timestamp()
WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
  AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ad';

DO $verify_lifecycle_persistence$
DECLARE
  previous_versions demo_lifecycle_versions%ROWTYPE;
BEGIN
  SELECT * INTO STRICT previous_versions FROM demo_lifecycle_versions;

  IF NOT EXISTS (
    SELECT 1 FROM identity.tenants
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
      AND state = 'suspended'
      AND version = previous_versions.tenant_version + 1
  ) THEN
    RAISE EXCEPTION 'tenant lifecycle state and version did not persist';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM identity.subjects
    WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ad'
      AND state = 'suspended'
      AND version = previous_versions.subject_version + 1
  ) THEN
    RAISE EXCEPTION 'subject lifecycle state and version did not persist';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM identity.tenant_memberships
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
      AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ad'
      AND state = 'suspended'
      AND version = previous_versions.membership_version + 1
  ) THEN
    RAISE EXCEPTION 'membership lifecycle state and version did not persist';
  END IF;
END
$verify_lifecycle_persistence$;

ROLLBACK;

\echo 'PASS deterministic tenants, identities, resources, security configuration and lifecycle persistence'
