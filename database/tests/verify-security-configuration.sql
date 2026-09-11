\set ON_ERROR_STOP on

DO $verify_security_configuration_schema$
DECLARE
  secured_table_count integer;
  policy_count integer;
BEGIN
  SELECT count(*) INTO secured_table_count
  FROM pg_class AS relation
  JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
  WHERE (namespace.nspname, relation.relname) IN (
    ('identity', 'tenant_issuer_mappings'),
    ('trust', 'evidence_sources'),
    ('trust', 'trust_configurations'),
    ('trust', 'policy_versions')
  )
    AND relation.relrowsecurity
    AND relation.relforcerowsecurity;

  IF secured_table_count <> 4 THEN
    RAISE EXCEPTION 'expected four forced-RLS security configuration tables, found %', secured_table_count;
  END IF;

  SELECT count(*) INTO policy_count
  FROM pg_policies
  WHERE (schemaname, tablename, policyname) IN (
    ('identity', 'tenant_issuer_mappings', 'issuer_mappings_current_actor_select'),
    ('identity', 'tenant_issuer_mappings', 'issuer_mappings_tenant_admin_insert'),
    ('identity', 'tenant_issuer_mappings', 'issuer_mappings_tenant_admin_update'),
    ('identity', 'tenant_issuer_mappings', 'issuer_mappings_tenant_admin_delete'),
    ('trust', 'evidence_sources', 'evidence_sources_current_actor_select'),
    ('trust', 'evidence_sources', 'evidence_sources_tenant_admin_insert'),
    ('trust', 'evidence_sources', 'evidence_sources_tenant_admin_update'),
    ('trust', 'evidence_sources', 'evidence_sources_tenant_admin_delete'),
    ('trust', 'trust_configurations', 'trust_configurations_current_actor_select'),
    ('trust', 'trust_configurations', 'trust_configurations_tenant_admin_insert'),
    ('trust', 'trust_configurations', 'trust_configurations_tenant_admin_update'),
    ('trust', 'trust_configurations', 'trust_configurations_tenant_admin_delete'),
    ('trust', 'policy_versions', 'policy_versions_current_actor_select'),
    ('trust', 'policy_versions', 'policy_versions_tenant_admin_insert'),
    ('trust', 'policy_versions', 'policy_versions_tenant_admin_update'),
    ('trust', 'policy_versions', 'policy_versions_tenant_admin_delete')
  )
    AND 'tenant_trust_app' = ANY(roles);

  IF policy_count <> 16 THEN
    RAISE EXCEPTION 'expected sixteen actor-aware security configuration policies, found %', policy_count;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'evidence_sources_issuer_fk'
      AND conrelid = 'trust.evidence_sources'::regclass
  ) THEN
    RAISE EXCEPTION 'tenant-qualified evidence-source issuer foreign key is missing';
  END IF;

  IF (SELECT count(*) FROM identity.tenant_issuer_mappings) <> 2
     OR (SELECT count(*) FROM trust.evidence_sources) <> 10
     OR (SELECT count(*) FROM trust.trust_configurations) <> 2
     OR (SELECT count(*) FROM trust.policy_versions) <> 2 THEN
    RAISE EXCEPTION 'deterministic tenant security configuration is incomplete';
  END IF;
END
$verify_security_configuration_schema$;

SET ROLE tenant_trust_app;
CREATE TEMP TABLE security_configuration_connection_probe (
  backend_pid integer PRIMARY KEY
) ON COMMIT PRESERVE ROWS;
INSERT INTO security_configuration_connection_probe VALUES (pg_backend_pid());

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $verify_alpha_member_security_configuration$
DECLARE
  affected integer;
BEGIN
  IF (SELECT count(*) FROM identity.tenant_issuer_mappings) <> 1
     OR (SELECT count(*) FROM trust.evidence_sources) <> 5
     OR (SELECT count(*) FROM trust.trust_configurations) <> 1
     OR (SELECT count(*) FROM trust.policy_versions) <> 1 THEN
    RAISE EXCEPTION 'Alpha member did not receive exactly the Alpha security configuration';
  END IF;

  IF EXISTS (
    SELECT 1 FROM identity.tenant_issuer_mappings
    WHERE issuer_id = 'iss_018f1234-5678-7abc-8def-0123456789b5'
  ) OR EXISTS (
    SELECT 1 FROM trust.evidence_sources
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789bb'
  ) OR EXISTS (
    SELECT 1 FROM trust.policy_versions
    WHERE policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c1'
  ) THEN
    RAISE EXCEPTION 'Alpha member read guessed Beta security configuration';
  END IF;

  UPDATE trust.evidence_sources
  SET maximum_age_seconds = maximum_age_seconds
  WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789bb';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 0 THEN
    RAISE EXCEPTION 'Alpha member updated a guessed Beta evidence source';
  END IF;

  BEGIN
    INSERT INTO trust.trust_configurations (
      tenant_id, configuration_version, model_version, state, initial_score,
      smoothing_alpha, maximum_source_influence, stale_after_seconds,
      identity_weight, device_weight, behaviour_weight, certificate_weight,
      compliance_weight, created_by_subject_id
    ) VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ab', 2, '1.0.0', 'draft', 60,
      0.3, 0.25, 3600, 0.2, 0.25, 0.25, 0.15, 0.15,
      'sub_018f1234-5678-7abc-8def-0123456789ab'
    );
    RAISE EXCEPTION 'ordinary member created a trust configuration';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_alpha_member_security_configuration$;
ROLLBACK;

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

INSERT INTO trust.trust_configurations (
  tenant_id, configuration_version, model_version, state, initial_score,
  smoothing_alpha, maximum_source_influence, stale_after_seconds,
  identity_weight, device_weight, behaviour_weight, certificate_weight,
  compliance_weight, created_by_subject_id
) VALUES (
  'tnt_018f1234-5678-7abc-8def-0123456789ab', 2, '1.1.0', 'draft', 62,
  0.35, 0.20, 2700, 0.20, 0.25, 0.25, 0.15, 0.15,
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_alpha_admin_security_configuration$
BEGIN
  IF (SELECT count(*) FROM identity.tenant_issuer_mappings) <> 1
     OR (SELECT count(*) FROM trust.evidence_sources) <> 5
     OR (SELECT count(*) FROM trust.trust_configurations) <> 2
     OR (SELECT count(*) FROM trust.policy_versions) <> 1 THEN
    RAISE EXCEPTION 'Alpha administrator did not receive exactly the Alpha security configuration';
  END IF;

  BEGIN
    INSERT INTO trust.evidence_sources (
      tenant_id, source_id, issuer_id, source_name, evidence_type,
      state, verification_algorithm, maximum_age_seconds, synthetic
    ) VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789c2',
      'iss_018f1234-5678-7abc-8def-0123456789b5',
      'cross-tenant-issuer-probe', 'certificate', 'planned', 'ed25519', 60, true
    );
    RAISE EXCEPTION 'Alpha evidence source referenced the Beta issuer mapping';
  EXCEPTION WHEN foreign_key_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO trust.policy_versions (
      tenant_id, policy_version_id, policy_name, bundle_version,
      bundle_hash_sha256, entrypoint, state, published_by_subject_id
    ) VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ac',
      'pol_018f1234-5678-7abc-8def-0123456789c2',
      'access-control', 2,
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'tenant_trust/authz/decision', 'published',
      'sub_018f1234-5678-7abc-8def-0123456789ae'
    );
    RAISE EXCEPTION 'Alpha administrator created a Beta policy version';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    UPDATE trust.policy_versions
    SET bundle_hash_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    WHERE policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c0';
    RAISE EXCEPTION 'published policy content was rewritten';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    UPDATE trust.trust_configurations
    SET state = 'active', activated_at = clock_timestamp(), updated_at = clock_timestamp()
    WHERE configuration_version = 2;
    RAISE EXCEPTION 'a second active trust configuration was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
END
$verify_alpha_admin_security_configuration$;
ROLLBACK;

BEGIN;
DO $verify_unbound_security_configuration$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM security_configuration_connection_probe WHERE backend_pid = pg_backend_pid()
  ) THEN
    RAISE EXCEPTION 'security configuration verification did not reuse the database session';
  END IF;

  IF identity.current_tenant_id() IS NOT NULL
     OR identity.current_subject_id() IS NOT NULL
     OR (SELECT count(*) FROM identity.tenant_issuer_mappings) <> 0
     OR (SELECT count(*) FROM trust.evidence_sources) <> 0
     OR (SELECT count(*) FROM trust.trust_configurations) <> 0
     OR (SELECT count(*) FROM trust.policy_versions) <> 0 THEN
    RAISE EXCEPTION 'tenant security configuration leaked into an unbound transaction';
  END IF;
END
$verify_unbound_security_configuration$;
ROLLBACK;

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ad'
);

DO $verify_beta_member_security_configuration$
BEGIN
  IF (SELECT count(*) FROM identity.tenant_issuer_mappings) <> 1
     OR NOT EXISTS (
       SELECT 1 FROM identity.tenant_issuer_mappings
       WHERE issuer_id = 'iss_018f1234-5678-7abc-8def-0123456789b5'
     )
     OR (SELECT count(*) FROM trust.evidence_sources) <> 5
     OR (SELECT count(*) FROM trust.trust_configurations) <> 1
     OR (SELECT count(*) FROM trust.policy_versions) <> 1 THEN
    RAISE EXCEPTION 'Beta member did not receive exactly the Beta security configuration';
  END IF;
END
$verify_beta_member_security_configuration$;
ROLLBACK;

RESET ROLE;

\echo 'PASS issuer, evidence, trust and policy configuration stays tenant-owned and administrator-controlled'
