\set ON_ERROR_STOP on

SET ROLE tenant_trust_app;
CREATE TEMP TABLE cross_tenant_connection_probe (
  backend_pid integer PRIMARY KEY
) ON COMMIT PRESERVE ROWS;
INSERT INTO cross_tenant_connection_probe VALUES (pg_backend_pid());

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_alpha_guessed_identifiers$
DECLARE
  affected integer;
BEGIN
  IF EXISTS (
    SELECT 1 FROM identity.tenants
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
  ) OR EXISTS (
    SELECT 1 FROM identity.subjects
    WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ad'
  ) OR EXISTS (
    SELECT 1 FROM app.resources
    WHERE resource_id = 'res_018f1234-5678-7abc-8def-0123456789b2'
  ) OR EXISTS (
    SELECT 1 FROM identity.tenant_issuer_mappings
    WHERE issuer_id = 'iss_018f1234-5678-7abc-8def-0123456789b5'
  ) OR EXISTS (
    SELECT 1 FROM trust.evidence_sources
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789bb'
  ) OR EXISTS (
    SELECT 1 FROM trust.trust_configurations
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
      AND configuration_version = 1
  ) OR EXISTS (
    SELECT 1 FROM trust.policy_versions
    WHERE policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c1'
  ) THEN
    RAISE EXCEPTION 'Alpha actor read a guessed Beta identifier';
  END IF;

  UPDATE app.resources
  SET resource_name = resource_name
  WHERE resource_id = 'res_018f1234-5678-7abc-8def-0123456789b2';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 0 THEN
    RAISE EXCEPTION 'Alpha actor updated a guessed Beta resource';
  END IF;

  UPDATE identity.tenant_issuer_mappings
  SET issuer_name = issuer_name
  WHERE issuer_id = 'iss_018f1234-5678-7abc-8def-0123456789b5';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 0 THEN
    RAISE EXCEPTION 'Alpha actor updated a guessed Beta issuer';
  END IF;

  UPDATE trust.evidence_sources
  SET source_name = source_name
  WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789bb';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 0 THEN
    RAISE EXCEPTION 'Alpha actor updated a guessed Beta evidence source';
  END IF;

  UPDATE trust.trust_configurations
  SET model_version = model_version
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
    AND configuration_version = 1;
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 0 THEN
    RAISE EXCEPTION 'Alpha actor updated a guessed Beta trust configuration';
  END IF;

  UPDATE trust.policy_versions
  SET policy_name = policy_name
  WHERE policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c1';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 0 THEN
    RAISE EXCEPTION 'Alpha actor updated a guessed Beta policy version';
  END IF;

  BEGIN
    INSERT INTO app.resources (tenant_id, resource_id, owner_subject_id, resource_name)
    VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ac',
      'res_018f1234-5678-7abc-8def-0123456789b4',
      'sub_018f1234-5678-7abc-8def-0123456789ad',
      'Cross-tenant tampering probe'
    );
    RAISE EXCEPTION 'Alpha actor inserted a Beta resource';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_alpha_guessed_identifiers$;
ROLLBACK;

BEGIN;
DO $verify_reused_connection_is_unbound$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM cross_tenant_connection_probe WHERE backend_pid = pg_backend_pid()
  ) THEN
    RAISE EXCEPTION 'cross-tenant verification did not reuse the database session';
  END IF;
  IF identity.current_tenant_id() IS NOT NULL
     OR identity.current_subject_id() IS NOT NULL
     OR (SELECT count(*) FROM identity.tenants) <> 0
     OR (SELECT count(*) FROM identity.subjects) <> 0
     OR (SELECT count(*) FROM app.resources) <> 0
     OR (SELECT count(*) FROM identity.tenant_issuer_mappings) <> 0
     OR (SELECT count(*) FROM trust.evidence_sources) <> 0
     OR (SELECT count(*) FROM trust.trust_configurations) <> 0
     OR (SELECT count(*) FROM trust.policy_versions) <> 0 THEN
    RAISE EXCEPTION 'tenant data leaked through a reused unbound connection';
  END IF;
END
$verify_reused_connection_is_unbound$;
ROLLBACK;

BEGIN;
DO $verify_invalid_actor_bindings$
BEGIN
  BEGIN
    PERFORM identity.set_tenant_actor_context(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ad'
    );
    RAISE EXCEPTION 'cross-tenant subject received an Alpha actor context';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM identity.set_tenant_actor_context(
      'not-a-tenant'::identity.tenant_id,
      'sub_018f1234-5678-7abc-8def-0123456789ac'
    );
    RAISE EXCEPTION 'malformed tenant identifier was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$verify_invalid_actor_bindings$;
ROLLBACK;

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ae'
);

DO $verify_beta_cannot_guess_alpha$
BEGIN
  IF EXISTS (
    SELECT 1 FROM app.resources
    WHERE resource_id = 'res_018f1234-5678-7abc-8def-0123456789b0'
  ) OR EXISTS (
    SELECT 1 FROM identity.tenant_issuer_mappings
    WHERE issuer_id = 'iss_018f1234-5678-7abc-8def-0123456789b4'
  ) OR EXISTS (
    SELECT 1 FROM trust.policy_versions
    WHERE policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c0'
  ) THEN
    RAISE EXCEPTION 'Beta actor read a guessed Alpha identifier';
  END IF;
END
$verify_beta_cannot_guess_alpha$;
ROLLBACK;

RESET ROLE;

\echo 'PASS guessed identifiers, invalid actor bindings and reused connections fail closed in PostgreSQL'
