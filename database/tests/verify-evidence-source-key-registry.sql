\set ON_ERROR_STOP on

DO $verify_evidence_source_registry_schema$
DECLARE
  secured_table boolean;
  select_policy boolean;
BEGIN
  SELECT relation.relrowsecurity AND relation.relforcerowsecurity INTO secured_table
  FROM pg_class AS relation
  JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'trust' AND relation.relname = 'evidence_source_keys';

  SELECT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'trust'
      AND tablename = 'evidence_source_keys'
      AND policyname = 'evidence_source_keys_current_actor_select'
  ) INTO select_policy;

  IF secured_table IS DISTINCT FROM true OR NOT select_policy THEN
    RAISE EXCEPTION 'evidence source key history is not protected by forced RLS';
  END IF;
  IF has_table_privilege('tenant_trust_app', 'trust.evidence_source_keys', 'INSERT')
     OR has_table_privilege('tenant_trust_app', 'trust.evidence_source_keys', 'UPDATE')
     OR has_table_privilege('tenant_trust_app', 'trust.evidence_source_keys', 'DELETE') THEN
    RAISE EXCEPTION 'application role received direct evidence source key mutation access';
  END IF;
  IF NOT has_function_privilege(
    'tenant_trust_app',
    'trust.enroll_evidence_source(trust.source_id,trust.evidence_source_key_id,trust.ed25519_public_key_base64url,timestamp with time zone)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'tenant_trust_app',
    'trust.rotate_evidence_source_key(trust.source_id,trust.evidence_source_key_id,trust.ed25519_public_key_base64url,timestamp with time zone)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'tenant_trust_app',
    'trust.revoke_evidence_source_key(trust.source_id,trust.evidence_source_key_id,text,timestamp with time zone)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'application role lacks a governed evidence source registry function';
  END IF;
END
$verify_evidence_source_registry_schema$;

SET ROLE tenant_trust_app;

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $verify_member_denied$
BEGIN
  BEGIN
    PERFORM trust.enroll_evidence_source(
      'src_018f1234-5678-7abc-8def-0123456789b6',
      'key_018f1234-5678-7abc-8def-0123456789d0',
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      clock_timestamp()
    );
    RAISE EXCEPTION 'ordinary tenant member enrolled an evidence source';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_member_denied$;
ROLLBACK;

BEGIN;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_registry_lifecycle$
DECLARE
  enrollment record;
  rotation record;
  historical_revocation record;
  active_revocation record;
  recovery record;
  original_fingerprint text := '66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925';
BEGIN
  BEGIN
    UPDATE trust.evidence_sources
    SET state = 'active',
        verification_key_sha256 = repeat('0', 64),
        updated_at = clock_timestamp()
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789b6';
    RAISE EXCEPTION 'tenant administrator bypassed the evidence source key registry';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  SELECT * INTO enrollment
  FROM trust.enroll_evidence_source(
    'src_018f1234-5678-7abc-8def-0123456789b6',
    'key_018f1234-5678-7abc-8def-0123456789d0',
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    clock_timestamp()
  );

  IF enrollment.enrolled_key_version <> 1
     OR enrollment.enrolled_key_sha256 <> original_fingerprint
     OR enrollment.enrolled_source_state <> 'active'
     OR NOT EXISTS (
       SELECT 1 FROM trust.evidence_source_keys
       WHERE source_id = enrollment.enrolled_source_id
         AND key_id = enrollment.enrolled_key_id
         AND key_version = 1
         AND state = 'active'
         AND public_key_sha256 = original_fingerprint
         AND enrolled_by_subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ac'
     ) THEN
    RAISE EXCEPTION 'authorized evidence source enrollment did not persist its first active key';
  END IF;

  BEGIN
    PERFORM trust.enroll_evidence_source(
      'src_018f1234-5678-7abc-8def-0123456789bb',
      'key_018f1234-5678-7abc-8def-0123456789d9',
      'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI',
      clock_timestamp()
    );
    RAISE EXCEPTION 'Alpha administrator enrolled a Beta evidence source';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  SELECT * INTO rotation
  FROM trust.rotate_evidence_source_key(
    'src_018f1234-5678-7abc-8def-0123456789b6',
    'key_018f1234-5678-7abc-8def-0123456789d1',
    'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
    clock_timestamp()
  );

  IF rotation.active_key_version <> 2
     OR (SELECT count(*) FROM trust.evidence_source_keys
         WHERE source_id = rotation.rotated_source_id) <> 2
     OR NOT EXISTS (
       SELECT 1 FROM trust.evidence_source_keys
       WHERE source_id = rotation.rotated_source_id
         AND key_id = enrollment.enrolled_key_id
         AND state = 'rotated'
         AND public_key_sha256 = original_fingerprint
         AND public_key_base64url = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
     ) THEN
    RAISE EXCEPTION 'evidence source rotation did not retain the prior verifiable key epoch';
  END IF;

  SELECT * INTO historical_revocation
  FROM trust.revoke_evidence_source_key(
    'src_018f1234-5678-7abc-8def-0123456789b6',
    'key_018f1234-5678-7abc-8def-0123456789d0',
    'HISTORICAL_KEY_COMPROMISE',
    clock_timestamp()
  );

  IF historical_revocation.revoked_key_state <> 'revoked'
     OR historical_revocation.resulting_source_state <> 'active'
     OR NOT EXISTS (
       SELECT 1 FROM trust.evidence_source_keys
       WHERE source_id = historical_revocation.revoked_source_id
         AND key_id = historical_revocation.revoked_key_id
         AND state = 'revoked'
         AND rotated_at IS NOT NULL
         AND revoked_at IS NOT NULL
         AND public_key_sha256 = original_fingerprint
     ) THEN
    RAISE EXCEPTION 'historical key revocation lost verification or lifecycle history';
  END IF;

  SELECT * INTO active_revocation
  FROM trust.revoke_evidence_source_key(
    'src_018f1234-5678-7abc-8def-0123456789b6',
    'key_018f1234-5678-7abc-8def-0123456789d1',
    'KEY_COMPROMISED',
    clock_timestamp()
  );

  IF active_revocation.resulting_source_state <> 'suspended'
     OR EXISTS (
       SELECT 1 FROM trust.evidence_source_keys
       WHERE source_id = active_revocation.revoked_source_id AND state = 'active'
     )
     OR NOT EXISTS (
       SELECT 1 FROM trust.evidence_sources
       WHERE source_id = active_revocation.revoked_source_id
         AND state = 'suspended'
         AND verification_key_sha256 IS NULL
     ) THEN
    RAISE EXCEPTION 'active key revocation did not suspend evidence acceptance';
  END IF;

  SELECT * INTO recovery
  FROM trust.rotate_evidence_source_key(
    'src_018f1234-5678-7abc-8def-0123456789b6',
    'key_018f1234-5678-7abc-8def-0123456789d2',
    'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI',
    clock_timestamp()
  );

  IF recovery.active_key_version <> 3
     OR recovery.rotated_source_state <> 'active'
     OR (SELECT count(*) FROM trust.evidence_source_keys
         WHERE source_id = recovery.rotated_source_id) <> 3
     OR (SELECT count(*) FROM trust.evidence_source_keys
         WHERE source_id = recovery.rotated_source_id AND state = 'revoked') <> 2
     OR (SELECT count(*) FROM trust.evidence_source_keys
         WHERE source_id = recovery.rotated_source_id AND state = 'active') <> 1 THEN
    RAISE EXCEPTION 'post-revocation key recovery did not append a new active epoch';
  END IF;

  BEGIN
    DELETE FROM trust.evidence_sources
    WHERE source_id = recovery.rotated_source_id;
    RAISE EXCEPTION 'tenant administrator deleted enrolled source history';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$verify_registry_lifecycle$;
ROLLBACK;

BEGIN;
DO $verify_unbound_registry$
BEGIN
  IF identity.current_tenant_id() IS NOT NULL
     OR identity.current_subject_id() IS NOT NULL
     OR (SELECT count(*) FROM trust.evidence_source_keys) <> 0 THEN
    RAISE EXCEPTION 'evidence source key history leaked without actor context';
  END IF;
END
$verify_unbound_registry$;
ROLLBACK;

RESET ROLE;

\echo 'PASS evidence source enrollment, key rotation and revocation are tenant-admin governed and history preserving'
