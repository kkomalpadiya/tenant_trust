\set ON_ERROR_STOP on

BEGIN;

INSERT INTO trust.evidence_sources (
  tenant_id, source_id, issuer_id, source_name, evidence_type,
  state, verification_algorithm, maximum_age_seconds, synthetic
) VALUES (
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'src_018f1234-5678-7abc-8def-0123456789c5',
  NULL,
  'alpha-ingestion-verifier',
  'identity',
  'planned',
  'ed25519',
  300,
  true
);

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
SELECT *
FROM trust.enroll_evidence_source(
  'src_018f1234-5678-7abc-8def-0123456789c5',
  'key_018f1234-5678-7abc-8def-0123456789c6',
  'xTDFvh5FOfldrRPRPrV1n_LmzQQdLuIOwIs9J61tjbQ',
  transaction_timestamp()
);

SELECT set_config('tenant_trust.tenant_id', '', true);
SELECT set_config('tenant_trust.subject_id', '', true);

DO $verification$
BEGIN
  IF (
    SELECT count(*)
    FROM trust.resolve_evidence_verification_context(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789c5',
      'key_018f1234-5678-7abc-8def-0123456789c6'
    )
  ) <> 1 THEN
    RAISE EXCEPTION 'Exact active tenant/source/key/subject tuple was not resolved.';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM trust.resolve_evidence_verification_context(
      'tnt_018f1234-5678-7abc-8def-0123456789ac',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789c5',
      'key_018f1234-5678-7abc-8def-0123456789c6'
    )
  ) OR EXISTS (
    SELECT 1
    FROM trust.resolve_evidence_verification_context(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ad',
      'src_018f1234-5678-7abc-8def-0123456789c5',
      'key_018f1234-5678-7abc-8def-0123456789c6'
    )
  ) OR EXISTS (
    SELECT 1
    FROM trust.resolve_evidence_verification_context(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789c5',
      'key_018f1234-5678-7abc-8def-0123456789ff'
    )
  ) THEN
    RAISE EXCEPTION 'Foreign tenant, foreign subject or foreign key tuple resolved.';
  END IF;
END
$verification$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
SELECT *
FROM trust.revoke_evidence_source_key(
  'src_018f1234-5678-7abc-8def-0123456789c5',
  'key_018f1234-5678-7abc-8def-0123456789c6',
  'TEST_KEY_REVOKED',
  clock_timestamp()
);
SELECT set_config('tenant_trust.tenant_id', '', true);
SELECT set_config('tenant_trust.subject_id', '', true);

DO $revocation$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM trust.resolve_evidence_verification_context(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789c5',
      'key_018f1234-5678-7abc-8def-0123456789c6'
    )
  ) THEN
    RAISE EXCEPTION 'Revoked evidence key remained eligible for new ingestion.';
  END IF;
END
$revocation$;

ROLLBACK;

SELECT 'PASS exact active evidence verification tuple resolves without actor authority' AS result;
SELECT 'PASS tenant, subject and key cross-binding attempts remain invisible' AS result;
SELECT 'PASS revoked keys cannot authenticate new evidence' AS result;
