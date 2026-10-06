\set ON_ERROR_STOP on

BEGIN;

INSERT INTO trust.evidence_sources (
  tenant_id, source_id, issuer_id, source_name, evidence_type,
  state, verification_algorithm, maximum_age_seconds, synthetic
) VALUES (
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'src_018f1234-5678-7abc-8def-0123456789d1',
  NULL, 'alpha-storage-verifier', 'identity', 'planned', 'ed25519', 300, true
);

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
SELECT * FROM trust.enroll_evidence_source(
  'src_018f1234-5678-7abc-8def-0123456789d1',
  'key_018f1234-5678-7abc-8def-0123456789d2',
  'xTDFvh5FOfldrRPRPrV1n_LmzQQdLuIOwIs9J61tjbQ',
  transaction_timestamp()
);
SELECT set_config('tenant_trust.tenant_id', '', true);
SELECT set_config('tenant_trust.subject_id', '', true);

DO $store$
DECLARE
  now_at_store timestamptz := clock_timestamp();
  decision record;
  deadline timestamptz;
BEGIN
  SELECT * INTO decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789d1',
    'key_018f1234-5678-7abc-8def-0123456789d2',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d3', 1,
    'AAAAAAAAAAAAAAAAAAAAAA', now_at_store - interval '1 second',
    now_at_store + interval '299 seconds', repeat('a', 64), true
  );
  IF NOT decision.accepted THEN RAISE EXCEPTION 'Storage fixture evidence was rejected.'; END IF;

  SELECT retained_until INTO deadline FROM trust.store_encrypted_evidence(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'evt_018f1234-5678-7abc-8def-0123456789d3',
    1::smallint, 'local-evidence-v1', decode(repeat('11', 12), 'hex'),
    decode(repeat('22', 16), 'hex'), decode(repeat('33', 32), 'hex'),
    repeat('b', 64), 32
  );
  IF deadline <> decision.accepted_at + interval '30 days' THEN
    RAISE EXCEPTION 'Evidence retention deadline is not fixed at 30 days.';
  END IF;
END
$store$;

DO $atomicity$
DECLARE
  now_at_attempt timestamptz := clock_timestamp();
  blocked boolean := false;
BEGIN
  BEGIN
    PERFORM trust.apply_evidence_replay_guard(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789d1',
      'key_018f1234-5678-7abc-8def-0123456789d2',
      'identity', 'evt_018f1234-5678-7abc-8def-0123456789d4', 2,
      'BBBBBBBBBBBBBBBBBBBBBB', now_at_attempt,
      now_at_attempt + interval '299 seconds', repeat('c', 64), true
    );
    SET CONSTRAINTS trust.evidence_receipt_requires_encrypted_storage IMMEDIATE;
  EXCEPTION WHEN check_violation THEN
    blocked := true;
  END;
  SET CONSTRAINTS trust.evidence_receipt_requires_encrypted_storage DEFERRED;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Accepted receipt committed without encrypted evidence.';
  END IF;
END
$atomicity$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);
DO $owner_access$
BEGIN
  IF (SELECT count(*) FROM trust.retrieve_encrypted_evidence(
    'evt_018f1234-5678-7abc-8def-0123456789d3'
  )) <> 1 THEN RAISE EXCEPTION 'Evidence owner could not retrieve encrypted evidence.'; END IF;
  IF trust.delete_encrypted_evidence(
    'evt_018f1234-5678-7abc-8def-0123456789d3', 'member deletion attempt'
  ) THEN RAISE EXCEPTION 'Ordinary member deleted evidence.'; END IF;
END
$owner_access$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ad'
);
DO $cross_tenant$
BEGIN
  IF (SELECT count(*) FROM trust.retrieve_encrypted_evidence(
    'evt_018f1234-5678-7abc-8def-0123456789d3'
  )) <> 0 THEN RAISE EXCEPTION 'Cross-tenant actor retrieved encrypted evidence.'; END IF;
END
$cross_tenant$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
DO $admin_delete$
BEGIN
  IF NOT trust.delete_encrypted_evidence(
    'evt_018f1234-5678-7abc-8def-0123456789d3', 'verification cleanup'
  ) THEN RAISE EXCEPTION 'Tenant administrator could not delete evidence.'; END IF;
  IF (SELECT count(*) FROM trust.retrieve_encrypted_evidence(
    'evt_018f1234-5678-7abc-8def-0123456789d3'
  )) <> 0 THEN RAISE EXCEPTION 'Deleted evidence remained retrievable.'; END IF;
END
$admin_delete$;

RESET ROLE;

DO $schema_controls$
BEGIN
  IF has_table_privilege('tenant_trust_app', 'trust.encrypted_evidence', 'SELECT')
    OR has_table_privilege('tenant_trust_app', 'trust.encrypted_evidence', 'INSERT')
    OR has_table_privilege('tenant_trust_app', 'trust.encrypted_evidence', 'UPDATE')
    OR has_table_privilege('tenant_trust_app', 'trust.encrypted_evidence', 'DELETE') THEN
    RAISE EXCEPTION 'Application role received direct encrypted evidence table access.';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM trust.encrypted_evidence
    WHERE event_id = 'evt_018f1234-5678-7abc-8def-0123456789d3'
      AND state = 'deleted'
      AND ciphertext IS NULL
      AND iv IS NULL
      AND authentication_tag IS NULL
      AND encryption_key_id IS NULL
      AND deletion_reason = 'verification cleanup'
  ) THEN RAISE EXCEPTION 'Deletion did not leave a ciphertext-free tombstone.'; END IF;
END
$schema_controls$;

ROLLBACK;

SELECT 'PASS accepted evidence has application-encrypted off-chain storage with fixed retention' AS result;
SELECT 'PASS evidence retrieval is owner-or-admin and tenant scoped' AS result;
SELECT 'PASS tenant-admin deletion removes ciphertext and retains a bounded tombstone' AS result;
