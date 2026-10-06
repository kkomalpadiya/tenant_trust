\set ON_ERROR_STOP on

DO $verify_trust_state_schema$
DECLARE
  secured_table_count integer;
  append_trigger_count integer;
BEGIN
  SELECT count(*) INTO secured_table_count
  FROM pg_class AS relation
  JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
  WHERE (namespace.nspname, relation.relname) IN (
    ('trust', 'subject_trust_state_versions'),
    ('trust', 'subject_trust_state_evidence'),
    ('trust', 'subject_trust_current')
  )
    AND relation.relrowsecurity
    AND relation.relforcerowsecurity;
  IF secured_table_count <> 3 THEN
    RAISE EXCEPTION 'expected three forced-RLS trust-state tables, found %', secured_table_count;
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'trust'
      AND tablename IN ('subject_trust_state_versions', 'subject_trust_state_evidence', 'subject_trust_current')
  ) THEN
    RAISE EXCEPTION 'trust-state tables unexpectedly expose row policies';
  END IF;

  IF has_table_privilege('tenant_trust_app', 'trust.subject_trust_state_versions', 'SELECT')
     OR has_table_privilege('tenant_trust_app', 'trust.subject_trust_current', 'SELECT')
     OR has_table_privilege('tenant_trust_trust_engine', 'trust.subject_trust_state_versions', 'SELECT')
     OR has_table_privilege('tenant_trust_trust_engine', 'trust.subject_trust_state_evidence', 'INSERT')
     OR has_table_privilege('tenant_trust_trust_engine', 'trust.subject_trust_current', 'UPDATE') THEN
    RAISE EXCEPTION 'a runtime role received direct trust-state table privileges';
  END IF;

  SELECT count(*) INTO append_trigger_count
  FROM pg_trigger
  WHERE (tgrelid, tgname) IN (
    ('trust.subject_trust_state_versions'::regclass, 'subject_trust_state_versions_keep_history'),
    ('trust.subject_trust_state_evidence'::regclass, 'subject_trust_state_evidence_keep_history')
  )
    AND NOT tgisinternal;
  IF append_trigger_count <> 2 THEN
    RAISE EXCEPTION 'trust-state append-only triggers are incomplete';
  END IF;

  IF NOT has_function_privilege(
    'tenant_trust_trust_engine',
    'trust.store_subject_trust_state(identity.tenant_id,identity.subject_id,bigint,text,integer,numeric,numeric,numeric,numeric,numeric,timestamptz,jsonb)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'tenant_trust_trust_engine',
    'trust.get_current_subject_trust_state(identity.tenant_id,identity.subject_id)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'trust engine function privileges are incomplete';
  END IF;
END
$verify_trust_state_schema$;

BEGIN;

UPDATE trust.evidence_sources AS source
SET state = 'active',
    verification_key_sha256 = trust.ed25519_public_key_sha256(
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'::trust.ed25519_public_key_base64url
    ),
    updated_at = clock_timestamp()
WHERE source.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  AND source.source_id IN (
    'src_018f1234-5678-7abc-8def-0123456789b6',
    'src_018f1234-5678-7abc-8def-0123456789b7',
    'src_018f1234-5678-7abc-8def-0123456789b8',
    'src_018f1234-5678-7abc-8def-0123456789b9',
    'src_018f1234-5678-7abc-8def-0123456789ba'
  );

INSERT INTO trust.evidence_source_keys (
  tenant_id, source_id, key_id, key_version, public_key_base64url,
  public_key_sha256, enrolled_by_subject_id, enrolled_at
)
VALUES
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b6', 'key_018f1234-5678-7abc-8def-0123456789c6', 1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', trust.ed25519_public_key_sha256('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 'sub_018f1234-5678-7abc-8def-0123456789ac', clock_timestamp()),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b7', 'key_018f1234-5678-7abc-8def-0123456789c7', 1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', trust.ed25519_public_key_sha256('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 'sub_018f1234-5678-7abc-8def-0123456789ac', clock_timestamp()),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b8', 'key_018f1234-5678-7abc-8def-0123456789c8', 1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', trust.ed25519_public_key_sha256('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 'sub_018f1234-5678-7abc-8def-0123456789ac', clock_timestamp()),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b9', 'key_018f1234-5678-7abc-8def-0123456789c9', 1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', trust.ed25519_public_key_sha256('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 'sub_018f1234-5678-7abc-8def-0123456789ac', clock_timestamp()),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789ba', 'key_018f1234-5678-7abc-8def-0123456789ca', 1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', trust.ed25519_public_key_sha256('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 'sub_018f1234-5678-7abc-8def-0123456789ac', clock_timestamp());

INSERT INTO trust.evidence_ingestion_receipts (
  tenant_id, event_id, subject_id, source_id, key_id, evidence_type,
  source_sequence, nonce_sha256, content_hash_sha256, synthetic,
  observed_at, expires_at, accepted_at, maximum_source_influence
)
VALUES
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789e0', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b6', 'key_018f1234-5678-7abc-8def-0123456789c6', 'identity', 1, repeat('0', 64), repeat('a', 64), true, TIMESTAMPTZ '2026-10-06 08:00:00+00', TIMESTAMPTZ '2026-10-06 09:00:00+00', TIMESTAMPTZ '2026-10-06 08:00:01+00', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789e1', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b7', 'key_018f1234-5678-7abc-8def-0123456789c7', 'device', 1, repeat('1', 64), repeat('b', 64), true, TIMESTAMPTZ '2026-10-06 08:00:00+00', TIMESTAMPTZ '2026-10-06 09:00:00+00', TIMESTAMPTZ '2026-10-06 08:00:01+00', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789e2', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b8', 'key_018f1234-5678-7abc-8def-0123456789c8', 'behaviour', 1, repeat('2', 64), repeat('c', 64), true, TIMESTAMPTZ '2026-10-06 08:00:00+00', TIMESTAMPTZ '2026-10-06 09:00:00+00', TIMESTAMPTZ '2026-10-06 08:00:01+00', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789e3', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b9', 'key_018f1234-5678-7abc-8def-0123456789c9', 'certificate', 1, repeat('3', 64), repeat('d', 64), true, TIMESTAMPTZ '2026-10-06 08:00:00+00', TIMESTAMPTZ '2026-10-06 09:00:00+00', TIMESTAMPTZ '2026-10-06 08:00:01+00', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789e4', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789ba', 'key_018f1234-5678-7abc-8def-0123456789ca', 'compliance', 1, repeat('4', 64), repeat('e', 64), true, TIMESTAMPTZ '2026-10-06 08:00:00+00', TIMESTAMPTZ '2026-10-06 09:00:00+00', TIMESTAMPTZ '2026-10-06 08:00:01+00', 0.20);

INSERT INTO trust.encrypted_evidence (
  tenant_id, event_id, subject_id, source_id, content_hash_sha256,
  format_version, cipher, encryption_key_id, iv, authentication_tag,
  ciphertext, canonical_sha256, canonical_byte_length, retained_until, created_at
)
SELECT receipt.tenant_id, receipt.event_id, receipt.subject_id, receipt.source_id,
       receipt.content_hash_sha256, 1, 'AES-256-GCM', 'trust-state-test-key',
       decode(repeat('01', 12), 'hex'), decode(repeat('02', 16), 'hex'),
       decode('03', 'hex'), repeat('f', 64), 1,
       receipt.accepted_at + interval '30 days', receipt.accepted_at
FROM trust.evidence_ingestion_receipts AS receipt
WHERE receipt.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  AND receipt.event_id IN (
    'evt_018f1234-5678-7abc-8def-0123456789e0',
    'evt_018f1234-5678-7abc-8def-0123456789e1',
    'evt_018f1234-5678-7abc-8def-0123456789e2',
    'evt_018f1234-5678-7abc-8def-0123456789e3',
    'evt_018f1234-5678-7abc-8def-0123456789e4'
  );

CREATE TEMP TABLE trust_state_test_references (evidence_references jsonb NOT NULL) ON COMMIT DROP;
INSERT INTO trust_state_test_references (evidence_references)
SELECT jsonb_agg(
  jsonb_build_object(
    'evidenceId', outbox.evidence_id,
    'sourceEventId', outbox.source_event_id,
    'evidenceType', receipt.evidence_type
  ) ORDER BY receipt.evidence_type
)
FROM trust.evidence_event_outbox AS outbox
JOIN trust.evidence_ingestion_receipts AS receipt
  ON receipt.tenant_id = outbox.tenant_id
 AND receipt.event_id = outbox.source_event_id
WHERE receipt.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  AND receipt.subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab'
  AND receipt.event_id IN (
    'evt_018f1234-5678-7abc-8def-0123456789e0',
    'evt_018f1234-5678-7abc-8def-0123456789e1',
    'evt_018f1234-5678-7abc-8def-0123456789e2',
    'evt_018f1234-5678-7abc-8def-0123456789e3',
    'evt_018f1234-5678-7abc-8def-0123456789e4'
  );
GRANT SELECT ON trust_state_test_references TO tenant_trust_trust_engine;

SET LOCAL ROLE tenant_trust_trust_engine;

DO $verify_no_direct_trust_table_access$
BEGIN
  BEGIN
    PERFORM 1 FROM trust.subject_trust_state_versions;
    RAISE EXCEPTION 'trust engine read trust-state tables directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_no_direct_trust_table_access$;

SELECT * FROM trust.store_subject_trust_state(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  0, '1.0.0', 1,
  91, 82.5, 76, 100, 88,
  TIMESTAMPTZ '2026-10-06 08:00:00+00',
  (SELECT evidence_references FROM trust_state_test_references)
);

SELECT * FROM trust.store_subject_trust_state(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  1, '1.0.0', 1,
  92, 83, 77, 100, 89,
  TIMESTAMPTZ '2026-10-06 08:05:00+00',
  (SELECT evidence_references FROM trust_state_test_references)
);

DO $verify_storage_denials$
BEGIN
  BEGIN
    PERFORM trust.store_subject_trust_state(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      1, '1.0.0', 1, 92, 83, 77, 100, 89,
      TIMESTAMPTZ '2026-10-06 08:06:00+00',
      (SELECT evidence_references FROM trust_state_test_references)
    );
    RAISE EXCEPTION 'stale trust-state version was accepted';
  EXCEPTION WHEN serialization_failure THEN
    NULL;
  END;

  BEGIN
    PERFORM trust.store_subject_trust_state(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ac',
      0, '1.0.0', 1, 50, 50, 50, 50, 50,
      TIMESTAMPTZ '2026-10-06 08:06:00+00',
      (SELECT evidence_references FROM trust_state_test_references)
    );
    RAISE EXCEPTION 'different-subject evidence was accepted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM trust.store_subject_trust_state(
      'tnt_018f1234-5678-7abc-8def-0123456789ac',
      'sub_018f1234-5678-7abc-8def-0123456789ad',
      0, '1.0.0', 1, 50, 50, 50, 50, 50,
      TIMESTAMPTZ '2026-10-06 08:06:00+00',
      (SELECT evidence_references FROM trust_state_test_references)
    );
    RAISE EXCEPTION 'cross-tenant evidence was accepted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_storage_denials$;

DO $verify_function_reads$
DECLARE
  current_state record;
  first_state record;
BEGIN
  SELECT * INTO STRICT current_state
  FROM trust.get_current_subject_trust_state(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ab'
  );
  SELECT * INTO STRICT first_state
  FROM trust.get_subject_trust_state_version(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    1
  );
  IF current_state.update_version <> 2
     OR current_state.identity_component <> 92
     OR jsonb_array_length(current_state.evidence_references) <> 5
     OR first_state.update_version <> 1
     OR first_state.identity_component <> 91 THEN
    RAISE EXCEPTION 'current or historical trust-state read is incomplete';
  END IF;
END
$verify_function_reads$;

RESET ROLE;

DO $verify_durable_storage$
BEGIN
  IF (SELECT count(*) FROM trust.subject_trust_state_versions) <> 2
     OR (SELECT count(*) FROM trust.subject_trust_state_evidence) <> 10
     OR (SELECT update_version FROM trust.subject_trust_current
         WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
           AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab') <> 2 THEN
    RAISE EXCEPTION 'trust-state versions, evidence or current pointer are incomplete';
  END IF;

  BEGIN
    UPDATE trust.subject_trust_state_versions
    SET identity_component = 0
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab';
    RAISE EXCEPTION 'trust-state history was mutable';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    UPDATE trust.subject_trust_state_evidence
    SET evidence_type = 'device'
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND evidence_type = 'identity';
    RAISE EXCEPTION 'trust-state evidence history was mutable';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$verify_durable_storage$;

ROLLBACK;

\echo 'Verified tenant-scoped append-only trust state and version storage without retaining test changes.'
