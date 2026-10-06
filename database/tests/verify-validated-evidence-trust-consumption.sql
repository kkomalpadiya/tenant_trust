\set ON_ERROR_STOP on

DO $verify_consumer_schema$
DECLARE
  function_definition text;
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'trust'
      AND relation.relname = 'subject_component_observations'
      AND relation.relrowsecurity
      AND relation.relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'validated component staging is not protected by forced RLS';
  END IF;

  IF has_table_privilege(
    'tenant_trust_evidence_event_consumer',
    'trust.subject_component_observations',
    'SELECT'
  ) OR has_table_privilege(
    'tenant_trust_evidence_event_consumer',
    'trust.subject_component_observations',
    'INSERT'
  ) THEN
    RAISE EXCEPTION 'evidence consumer has direct component-staging privileges';
  END IF;

  IF NOT has_function_privilege(
    'tenant_trust_evidence_event_consumer',
    'trust.consume_validated_evidence_component(text,identity.tenant_id,identity.event_id,trust.evidence_id,bigint,identity.sha256_digest,numeric,timestamptz)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'evidence consumer cannot execute the constrained trust-consumption function';
  END IF;

  SELECT pg_get_functiondef(
    'trust.consume_validated_evidence_component(text,identity.tenant_id,identity.event_id,trust.evidence_id,bigint,identity.sha256_digest,numeric,timestamptz)'::regprocedure
  ) INTO function_definition;
  IF function_definition !~ 'pg_advisory_xact_lock'
     OR function_definition !~ 'record_evidence_event_effect'
     OR function_definition !~ 'store_subject_trust_state' THEN
    RAISE EXCEPTION 'consumer function is missing subject locking, idempotency or atomic state storage';
  END IF;
END
$verify_consumer_schema$;

BEGIN;

INSERT INTO identity.subjects (
  subject_id, identity_provider, provider_subject, subject_kind, display_name, state
) VALUES (
  'sub_018f1234-5678-7abc-8def-0123456789d0',
  'verification',
  'trust-consumer-t6-5',
  'service',
  'Trust consumer verification',
  'active'
);

INSERT INTO identity.tenant_memberships (tenant_id, subject_id, state)
VALUES (
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789d0',
  'active'
);

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
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789ba', 'key_018f1234-5678-7abc-8def-0123456789ca', 1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', trust.ed25519_public_key_sha256('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 'sub_018f1234-5678-7abc-8def-0123456789ac', clock_timestamp())
ON CONFLICT DO NOTHING;

INSERT INTO trust.evidence_ingestion_receipts (
  tenant_id, event_id, subject_id, source_id, key_id, evidence_type,
  source_sequence, nonce_sha256, content_hash_sha256, synthetic,
  observed_at, expires_at, accepted_at, maximum_source_influence
)
VALUES
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789f0', 'sub_018f1234-5678-7abc-8def-0123456789d0', 'src_018f1234-5678-7abc-8def-0123456789b6', 'key_018f1234-5678-7abc-8def-0123456789c6', 'identity', 1, repeat('0', 64), repeat('a', 64), true, clock_timestamp() - interval '10 minutes', clock_timestamp() + interval '1 hour', clock_timestamp() - interval '1 minute', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789f1', 'sub_018f1234-5678-7abc-8def-0123456789d0', 'src_018f1234-5678-7abc-8def-0123456789b7', 'key_018f1234-5678-7abc-8def-0123456789c7', 'device', 1, repeat('1', 64), repeat('b', 64), true, clock_timestamp() - interval '10 minutes', clock_timestamp() + interval '1 hour', clock_timestamp() - interval '1 minute', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789f2', 'sub_018f1234-5678-7abc-8def-0123456789d0', 'src_018f1234-5678-7abc-8def-0123456789b8', 'key_018f1234-5678-7abc-8def-0123456789c8', 'behaviour', 1, repeat('2', 64), repeat('c', 64), true, clock_timestamp() - interval '10 minutes', clock_timestamp() + interval '1 hour', clock_timestamp() - interval '1 minute', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789f3', 'sub_018f1234-5678-7abc-8def-0123456789d0', 'src_018f1234-5678-7abc-8def-0123456789b9', 'key_018f1234-5678-7abc-8def-0123456789c9', 'certificate', 1, repeat('3', 64), repeat('d', 64), true, clock_timestamp() - interval '10 minutes', clock_timestamp() + interval '1 hour', clock_timestamp() - interval '1 minute', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789f4', 'sub_018f1234-5678-7abc-8def-0123456789d0', 'src_018f1234-5678-7abc-8def-0123456789ba', 'key_018f1234-5678-7abc-8def-0123456789ca', 'compliance', 1, repeat('4', 64), repeat('e', 64), true, clock_timestamp() - interval '10 minutes', clock_timestamp() + interval '1 hour', clock_timestamp() - interval '1 minute', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789f5', 'sub_018f1234-5678-7abc-8def-0123456789d0', 'src_018f1234-5678-7abc-8def-0123456789b6', 'key_018f1234-5678-7abc-8def-0123456789c6', 'identity', 2, repeat('5', 64), repeat('a', 64), true, clock_timestamp() - interval '20 minutes', clock_timestamp() + interval '1 hour', clock_timestamp() - interval '1 minute', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789f6', 'sub_018f1234-5678-7abc-8def-0123456789d0', 'src_018f1234-5678-7abc-8def-0123456789b6', 'key_018f1234-5678-7abc-8def-0123456789c6', 'identity', 3, repeat('6', 64), repeat('f', 64), true, clock_timestamp() - interval '5 minutes', clock_timestamp() + interval '1 hour', clock_timestamp() - interval '1 minute', 0.20),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'evt_018f1234-5678-7abc-8def-0123456789f7', 'sub_018f1234-5678-7abc-8def-0123456789d0', 'src_018f1234-5678-7abc-8def-0123456789b7', 'key_018f1234-5678-7abc-8def-0123456789c7', 'device', 2, repeat('7', 64), repeat('0', 64), true, clock_timestamp() - interval '4 minutes', clock_timestamp() + interval '1 hour', clock_timestamp() - interval '1 minute', 0.20);

INSERT INTO trust.encrypted_evidence (
  tenant_id, event_id, subject_id, source_id, content_hash_sha256,
  format_version, cipher, encryption_key_id, iv, authentication_tag,
  ciphertext, canonical_sha256, canonical_byte_length, retained_until, created_at
)
SELECT receipt.tenant_id,
       receipt.event_id,
       receipt.subject_id,
       receipt.source_id,
       receipt.content_hash_sha256,
       1,
       'AES-256-GCM',
       'trust-consumer-test-key',
       decode(repeat('01', 12), 'hex'),
       decode(repeat('02', 16), 'hex'),
       decode('03', 'hex'),
       repeat('f', 64),
       1,
       receipt.accepted_at + interval '30 days',
       receipt.accepted_at
FROM trust.evidence_ingestion_receipts AS receipt
WHERE receipt.subject_id = 'sub_018f1234-5678-7abc-8def-0123456789d0';

UPDATE trust.evidence_event_outbox AS outbox
SET status = 'published',
    stream_sequence = mapping.stream_sequence,
    signed_event_sha256 = repeat('a', 64),
    published_at = clock_timestamp(),
    updated_at = clock_timestamp()
FROM (
  VALUES
    ('evt_018f1234-5678-7abc-8def-0123456789f0'::trust.evidence_event_id, 601::bigint),
    ('evt_018f1234-5678-7abc-8def-0123456789f1'::trust.evidence_event_id, 602::bigint),
    ('evt_018f1234-5678-7abc-8def-0123456789f2'::trust.evidence_event_id, 603::bigint),
    ('evt_018f1234-5678-7abc-8def-0123456789f3'::trust.evidence_event_id, 604::bigint),
    ('evt_018f1234-5678-7abc-8def-0123456789f4'::trust.evidence_event_id, 605::bigint),
    ('evt_018f1234-5678-7abc-8def-0123456789f5'::trust.evidence_event_id, 606::bigint),
    ('evt_018f1234-5678-7abc-8def-0123456789f6'::trust.evidence_event_id, 607::bigint),
    ('evt_018f1234-5678-7abc-8def-0123456789f7'::trust.evidence_event_id, 608::bigint)
) AS mapping(source_event_id, stream_sequence)
WHERE outbox.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  AND outbox.source_event_id = mapping.source_event_id;

CREATE TEMP TABLE trust_consumer_test_deliveries ON COMMIT DROP AS
SELECT outbox.delivery_event_id,
       outbox.evidence_id,
       outbox.stream_sequence,
       outbox.signed_event_sha256,
       receipt.evidence_type
FROM trust.evidence_event_outbox AS outbox
JOIN trust.evidence_ingestion_receipts AS receipt
  ON receipt.tenant_id = outbox.tenant_id
 AND receipt.event_id = outbox.source_event_id
WHERE outbox.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  AND outbox.stream_sequence BETWEEN 601 AND 608;
GRANT SELECT ON trust_consumer_test_deliveries TO tenant_trust_evidence_event_consumer;

SET LOCAL ROLE tenant_trust_evidence_event_consumer;

DO $verify_direct_access_denied$
BEGIN
  BEGIN
    PERFORM 1 FROM trust.subject_component_observations;
    RAISE EXCEPTION 'consumer read staging rows directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_direct_access_denied$;

DO $consume_initial_snapshot$
DECLARE
  delivered record;
  result record;
  processed integer := 0;
  score numeric;
BEGIN
  FOR delivered IN
    SELECT *
    FROM trust_consumer_test_deliveries
    WHERE stream_sequence BETWEEN 601 AND 605
    ORDER BY stream_sequence
  LOOP
    score := CASE delivered.evidence_type
      WHEN 'identity' THEN 91
      WHEN 'device' THEN 82.5
      WHEN 'behaviour' THEN 76
      WHEN 'certificate' THEN 100
      WHEN 'compliance' THEN 88
    END;
    SELECT * INTO STRICT result
    FROM trust.consume_validated_evidence_component(
      'trust-engine.v1',
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      delivered.delivery_event_id,
      delivered.evidence_id,
      delivered.stream_sequence,
      delivered.signed_event_sha256,
      score,
      clock_timestamp()
    );
    processed := processed + 1;
    IF NOT result.applied
       OR (processed < 5 AND result.outcome_code <> 'staged')
       OR (processed = 5 AND (result.outcome_code <> 'state_updated' OR result.update_version <> 1)) THEN
      RAISE EXCEPTION 'initial component % produced unexpected result %', processed, result;
    END IF;
  END LOOP;
END
$consume_initial_snapshot$;

DO $verify_duplicate_and_ordering$
DECLARE
  delivered record;
  result record;
BEGIN
  SELECT delivery_event_id, evidence_id, stream_sequence, signed_event_sha256
  INTO STRICT delivered
  FROM trust_consumer_test_deliveries
  WHERE stream_sequence = 605;
  SELECT * INTO STRICT result
  FROM trust.consume_validated_evidence_component(
    'trust-engine.v1',
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    delivered.delivery_event_id,
    delivered.evidence_id,
    delivered.stream_sequence,
    delivered.signed_event_sha256,
    88,
    clock_timestamp()
  );
  IF result.applied OR result.outcome_code <> 'duplicate' OR result.update_version <> 1 THEN
    RAISE EXCEPTION 'redelivery was not suppressed: %', result;
  END IF;

  SELECT delivery_event_id, evidence_id, stream_sequence, signed_event_sha256
  INTO STRICT delivered
  FROM trust_consumer_test_deliveries
  WHERE stream_sequence = 606;
  SELECT * INTO STRICT result
  FROM trust.consume_validated_evidence_component(
    'trust-engine.v1',
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    delivered.delivery_event_id,
    delivered.evidence_id,
    delivered.stream_sequence,
    delivered.signed_event_sha256,
    1,
    clock_timestamp()
  );
  IF NOT result.applied OR result.outcome_code <> 'superseded' OR result.update_version <> 1 THEN
    RAISE EXCEPTION 'older evidence rolled state backward: %', result;
  END IF;
END
$verify_duplicate_and_ordering$;

DO $verify_serial_updates$
DECLARE
  delivered record;
  result record;
BEGIN
  FOR delivered IN
    SELECT delivery_event_id,
           evidence_id,
           stream_sequence,
           signed_event_sha256
    FROM trust_consumer_test_deliveries
    WHERE stream_sequence IN (607, 608)
    ORDER BY stream_sequence
  LOOP
    SELECT * INTO STRICT result
    FROM trust.consume_validated_evidence_component(
      'trust-engine.v1',
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      delivered.delivery_event_id,
      delivered.evidence_id,
      delivered.stream_sequence,
      delivered.signed_event_sha256,
      CASE delivered.stream_sequence WHEN 607 THEN 95 ELSE 90 END,
      clock_timestamp()
    );
    IF result.outcome_code <> 'state_updated'
       OR result.update_version <> delivered.stream_sequence - 605 THEN
      RAISE EXCEPTION 'serialized subject update was lost: %', result;
    END IF;
  END LOOP;
END
$verify_serial_updates$;

DO $verify_cross_tenant_denial$
DECLARE
  delivered record;
BEGIN
  SELECT delivery_event_id, evidence_id, stream_sequence, signed_event_sha256
  INTO STRICT delivered
  FROM trust_consumer_test_deliveries
  WHERE stream_sequence = 601;
  BEGIN
    PERFORM trust.consume_validated_evidence_component(
      'trust-engine.v1',
      'tnt_018f1234-5678-7abc-8def-0123456789ac',
      delivered.delivery_event_id,
      delivered.evidence_id,
      delivered.stream_sequence,
      delivered.signed_event_sha256,
      91,
      clock_timestamp()
    );
    RAISE EXCEPTION 'cross-tenant event substitution was accepted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_cross_tenant_denial$;

RESET ROLE;

DO $verify_final_state$
DECLARE
  current_state record;
BEGIN
  SELECT * INTO STRICT current_state
  FROM trust.get_current_subject_trust_state(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789d0'
  );
  IF current_state.update_version <> 3
     OR current_state.identity_component <> 95
     OR current_state.device_component <> 90
     OR current_state.behaviour_component <> 76
     OR current_state.certificate_component <> 100
     OR current_state.compliance_component <> 88 THEN
    RAISE EXCEPTION 'current state lost one of the serialized component updates: %', current_state;
  END IF;

  IF (SELECT count(*) FROM trust.subject_trust_state_versions
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789d0') <> 3 THEN
    RAISE EXCEPTION 'unexpected trust-state version count';
  END IF;

  IF (SELECT count(*) FROM trust.evidence_event_effects
      WHERE consumer_name = 'trust-engine.v1'
        AND tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND delivery_event_id IN (
          SELECT delivery_event_id
          FROM trust.evidence_event_outbox
          WHERE source_event_id BETWEEN
            'evt_018f1234-5678-7abc-8def-0123456789f0'
            AND 'evt_018f1234-5678-7abc-8def-0123456789f7'
        )) <> 8 THEN
    RAISE EXCEPTION 'consume-once receipts are incomplete or duplicated';
  END IF;
END
$verify_final_state$;

ROLLBACK;

\echo 'Validated evidence trust-consumption checks passed and rolled back.'
