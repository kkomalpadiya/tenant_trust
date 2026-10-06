\set ON_ERROR_STOP on

BEGIN;

INSERT INTO trust.evidence_sources (
  tenant_id, source_id, issuer_id, source_name, evidence_type,
  state, verification_algorithm, maximum_age_seconds, synthetic
) VALUES (
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'src_018f1234-5678-7abc-8def-0123456789c7',
  NULL,
  'alpha-replay-verifier',
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
  'src_018f1234-5678-7abc-8def-0123456789c7',
  'key_018f1234-5678-7abc-8def-0123456789c8',
  'xTDFvh5FOfldrRPRPrV1n_LmzQQdLuIOwIs9J61tjbQ',
  transaction_timestamp()
);
SELECT set_config('tenant_trust.tenant_id', '', true);
SELECT set_config('tenant_trust.subject_id', '', true);

DO $guard$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_decision record;
BEGIN
  SELECT * INTO v_decision
  FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7',
    'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d0', 10,
    'AAAAAAAAAAAAAAAAAAAAAA', v_now - interval '5 seconds', v_now + interval '295 seconds',
    repeat('a', 64), true
  );
  IF NOT v_decision.accepted OR v_decision.highest_source_sequence <> 10 THEN
    RAISE EXCEPTION 'First fresh evidence was not accepted.';
  END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d1', 11,
    'BBBBBBBBBBBBBBBBBBBBBB', v_now + interval '31 seconds', v_now + interval '60 seconds', repeat('b', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_OBSERVED_IN_FUTURE' THEN RAISE EXCEPTION 'Future clock-skew rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d2', 11,
    'CCCCCCCCCCCCCCCCCCCCCC', v_now - interval '301 seconds', v_now + interval '30 seconds', repeat('c', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_STALE' THEN RAISE EXCEPTION 'Source-age rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d3', 11,
    'DDDDDDDDDDDDDDDDDDDDDD', v_now - interval '100 seconds', v_now - interval '1 second', repeat('d', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_EXPIRED' THEN RAISE EXCEPTION 'Expiry rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d4', 11,
    'EEEEEEEEEEEEEEEEEEEEEE', v_now, v_now + interval '301 seconds', repeat('e', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_TTL_EXCEEDED' THEN RAISE EXCEPTION 'TTL rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d5', 11,
    'FFFFFFFFFFFFFFFFFFFFFF', v_now, v_now, repeat('f', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_TIME_WINDOW_INVALID' THEN RAISE EXCEPTION 'Time-window rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d0', 10,
    'AAAAAAAAAAAAAAAAAAAAAA', v_now - interval '5 seconds', v_now + interval '295 seconds', repeat('a', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_EVENT_REPLAYED' THEN RAISE EXCEPTION 'Event replay rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d6', 11,
    'AAAAAAAAAAAAAAAAAAAAAA', v_now - interval '4 seconds', v_now + interval '296 seconds', repeat('6', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_NONCE_REPLAYED' THEN RAISE EXCEPTION 'Nonce replay rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d7', 10,
    'GGGGGGGGGGGGGGGGGGGGGG', v_now - interval '4 seconds', v_now + interval '296 seconds', repeat('7', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_SEQUENCE_REPLAYED' THEN RAISE EXCEPTION 'Sequence replay rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d8', 9,
    'HHHHHHHHHHHHHHHHHHHHHH', v_now - interval '4 seconds', v_now + interval '296 seconds', repeat('8', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_SEQUENCE_REORDERED' THEN RAISE EXCEPTION 'Sequence reordering rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789d9', 11,
    'IIIIIIIIIIIIIIIIIIIIII', v_now - interval '6 seconds', v_now + interval '294 seconds', repeat('9', 64), true
  );
  IF v_decision.reason_code <> 'EVIDENCE_OBSERVATION_REORDERED' THEN RAISE EXCEPTION 'Observation reordering rejection failed.'; END IF;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789c7', 'key_018f1234-5678-7abc-8def-0123456789c8',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789da', 11,
    'JJJJJJJJJJJJJJJJJJJJJJ', v_now - interval '4 seconds', v_now + interval '296 seconds', repeat('0', 64), true
  );
  IF NOT v_decision.accepted OR v_decision.highest_source_sequence <> 11 THEN
    RAISE EXCEPTION 'A later monotonic observation was not accepted.';
  END IF;
END
$guard$;

RESET ROLE;

DO $verification$
BEGIN
  IF (
    SELECT count(*) FROM trust.evidence_ingestion_receipts
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789c7'
  ) <> 2 THEN
    RAISE EXCEPTION 'Accepted evidence receipt count was not two.';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM trust.evidence_ingestion_state
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789c7'
      AND highest_source_sequence = 11
      AND accepted_count = 2
  ) THEN
    RAISE EXCEPTION 'Replay state advanced incorrectly after rejections.';
  END IF;

  IF (
    SELECT count(*) FROM trust.evidence_ingestion_rejections
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789c7'
  ) <> 10 OR (
    SELECT count(DISTINCT reason_code) FROM trust.evidence_ingestion_rejections
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789c7'
  ) <> 10 THEN
    RAISE EXCEPTION 'Observable rejection audit did not retain all bounded reason codes.';
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'trust'
      AND table_name = 'evidence_ingestion_rejections'
      AND column_name IN ('event_id', 'nonce', 'payload')
  ) THEN
    RAISE EXCEPTION 'Rejection audit exposes a raw event, nonce or payload column.';
  END IF;

  IF has_table_privilege('tenant_trust_app', 'trust.evidence_ingestion_receipts', 'SELECT')
    OR has_table_privilege('tenant_trust_app', 'trust.evidence_ingestion_rejections', 'SELECT')
    OR has_table_privilege('tenant_trust_app', 'trust.evidence_ingestion_state', 'UPDATE') THEN
    RAISE EXCEPTION 'Application role received direct replay-state or audit-table access.';
  END IF;

  BEGIN
    UPDATE trust.evidence_ingestion_receipts
    SET source_sequence = 12
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789c7';
    RAISE EXCEPTION 'Accepted evidence history was mutable.';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    DELETE FROM trust.evidence_ingestion_rejections
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789c7';
    RAISE EXCEPTION 'Evidence rejection history was mutable.';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$verification$;

ROLLBACK;

SELECT 'PASS trusted-time skew, expiry and source TTL rules reject invalid evidence' AS result;
SELECT 'PASS duplicate event IDs, nonces and non-monotonic source observations cannot advance state' AS result;
SELECT 'PASS rejection reasons remain observable with hash-only identifiers and append-only history' AS result;
