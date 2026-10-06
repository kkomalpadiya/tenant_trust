\set ON_ERROR_STOP on

DO $verify_delivery_privileges$
BEGIN
  IF has_table_privilege('tenant_trust_app', 'trust.evidence_event_outbox', 'SELECT')
     OR has_table_privilege('tenant_trust_evidence_event_worker', 'trust.evidence_event_outbox', 'SELECT')
     OR has_table_privilege('tenant_trust_evidence_event_consumer', 'trust.evidence_event_effects', 'SELECT') THEN
    RAISE EXCEPTION 'evidence event roles received direct delivery-table privileges';
  END IF;
  IF NOT has_function_privilege(
    'tenant_trust_evidence_event_worker',
    'trust.claim_evidence_event_outbox(identity.tenant_id, text, trust.evidence_event_claim_token, timestamptz)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'tenant_trust_evidence_event_consumer',
    'trust.record_evidence_event_effect(text, identity.tenant_id, identity.event_id, trust.evidence_id, bigint, identity.sha256_digest, timestamptz)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'evidence event roles lack their constrained delivery functions';
  END IF;
END
$verify_delivery_privileges$;

BEGIN;

INSERT INTO trust.evidence_sources (
  tenant_id, source_id, issuer_id, source_name, evidence_type,
  state, verification_algorithm, maximum_age_seconds, synthetic
) VALUES (
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'src_018f1234-5678-7abc-8def-0123456789e1',
  NULL, 'alpha-event-delivery-verifier', 'identity', 'planned', 'ed25519', 300, true
);

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
SELECT * FROM trust.enroll_evidence_source(
  'src_018f1234-5678-7abc-8def-0123456789e1',
  'key_018f1234-5678-7abc-8def-0123456789e2',
  'xTDFvh5FOfldrRPRPrV1n_LmzQQdLuIOwIs9J61tjbQ',
  transaction_timestamp()
);
SELECT set_config('tenant_trust.tenant_id', '', true);
SELECT set_config('tenant_trust.subject_id', '', true);

DO $accept_and_store_three$
DECLARE now_at_accept timestamptz := clock_timestamp();
DECLARE decision record;
DECLARE suffix text;
DECLARE sequence_number integer;
BEGIN
  FOR sequence_number IN 1..3 LOOP
    suffix := CASE sequence_number WHEN 1 THEN 'e3' WHEN 2 THEN 'e4' ELSE 'e5' END;
    SELECT * INTO decision FROM trust.apply_evidence_replay_guard(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789e1',
      'key_018f1234-5678-7abc-8def-0123456789e2',
      'identity', ('evt_018f1234-5678-7abc-8def-0123456789' || suffix)::trust.evidence_event_id,
      sequence_number,
      CASE sequence_number
        WHEN 1 THEN 'AAAAAAAAAAAAAAAAAAAAAA'
        WHEN 2 THEN 'BBBBBBBBBBBBBBBBBBBBBB'
        ELSE 'CCCCCCCCCCCCCCCCCCCCCC'
      END,
      now_at_accept - interval '1 second' + sequence_number * interval '1 millisecond',
      now_at_accept + interval '299 seconds', repeat(sequence_number::text, 64), true
    );
    IF NOT decision.accepted THEN RAISE EXCEPTION 'Delivery fixture evidence % was rejected.', sequence_number; END IF;
    PERFORM trust.store_encrypted_evidence(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      ('evt_018f1234-5678-7abc-8def-0123456789' || suffix)::trust.evidence_event_id,
      1::smallint, 'local-evidence-v1', decode(repeat('11', 12), 'hex'),
      decode(repeat('22', 16), 'hex'), decode(repeat('33', 32), 'hex'),
      repeat('a', 64), 32
    );
  END LOOP;
END
$accept_and_store_three$;

DO $atomic_enqueue_rollback$
DECLARE now_at_attempt timestamptz := clock_timestamp();
DECLARE blocked boolean := false;
BEGIN
  BEGIN
    PERFORM trust.apply_evidence_replay_guard(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789e1',
      'key_018f1234-5678-7abc-8def-0123456789e2',
      'identity', 'evt_018f1234-5678-7abc-8def-0123456789e6', 4,
      'DDDDDDDDDDDDDDDDDDDDDD', now_at_attempt,
      now_at_attempt + interval '299 seconds', repeat('4', 64), true
    );
    SET CONSTRAINTS trust.evidence_receipt_requires_encrypted_storage IMMEDIATE;
  EXCEPTION WHEN check_violation THEN
    blocked := true;
  END;
  SET CONSTRAINTS trust.evidence_receipt_requires_encrypted_storage DEFERRED;
  IF NOT blocked THEN RAISE EXCEPTION 'Unstored accepted evidence was allowed to commit.'; END IF;
END
$atomic_enqueue_rollback$;

RESET ROLE;

DO $verify_atomic_outbox$
BEGIN
  IF (SELECT count(*) FROM trust.evidence_event_outbox
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND source_event_id IN (
          'evt_018f1234-5678-7abc-8def-0123456789e3',
          'evt_018f1234-5678-7abc-8def-0123456789e4',
          'evt_018f1234-5678-7abc-8def-0123456789e5'
        )) <> 3 THEN
    RAISE EXCEPTION 'Every stored acceptance did not receive one outbox identity.';
  END IF;
  IF EXISTS (SELECT 1 FROM trust.evidence_event_outbox
             WHERE source_event_id = 'evt_018f1234-5678-7abc-8def-0123456789e6') THEN
    RAISE EXCEPTION 'Rolled-back accepted evidence retained an outbox identity.';
  END IF;
END
$verify_atomic_outbox$;

SET LOCAL ROLE tenant_trust_evidence_event_worker;

DO $publish_first$
DECLARE claimed record;
DECLARE published record;
BEGIN
  SELECT * INTO claimed FROM trust.claim_evidence_event_outbox(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'publisher.local-1',
    'clm_018f1234-5678-7abc-8def-0123456789e1', clock_timestamp()
  );
  IF claimed.event_id IS NULL OR claimed.evidence_id IS NULL OR claimed.source_event_id IS NULL
     OR claimed.attempt_count <> 1 OR claimed.content_hash_sha256 <> repeat('1', 64) THEN
    RAISE EXCEPTION 'Publisher did not claim complete authoritative evidence metadata.';
  END IF;
  SELECT * INTO published FROM trust.mark_evidence_event_published(
    claimed.tenant_id, claimed.event_id, claimed.claim_token,
    501, repeat('a', 64), clock_timestamp()
  );
  IF published.status <> 'published' OR published.stream_sequence <> 501 THEN
    RAISE EXCEPTION 'Acknowledged evidence event was not durably confirmed.';
  END IF;
END
$publish_first$;

DO $retry_second$
DECLARE claimed record;
DECLARE failed record;
BEGIN
  SELECT * INTO claimed FROM trust.claim_evidence_event_outbox(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'publisher.local-1',
    'clm_018f1234-5678-7abc-8def-0123456789e2', clock_timestamp()
  );
  SELECT * INTO failed FROM trust.mark_evidence_event_publish_failed(
    claimed.tenant_id, claimed.event_id, claimed.claim_token,
    'NATS_UNAVAILABLE', clock_timestamp(), 5
  );
  IF failed.status <> 'pending' THEN RAISE EXCEPTION 'Publish failure did not become retryable.'; END IF;
END
$retry_second$;

DO $claim_third$
DECLARE claimed record;
BEGIN
  SELECT * INTO claimed FROM trust.claim_evidence_event_outbox(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'publisher.local-1',
    'clm_018f1234-5678-7abc-8def-0123456789e3', clock_timestamp()
  );
  IF claimed.event_id IS NULL THEN RAISE EXCEPTION 'Third event was not claimable.'; END IF;
END
$claim_third$;

RESET ROLE;

UPDATE trust.evidence_event_outbox
SET created_at = created_at - interval '10 minutes',
    claimed_at = claimed_at - interval '6 minutes',
    updated_at = updated_at
WHERE claim_token = 'clm_018f1234-5678-7abc-8def-0123456789e3';

SET LOCAL ROLE tenant_trust_evidence_event_worker;

DO $recover_after_restart$
DECLARE claimed record;
BEGIN
  SELECT * INTO claimed FROM trust.claim_evidence_event_outbox(
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 'publisher.local-2',
    'clm_018f1234-5678-7abc-8def-0123456789e4', clock_timestamp()
  );
  IF claimed.claim_token <> 'clm_018f1234-5678-7abc-8def-0123456789e4'
     OR claimed.attempt_count <> 2 THEN
    RAISE EXCEPTION 'Restart did not recover the stale publisher claim.';
  END IF;
  PERFORM trust.mark_evidence_event_published(
    claimed.tenant_id, claimed.event_id, claimed.claim_token,
    503, repeat('c', 64), clock_timestamp()
  );
END
$recover_after_restart$;

RESET ROLE;

DO $consume_once$
DECLARE published record;
DECLARE first_recorded boolean;
DECLARE duplicate_recorded boolean;
BEGIN
  SELECT delivery_event_id, evidence_id, stream_sequence, signed_event_sha256
  INTO published
  FROM trust.evidence_event_outbox
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
    AND stream_sequence = 501;
  SELECT trust.record_evidence_event_effect(
    'trust-engine.v1', 'tnt_018f1234-5678-7abc-8def-0123456789ab',
    published.delivery_event_id, published.evidence_id,
    published.stream_sequence, published.signed_event_sha256, clock_timestamp()
  ) INTO first_recorded;
  SELECT trust.record_evidence_event_effect(
    'trust-engine.v1', 'tnt_018f1234-5678-7abc-8def-0123456789ab',
    published.delivery_event_id, published.evidence_id,
    published.stream_sequence, published.signed_event_sha256, clock_timestamp()
  ) INTO duplicate_recorded;
  IF NOT first_recorded OR duplicate_recorded THEN
    RAISE EXCEPTION 'Consumer idempotency did not accept once and suppress redelivery.';
  END IF;
END
$consume_once$;

DO $verify_durable_state$
BEGIN
  IF (SELECT count(*) FROM trust.evidence_event_effects
      WHERE consumer_name = 'trust-engine.v1'
        AND tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab') <> 1 THEN
    RAISE EXCEPTION 'Duplicate delivery produced more than one durable effect receipt.';
  END IF;
  IF (SELECT count(*) FROM trust.evidence_event_outbox
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND status = 'published' AND stream_sequence IN (501, 503)) <> 2 THEN
    RAISE EXCEPTION 'Published delivery evidence is incomplete after restart recovery.';
  END IF;
  IF (SELECT count(*) FROM trust.evidence_event_outbox
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND status = 'pending' AND last_failure_code = 'NATS_UNAVAILABLE'
        AND attempt_count = 1 AND next_attempt_at > clock_timestamp()) <> 1 THEN
    RAISE EXCEPTION 'Retryable publisher failure state is incomplete.';
  END IF;
END
$verify_durable_state$;

ROLLBACK;

\echo 'PASS accepted evidence is atomically queued only with encrypted storage'
\echo 'PASS publisher failures retry and stale claims recover after worker restart'
\echo 'PASS consumer redelivery records one durable processing effect'
