\set ON_ERROR_STOP on

DO $verify_outbox_schema$
BEGIN
  IF has_table_privilege('tenant_trust_app', 'identity.certificate_event_outbox', 'SELECT')
     OR has_table_privilege('tenant_trust_certificate_event_worker', 'identity.certificate_event_outbox', 'SELECT') THEN
    RAISE EXCEPTION 'certificate event outbox received direct runtime table privileges';
  END IF;
  IF has_function_privilege(
    'tenant_trust_app',
    'identity.claim_certificate_event_outbox(identity.tenant_id, text, identity.certificate_event_claim_token, timestamptz)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'tenant application role can claim platform event work';
  END IF;
  IF NOT has_function_privilege(
    'tenant_trust_certificate_event_worker',
    'identity.claim_certificate_event_outbox(identity.tenant_id, text, identity.certificate_event_claim_token, timestamptz)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'tenant_trust_certificate_event_worker',
    'identity.record_due_certificate_expiration(identity.tenant_id, identity.certificate_id, identity.event_id, identity.correlation_id, timestamptz)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'certificate event worker lacks its constrained functions';
  END IF;
END
$verify_outbox_schema$;

BEGIN;

UPDATE identity.tenant_issuer_mappings
SET state = 'active', root_certificate_sha256 = repeat('a', 64), updated_at = clock_timestamp()
WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab';

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

SELECT * FROM identity.record_certificate_issuance(
  'crt_018f1234-5678-7abc-8def-0123456789d1',
  'evt_018f1234-5678-7abc-8def-0123456789d1',
  'cor_018f1234-5678-7abc-8def-0123456789d1',
  'req_018f1234-5678-7abc-8def-0123456789d1',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1', '00000000000000000000000000000051',
  repeat('1', 64), repeat('2', 64), 'ecdsa-p256',
  clock_timestamp() - interval '2 hours',
  clock_timestamp() - interval '1 minute',
  clock_timestamp() - interval '90 minutes',
  'tenant-alpha:certificate:event:expiry-source'
);

SELECT * FROM identity.record_certificate_issuance(
  'crt_018f1234-5678-7abc-8def-0123456789d2',
  'evt_018f1234-5678-7abc-8def-0123456789d2',
  'cor_018f1234-5678-7abc-8def-0123456789d2',
  'req_018f1234-5678-7abc-8def-0123456789d2',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1', '00000000000000000000000000000052',
  repeat('3', 64), repeat('4', 64), 'ecdsa-p256',
  clock_timestamp() - interval '5 minutes',
  clock_timestamp() + interval '55 minutes',
  clock_timestamp() - interval '4 minutes',
  'tenant-alpha:certificate:event:revocation-source'
);

SELECT * FROM identity.record_certificate_issuance(
  'crt_018f1234-5678-7abc-8def-0123456789d3',
  'evt_018f1234-5678-7abc-8def-0123456789d3',
  'cor_018f1234-5678-7abc-8def-0123456789d3',
  'req_018f1234-5678-7abc-8def-0123456789d3',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1', '00000000000000000000000000000053',
  repeat('5', 64), repeat('6', 64), 'ecdsa-p256',
  clock_timestamp() - interval '40 minutes',
  clock_timestamp() + interval '10 minutes',
  clock_timestamp() - interval '30 minutes',
  'tenant-alpha:certificate:event:renewal-source'
);

SELECT * FROM identity.record_certificate_renewal(
  'crt_018f1234-5678-7abc-8def-0123456789d4',
  'evt_018f1234-5678-7abc-8def-0123456789d4',
  'evt_018f1234-5678-7abc-8def-0123456789d5',
  'cor_018f1234-5678-7abc-8def-0123456789d4',
  'req_018f1234-5678-7abc-8def-0123456789d4',
  'crt_018f1234-5678-7abc-8def-0123456789d3',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1', '00000000000000000000000000000054',
  repeat('7', 64), repeat('8', 64), 'ecdsa-p256',
  clock_timestamp() - interval '1 minute',
  clock_timestamp() + interval '1 hour',
  clock_timestamp(),
  'tenant-alpha:certificate:event:renewal-successor'
);

SELECT * FROM identity.record_certificate_revocation(
  'evt_018f1234-5678-7abc-8def-0123456789d6',
  'cor_018f1234-5678-7abc-8def-0123456789d6',
  'req_018f1234-5678-7abc-8def-0123456789d6',
  'crt_018f1234-5678-7abc-8def-0123456789d2',
  'KEY_COMPROMISE', clock_timestamp(),
  'tenant-alpha:certificate:event:revocation',
  'step-ca:revocation:event-outbox-0001'
);

RESET ROLE;
SET LOCAL ROLE tenant_trust_certificate_event_worker;

SELECT * FROM identity.record_due_certificate_expiration(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'crt_018f1234-5678-7abc-8def-0123456789d1',
  'evt_018f1234-5678-7abc-8def-0123456789d7',
  'cor_018f1234-5678-7abc-8def-0123456789d7',
  clock_timestamp()
);

DO $verify_expiry_and_enqueue$
DECLARE replay record;
BEGIN
  SELECT * INTO replay FROM identity.record_due_certificate_expiration(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'crt_018f1234-5678-7abc-8def-0123456789d1',
    'evt_018f1234-5678-7abc-8def-0123456789d8',
    'cor_018f1234-5678-7abc-8def-0123456789d8',
    clock_timestamp()
  );
  IF replay.recorded_event_id <> 'evt_018f1234-5678-7abc-8def-0123456789d7'
     OR replay.recorded_state <> 'expired' OR replay.recorded_version <> 2 THEN
    RAISE EXCEPTION 'expiration replay did not return the durable terminal event';
  END IF;

END
$verify_expiry_and_enqueue$;

DO $verify_publish_confirmation$
DECLARE claimed record; published record;
BEGIN
  SELECT * INTO claimed FROM identity.claim_certificate_event_outbox(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'publisher.local-1',
    'clm_018f1234-5678-7abc-8def-0123456789d1',
    clock_timestamp()
  );
  IF claimed.event_id IS NULL OR claimed.claim_token <> 'clm_018f1234-5678-7abc-8def-0123456789d1'
     OR claimed.attempt_count <> 1 OR claimed.certificate_id IS NULL
     OR claimed.correlation_id IS NULL THEN
    RAISE EXCEPTION 'publisher could not claim one complete authoritative event';
  END IF;

  SELECT * INTO published FROM identity.mark_certificate_event_published(
    claimed.tenant_id, claimed.event_id, claimed.claim_token,
    101, repeat('a', 64), clock_timestamp()
  );
  IF published.event_id <> claimed.event_id OR published.status <> 'published'
     OR published.stream_sequence <> 101 OR published.signed_event_sha256 <> repeat('a', 64) THEN
    RAISE EXCEPTION 'acknowledged publish evidence was not durably recorded';
  END IF;

  BEGIN
    PERFORM identity.mark_certificate_event_published(
      claimed.tenant_id, claimed.event_id,
      'clm_018f1234-5678-7abc-8def-0123456789d9',
      102, repeat('b', 64), clock_timestamp()
    );
    RAISE EXCEPTION 'wrong claim token confirmed a published event';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_publish_confirmation$;

DO $verify_failure_retry$
DECLARE claimed record; failed record;
BEGIN
  SELECT * INTO claimed FROM identity.claim_certificate_event_outbox(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'publisher.local-1',
    'clm_018f1234-5678-7abc-8def-0123456789d2',
    clock_timestamp()
  );
  SELECT * INTO failed FROM identity.mark_certificate_event_publish_failed(
    claimed.tenant_id, claimed.event_id, claimed.claim_token,
    'NATS_UNAVAILABLE', clock_timestamp(), 5
  );
  IF failed.event_id <> claimed.event_id OR failed.status <> 'pending' THEN
    RAISE EXCEPTION 'publish failure did not return to pending with a bounded retry';
  END IF;
END
$verify_failure_retry$;

DO $verify_early_expiry_denied$
BEGIN
  BEGIN
    PERFORM identity.record_due_certificate_expiration(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'crt_018f1234-5678-7abc-8def-0123456789d4',
      'evt_018f1234-5678-7abc-8def-0123456789da',
      'cor_018f1234-5678-7abc-8def-0123456789da',
      clock_timestamp()
    );
    RAISE EXCEPTION 'non-due certificate was expired';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_early_expiry_denied$;

RESET ROLE;

DO $verify_durable_outbox_state$
BEGIN
  IF (SELECT count(*) FROM identity.certificate_event_outbox
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND event_id IN (
          'evt_018f1234-5678-7abc-8def-0123456789d1',
          'evt_018f1234-5678-7abc-8def-0123456789d2',
          'evt_018f1234-5678-7abc-8def-0123456789d3',
          'evt_018f1234-5678-7abc-8def-0123456789d4',
          'evt_018f1234-5678-7abc-8def-0123456789d5',
          'evt_018f1234-5678-7abc-8def-0123456789d6',
          'evt_018f1234-5678-7abc-8def-0123456789d7'
        )) <> 7 THEN
    RAISE EXCEPTION 'not every issuance, renewal, supersession, revocation and expiry event was transactionally enqueued';
  END IF;
  IF (SELECT count(*) FROM identity.certificate_event_outbox
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND status = 'published' AND stream_sequence = 101
        AND signed_event_sha256 = repeat('a', 64) AND published_at IS NOT NULL) <> 1 THEN
    RAISE EXCEPTION 'published outbox evidence is incomplete';
  END IF;
  IF (SELECT count(*) FROM identity.certificate_event_outbox
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND status = 'pending' AND last_failure_code = 'NATS_UNAVAILABLE'
        AND attempt_count = 1 AND next_attempt_at > clock_timestamp()) <> 1 THEN
    RAISE EXCEPTION 'failed outbox evidence or retry timing is incomplete';
  END IF;
END
$verify_durable_outbox_state$;

ROLLBACK;

\echo 'PASS certificate lifecycle events are transactionally queued, expiry is causal and publish acknowledgements are claim-bound'
