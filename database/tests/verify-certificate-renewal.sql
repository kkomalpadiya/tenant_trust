\set ON_ERROR_STOP on

DO $verify_certificate_renewal_schema$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'identity'
      AND table_name = 'certificates'
      AND column_name = 'public_key_sha256'
  ) THEN
    RAISE EXCEPTION 'certificate SPKI digest column is missing';
  END IF;
  IF NOT has_function_privilege(
    'tenant_trust_app',
    'identity.record_certificate_renewal(identity.certificate_id,identity.event_id,identity.event_id,identity.correlation_id,identity.request_id,identity.certificate_id,identity.subject_id,identity.issuer_id,identity.certificate_profile_id,identity.x509_serial_number,identity.sha256_digest,identity.sha256_digest,text,timestamptz,timestamptz,timestamptz,identity.idempotency_key)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'tenant runtime role cannot execute the renewal transition';
  END IF;
END
$verify_certificate_renewal_schema$;

BEGIN;

UPDATE identity.tenant_issuer_mappings
SET state = 'active',
    root_certificate_sha256 = repeat('a', 64),
    updated_at = clock_timestamp()
WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab';

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $create_renewal_predecessors$
DECLARE
  at_time timestamptz := clock_timestamp();
BEGIN
  PERFORM identity.record_certificate_issuance(
    'crt_018f1234-5678-7abc-8def-0123456789a1',
    'evt_018f1234-5678-7abc-8def-0123456789a1',
    'cor_018f1234-5678-7abc-8def-0123456789a1',
    'req_018f1234-5678-7abc-8def-0123456789a1',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1', '00000000000000000000000000000011',
    repeat('1', 64), repeat('a', 64), 'ecdsa-p256',
    at_time - interval '49 minutes', at_time + interval '11 minutes',
    at_time - interval '48 minutes', 'tenant-alpha:certificate:issue:renewable'
  );
  PERFORM identity.record_certificate_issuance(
    'crt_018f1234-5678-7abc-8def-0123456789a2',
    'evt_018f1234-5678-7abc-8def-0123456789a2',
    'cor_018f1234-5678-7abc-8def-0123456789a2',
    'req_018f1234-5678-7abc-8def-0123456789a2',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1', '00000000000000000000000000000012',
    repeat('2', 64), repeat('b', 64), 'ecdsa-p256',
    at_time - interval '1 minute', at_time + interval '59 minutes',
    at_time, 'tenant-alpha:certificate:issue:early'
  );
  PERFORM identity.record_certificate_issuance(
    'crt_018f1234-5678-7abc-8def-0123456789a3',
    'evt_018f1234-5678-7abc-8def-0123456789a3',
    'cor_018f1234-5678-7abc-8def-0123456789a3',
    'req_018f1234-5678-7abc-8def-0123456789a3',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1', '00000000000000000000000000000013',
    repeat('3', 64), repeat('c', 64), 'ecdsa-p256',
    at_time - interval '49 minutes', at_time + interval '11 minutes',
    at_time - interval '48 minutes', 'tenant-alpha:certificate:issue:revoked'
  );
  PERFORM identity.record_certificate_issuance(
    'crt_018f1234-5678-7abc-8def-0123456789a4',
    'evt_018f1234-5678-7abc-8def-0123456789a4',
    'cor_018f1234-5678-7abc-8def-0123456789a4',
    'req_018f1234-5678-7abc-8def-0123456789a4',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1', '00000000000000000000000000000014',
    repeat('4', 64), repeat('d', 64), 'ecdsa-p256',
    at_time - interval '49 minutes', at_time + interval '11 minutes',
    at_time - interval '48 minutes', 'tenant-alpha:certificate:issue:suspended'
  );
END
$create_renewal_predecessors$;

RESET ROLE;
UPDATE identity.certificates
SET state = 'revoked',
    state_changed_at = clock_timestamp(),
    updated_at = clock_timestamp(),
    version = version + 1
WHERE certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789a3';

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_denied_renewals$
DECLARE
  at_time timestamptz := clock_timestamp();
BEGIN
  BEGIN
    PERFORM identity.record_certificate_renewal(
      'crt_018f1234-5678-7abc-8def-0123456789b2',
      'evt_018f1234-5678-7abc-8def-0123456789b2',
      'evt_018f1234-5678-7abc-8def-0123456789c2',
      'cor_018f1234-5678-7abc-8def-0123456789b2',
      'req_018f1234-5678-7abc-8def-0123456789b2',
      'crt_018f1234-5678-7abc-8def-0123456789a2',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1', '00000000000000000000000000000022',
      repeat('5', 64), repeat('e', 64), 'ecdsa-p256',
      at_time - interval '1 minute', at_time + interval '59 minutes', at_time,
      'tenant-alpha:certificate:renew:early'
    );
    RAISE EXCEPTION 'early renewal was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM identity.record_certificate_renewal(
      'crt_018f1234-5678-7abc-8def-0123456789b3',
      'evt_018f1234-5678-7abc-8def-0123456789b3',
      'evt_018f1234-5678-7abc-8def-0123456789c3',
      'cor_018f1234-5678-7abc-8def-0123456789b3',
      'req_018f1234-5678-7abc-8def-0123456789b3',
      'crt_018f1234-5678-7abc-8def-0123456789a3',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1', '00000000000000000000000000000023',
      repeat('6', 64), repeat('f', 64), 'ecdsa-p256',
      at_time - interval '1 minute', at_time + interval '59 minutes', at_time,
      'tenant-alpha:certificate:renew:revoked'
    );
    RAISE EXCEPTION 'revoked certificate was renewed';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM identity.record_certificate_renewal(
      'crt_018f1234-5678-7abc-8def-0123456789b4',
      'evt_018f1234-5678-7abc-8def-0123456789b4',
      'evt_018f1234-5678-7abc-8def-0123456789c4',
      'cor_018f1234-5678-7abc-8def-0123456789b4',
      'req_018f1234-5678-7abc-8def-0123456789b4',
      'crt_018f1234-5678-7abc-8def-0123456789a1',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1', '00000000000000000000000000000024',
      repeat('7', 64), repeat('a', 64), 'ecdsa-p256',
      at_time - interval '1 minute', at_time + interval '59 minutes', at_time,
      'tenant-alpha:certificate:renew:same-key'
    );
    RAISE EXCEPTION 'same-key renewal was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_denied_renewals$;

DO $verify_atomic_renewal$
DECLARE
  at_time timestamptz := clock_timestamp();
  recorded record;
  replay record;
BEGIN
  SELECT * INTO recorded FROM identity.record_certificate_renewal(
    'crt_018f1234-5678-7abc-8def-0123456789b1',
    'evt_018f1234-5678-7abc-8def-0123456789b1',
    'evt_018f1234-5678-7abc-8def-0123456789c1',
    'cor_018f1234-5678-7abc-8def-0123456789b1',
    'req_018f1234-5678-7abc-8def-0123456789b1',
    'crt_018f1234-5678-7abc-8def-0123456789a1',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1', '00000000000000000000000000000021',
    repeat('8', 64), repeat('9', 64), 'ecdsa-p256',
    at_time - interval '1 minute', at_time + interval '59 minutes', at_time,
    'tenant-alpha:certificate:renew:valid'
  );

  IF recorded.recorded_state <> 'active'
     OR recorded.recorded_predecessor_state <> 'superseded'
     OR NOT EXISTS (
       SELECT 1 FROM identity.certificates
       WHERE certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789b1'
         AND state = 'active'
         AND supersedes_certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789a1'
         AND public_key_sha256 = repeat('9', 64)
     ) OR NOT EXISTS (
       SELECT 1 FROM identity.certificates
       WHERE certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789a1'
         AND state = 'superseded'
         AND last_event_id = 'evt_018f1234-5678-7abc-8def-0123456789c1'
         AND version = 2
     ) THEN
    RAISE EXCEPTION 'atomic renewal did not activate the successor and supersede its predecessor';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM identity.certificate_lifecycle_events
    WHERE event_id = 'evt_018f1234-5678-7abc-8def-0123456789b1'
      AND event_type = 'renewed'
      AND certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789b1'
      AND causation_event_id = 'evt_018f1234-5678-7abc-8def-0123456789a1'
  ) OR NOT EXISTS (
    SELECT 1 FROM identity.certificate_lifecycle_events
    WHERE event_id = 'evt_018f1234-5678-7abc-8def-0123456789c1'
      AND event_type = 'superseded'
      AND certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789a1'
      AND causation_event_id = 'evt_018f1234-5678-7abc-8def-0123456789b1'
      AND reason_code = 'CERTIFICATE_RENEWED'
  ) THEN
    RAISE EXCEPTION 'renewal and supersession event chain is incomplete';
  END IF;

  SELECT * INTO replay FROM identity.record_certificate_renewal(
    'crt_018f1234-5678-7abc-8def-0123456789d1',
    'evt_018f1234-5678-7abc-8def-0123456789d1',
    'evt_018f1234-5678-7abc-8def-0123456789d2',
    'cor_018f1234-5678-7abc-8def-0123456789d1',
    'req_018f1234-5678-7abc-8def-0123456789b1',
    'crt_018f1234-5678-7abc-8def-0123456789a1',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1', '00000000000000000000000000000021',
    repeat('8', 64), repeat('9', 64), 'ecdsa-p256',
    at_time - interval '1 minute', at_time + interval '59 minutes', at_time,
    'tenant-alpha:certificate:renew:valid'
  );
  IF replay.recorded_certificate_id <> recorded.recorded_certificate_id
     OR replay.recorded_renewed_event_id <> recorded.recorded_renewed_event_id
     OR replay.recorded_superseded_event_id <> recorded.recorded_superseded_event_id THEN
    RAISE EXCEPTION 'renewal idempotency replay did not return durable identities';
  END IF;

  BEGIN
    PERFORM identity.record_certificate_renewal(
      'crt_018f1234-5678-7abc-8def-0123456789b5',
      'evt_018f1234-5678-7abc-8def-0123456789b5',
      'evt_018f1234-5678-7abc-8def-0123456789c5',
      'cor_018f1234-5678-7abc-8def-0123456789b5',
      'req_018f1234-5678-7abc-8def-0123456789b5',
      'crt_018f1234-5678-7abc-8def-0123456789a1',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1', '00000000000000000000000000000025',
      repeat('a', 64), repeat('b', 64), 'ecdsa-p256',
      at_time - interval '1 minute', at_time + interval '59 minutes', at_time,
      'tenant-alpha:certificate:renew:second'
    );
    RAISE EXCEPTION 'superseded predecessor was renewed twice';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_atomic_renewal$;

RESET ROLE;
UPDATE identity.subjects
SET state = 'suspended', updated_at = clock_timestamp()
WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab';

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_suspended_subject_denied$
DECLARE at_time timestamptz := clock_timestamp();
BEGIN
  BEGIN
    PERFORM identity.record_certificate_renewal(
      'crt_018f1234-5678-7abc-8def-0123456789b6',
      'evt_018f1234-5678-7abc-8def-0123456789b6',
      'evt_018f1234-5678-7abc-8def-0123456789c6',
      'cor_018f1234-5678-7abc-8def-0123456789b6',
      'req_018f1234-5678-7abc-8def-0123456789b6',
      'crt_018f1234-5678-7abc-8def-0123456789a4',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1', '00000000000000000000000000000026',
      repeat('c', 64), repeat('e', 64), 'ecdsa-p256',
      at_time - interval '1 minute', at_time + interval '59 minutes', at_time,
      'tenant-alpha:certificate:renew:suspended'
    );
    RAISE EXCEPTION 'suspended subject was renewed';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_suspended_subject_denied$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ad'
);

DO $verify_foreign_tenant_denied$
DECLARE at_time timestamptz := clock_timestamp();
BEGIN
  BEGIN
    PERFORM identity.record_certificate_renewal(
      'crt_018f1234-5678-7abc-8def-0123456789b7',
      'evt_018f1234-5678-7abc-8def-0123456789b7',
      'evt_018f1234-5678-7abc-8def-0123456789c7',
      'cor_018f1234-5678-7abc-8def-0123456789b7',
      'req_018f1234-5678-7abc-8def-0123456789b7',
      'crt_018f1234-5678-7abc-8def-0123456789a4',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1', '00000000000000000000000000000027',
      repeat('d', 64), repeat('f', 64), 'ecdsa-p256',
      at_time - interval '1 minute', at_time + interval '59 minutes', at_time,
      'tenant-beta:certificate:renew:foreign'
    );
    RAISE EXCEPTION 'foreign tenant renewed an Alpha certificate';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_foreign_tenant_denied$;

RESET ROLE;
ROLLBACK;

\echo 'PASS renewal rotates keys, enforces eligibility and records atomic supersession'
