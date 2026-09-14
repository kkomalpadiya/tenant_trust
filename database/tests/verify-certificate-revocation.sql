\set ON_ERROR_STOP on

DO $verify_revocation_schema$
BEGIN
  IF NOT has_function_privilege(
    'tenant_trust_app',
    'identity.record_certificate_revocation(identity.event_id, identity.correlation_id, identity.request_id, identity.certificate_id, identity.certificate_revocation_reason, timestamptz, identity.idempotency_key, identity.issuer_confirmation_id)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'tenant runtime role cannot execute the guarded revocation function';
  END IF;

  IF has_table_privilege('tenant_trust_app', 'identity.certificates', 'UPDATE')
     OR has_table_privilege('tenant_trust_app', 'identity.certificate_lifecycle_events', 'INSERT') THEN
    RAISE EXCEPTION 'tenant runtime role received direct revocation table privileges';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'identity.certificate_lifecycle_events'::regclass
      AND conname = 'certificate_lifecycle_events_revocation_shape'
  ) THEN
    RAISE EXCEPTION 'issuer-confirmed revoked event constraint is missing';
  END IF;
END
$verify_revocation_schema$;

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

SELECT * FROM identity.record_certificate_issuance(
  'crt_018f1234-5678-7abc-8def-0123456789a7',
  'evt_018f1234-5678-7abc-8def-0123456789a7',
  'cor_018f1234-5678-7abc-8def-0123456789a7',
  'req_018f1234-5678-7abc-8def-0123456789a7',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1',
  '00000000000000000000000000000037',
  repeat('7', 64), repeat('8', 64), 'ecdsa-p256',
  clock_timestamp() - interval '2 minutes',
  clock_timestamp() + interval '58 minutes',
  clock_timestamp() - interval '1 minute',
  'tenant-alpha:certificate:issue:revoke-admin'
);

SELECT * FROM identity.record_certificate_issuance(
  'crt_018f1234-5678-7abc-8def-0123456789a8',
  'evt_018f1234-5678-7abc-8def-0123456789a8',
  'cor_018f1234-5678-7abc-8def-0123456789a8',
  'req_018f1234-5678-7abc-8def-0123456789a8',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1',
  '00000000000000000000000000000038',
  repeat('9', 64), repeat('a', 64), 'ecdsa-p256',
  clock_timestamp() - interval '2 minutes',
  clock_timestamp() + interval '58 minutes',
  clock_timestamp() - interval '1 minute',
  'tenant-alpha:certificate:issue:revoke-self'
);

SELECT * FROM identity.record_certificate_issuance(
  'crt_018f1234-5678-7abc-8def-0123456789a9',
  'evt_018f1234-5678-7abc-8def-0123456789a9',
  'cor_018f1234-5678-7abc-8def-0123456789a9',
  'req_018f1234-5678-7abc-8def-0123456789a9',
  'sub_018f1234-5678-7abc-8def-0123456789ac',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1',
  '00000000000000000000000000000039',
  repeat('b', 64), repeat('c', 64), 'ecdsa-p256',
  clock_timestamp() - interval '2 minutes',
  clock_timestamp() + interval '58 minutes',
  clock_timestamp() - interval '1 minute',
  'tenant-alpha:certificate:issue:revoke-other'
);

DO $verify_admin_revocation$
DECLARE
  result record;
  changed_at timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO result FROM identity.record_certificate_revocation(
    'evt_018f1234-5678-7abc-8def-0123456789b7',
    'cor_018f1234-5678-7abc-8def-0123456789b7',
    'req_018f1234-5678-7abc-8def-0123456789b7',
    'crt_018f1234-5678-7abc-8def-0123456789a7',
    'KEY_COMPROMISE', changed_at,
    'tenant-alpha:certificate:revoke:admin',
    'step-ca:revocation:admin-0001'
  );

  IF result.recorded_certificate_id <> 'crt_018f1234-5678-7abc-8def-0123456789a7'
     OR result.recorded_event_id <> 'evt_018f1234-5678-7abc-8def-0123456789b7'
     OR result.recorded_correlation_id <> 'cor_018f1234-5678-7abc-8def-0123456789b7'
     OR result.recorded_state <> 'revoked'
     OR result.recorded_version <> 2 THEN
    RAISE EXCEPTION 'administrator revocation did not return its durable transition';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM identity.certificates AS certificate
    JOIN identity.certificate_lifecycle_events AS event
      ON event.tenant_id = certificate.tenant_id
     AND event.event_id = certificate.last_event_id
    WHERE certificate.certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789a7'
      AND certificate.state = 'revoked'
      AND certificate.version = 2
      AND event.event_type = 'revoked'
      AND event.certificate_state = 'revoked'
      AND event.reason_code = 'KEY_COMPROMISE'
      AND event.actor_subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ac'
      AND event.causation_event_id = 'evt_018f1234-5678-7abc-8def-0123456789a7'
      AND event.issuer_confirmation_id = 'step-ca:revocation:admin-0001'
  ) THEN
    RAISE EXCEPTION 'revoked state, reason, actor, causation or issuer confirmation was not persisted';
  END IF;
END
$verify_admin_revocation$;

DO $verify_idempotent_replay$
DECLARE replay record;
BEGIN
  SELECT * INTO replay FROM identity.record_certificate_revocation(
    'evt_018f1234-5678-7abc-8def-0123456789b8',
    'cor_018f1234-5678-7abc-8def-0123456789b8',
    'req_018f1234-5678-7abc-8def-0123456789b7',
    'crt_018f1234-5678-7abc-8def-0123456789a7',
    'KEY_COMPROMISE', clock_timestamp(),
    'tenant-alpha:certificate:revoke:admin',
    'step-ca:revocation:admin-0001'
  );
  IF replay.recorded_event_id <> 'evt_018f1234-5678-7abc-8def-0123456789b7'
     OR replay.recorded_correlation_id <> 'cor_018f1234-5678-7abc-8def-0123456789b7'
     OR replay.recorded_version <> 2
     OR (SELECT count(*) FROM identity.certificate_lifecycle_events
         WHERE certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789a7'
           AND event_type = 'revoked') <> 1 THEN
    RAISE EXCEPTION 'identical revocation replay did not return exactly one durable event';
  END IF;

  BEGIN
    PERFORM identity.record_certificate_revocation(
      'evt_018f1234-5678-7abc-8def-0123456789b9',
      'cor_018f1234-5678-7abc-8def-0123456789b9',
      'req_018f1234-5678-7abc-8def-0123456789b7',
      'crt_018f1234-5678-7abc-8def-0123456789a7',
      'CA_COMPROMISE', clock_timestamp(),
      'tenant-alpha:certificate:revoke:admin',
      'step-ca:revocation:admin-0001'
    );
    RAISE EXCEPTION 'conflicting revocation idempotency reuse succeeded';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;
END
$verify_idempotent_replay$;

DO $verify_future_confirmation_denied$
BEGIN
  BEGIN
    PERFORM identity.record_certificate_revocation(
      'evt_018f1234-5678-7abc-8def-0123456789ba',
      'cor_018f1234-5678-7abc-8def-0123456789ba',
      'req_018f1234-5678-7abc-8def-0123456789ba',
      'crt_018f1234-5678-7abc-8def-0123456789a9',
      'KEY_COMPROMISE', clock_timestamp() + interval '3 seconds',
      'tenant-alpha:certificate:revoke:future',
      'step-ca:revocation:future-0001'
    );
    RAISE EXCEPTION 'future-dated issuer confirmation was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_future_confirmation_denied$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $verify_self_and_other_authorization$
BEGIN
  PERFORM identity.record_certificate_revocation(
    'evt_018f1234-5678-7abc-8def-0123456789c7',
    'cor_018f1234-5678-7abc-8def-0123456789c7',
    'req_018f1234-5678-7abc-8def-0123456789c7',
    'crt_018f1234-5678-7abc-8def-0123456789a8',
    'PRIVILEGE_WITHDRAWN', clock_timestamp(),
    'tenant-alpha:certificate:revoke:self',
    'step-ca:revocation:self-0001'
  );

  IF NOT EXISTS (
    SELECT 1 FROM identity.certificates
    WHERE certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789a8'
      AND state = 'revoked'
  ) THEN
    RAISE EXCEPTION 'certificate owner could not revoke their own certificate';
  END IF;

  BEGIN
    PERFORM identity.record_certificate_revocation(
      'evt_018f1234-5678-7abc-8def-0123456789c8',
      'cor_018f1234-5678-7abc-8def-0123456789c8',
      'req_018f1234-5678-7abc-8def-0123456789c8',
      'crt_018f1234-5678-7abc-8def-0123456789a9',
      'KEY_COMPROMISE', clock_timestamp(),
      'tenant-alpha:certificate:revoke:other',
      'step-ca:revocation:other-0001'
    );
    RAISE EXCEPTION 'ordinary member revoked another subject certificate';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM identity.record_certificate_revocation(
      'evt_018f1234-5678-7abc-8def-0123456789c9',
      'cor_018f1234-5678-7abc-8def-0123456789c9',
      'req_018f1234-5678-7abc-8def-0123456789c9',
      'crt_018f1234-5678-7abc-8def-0123456789a8',
      'KEY_COMPROMISE', clock_timestamp(),
      'tenant-alpha:certificate:revoke:terminal',
      'step-ca:revocation:terminal-0001'
    );
    RAISE EXCEPTION 'already revoked certificate accepted a second transition';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_self_and_other_authorization$;

RESET ROLE;

DO $verify_terminal_state_immutable$
BEGIN
  BEGIN
    UPDATE identity.certificates
    SET state = 'active'
    WHERE certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789a7';
    RAISE EXCEPTION 'revoked certificate returned to active';
  EXCEPTION WHEN check_violation THEN NULL;
  END;

  BEGIN
    UPDATE identity.certificate_lifecycle_events
    SET reason_code = 'CA_COMPROMISE'
    WHERE event_id = 'evt_018f1234-5678-7abc-8def-0123456789b7';
    RAISE EXCEPTION 'revocation event was mutable';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_terminal_state_immutable$;

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ad'
);

DO $verify_foreign_tenant_denied$
BEGIN
  BEGIN
    PERFORM identity.record_certificate_revocation(
      'evt_018f1234-5678-7abc-8def-0123456789d7',
      'cor_018f1234-5678-7abc-8def-0123456789d7',
      'req_018f1234-5678-7abc-8def-0123456789d7',
      'crt_018f1234-5678-7abc-8def-0123456789a7',
      'KEY_COMPROMISE', clock_timestamp(),
      'tenant-beta:certificate:revoke:foreign',
      'step-ca:revocation:foreign-0001'
    );
    RAISE EXCEPTION 'foreign tenant revoked an Alpha certificate';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_foreign_tenant_denied$;

RESET ROLE;
ROLLBACK;

\echo 'PASS certificate revocation is issuer-confirmed, authorized, idempotent and permanently recorded'
