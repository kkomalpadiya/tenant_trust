\set ON_ERROR_STOP on

DO $verify_certificate_inventory_schema$
DECLARE
  secured_table_count integer;
  policy_count integer;
BEGIN
  SELECT count(*) INTO secured_table_count
  FROM pg_class AS relation
  JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
  WHERE (namespace.nspname, relation.relname) IN (
    ('identity', 'certificates'),
    ('identity', 'certificate_lifecycle_events')
  )
    AND relation.relrowsecurity
    AND relation.relforcerowsecurity;

  IF secured_table_count <> 2 THEN
    RAISE EXCEPTION 'expected two forced-RLS certificate inventory tables, found %', secured_table_count;
  END IF;

  SELECT count(*) INTO policy_count
  FROM pg_policies
  WHERE (schemaname, tablename, policyname) IN (
    ('identity', 'certificates', 'certificates_current_actor_select'),
    ('identity', 'certificate_lifecycle_events', 'certificate_lifecycle_events_current_actor_select')
  )
    AND 'tenant_trust_app' = ANY(roles);

  IF policy_count <> 2 THEN
    RAISE EXCEPTION 'expected two actor-aware certificate inventory policies, found %', policy_count;
  END IF;

  IF has_table_privilege('tenant_trust_app', 'identity.certificates', 'INSERT')
     OR has_table_privilege('tenant_trust_app', 'identity.certificates', 'UPDATE')
     OR has_table_privilege('tenant_trust_app', 'identity.certificate_lifecycle_events', 'INSERT')
     OR has_table_privilege('tenant_trust_app', 'identity.certificate_lifecycle_events', 'UPDATE') THEN
    RAISE EXCEPTION 'tenant runtime role received direct certificate mutation privileges';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = 'identity.certificate_lifecycle_events'::regclass
      AND tgname = 'certificate_lifecycle_events_append_only'
      AND NOT tgisinternal
  ) THEN
    RAISE EXCEPTION 'certificate lifecycle append-only trigger is missing';
  END IF;
END
$verify_certificate_inventory_schema$;

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
  'crt_018f1234-5678-7abc-8def-0123456789d0',
  'evt_018f1234-5678-7abc-8def-0123456789e0',
  'cor_018f1234-5678-7abc-8def-0123456789f0',
  'req_018f1234-5678-7abc-8def-0123456789c2',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1',
  '00000000000000000000000000000001',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  'ecdsa-p256',
  TIMESTAMPTZ '2026-09-14 09:59:00+00',
  TIMESTAMPTZ '2026-09-14 10:59:00+00',
  TIMESTAMPTZ '2026-09-14 10:00:00+00',
  'tenant-alpha:certificate:issue:0004'
);

SELECT * FROM identity.record_certificate_issuance(
  'crt_018f1234-5678-7abc-8def-0123456789d1',
  'evt_018f1234-5678-7abc-8def-0123456789e1',
  'cor_018f1234-5678-7abc-8def-0123456789f1',
  'req_018f1234-5678-7abc-8def-0123456789c3',
  'sub_018f1234-5678-7abc-8def-0123456789ac',
  'iss_018f1234-5678-7abc-8def-0123456789b4',
  'tenant-client-auth-v1',
  '00000000000000000000000000000002',
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'ed25519',
  TIMESTAMPTZ '2026-09-14 10:00:00+00',
  TIMESTAMPTZ '2026-09-14 11:00:00+00',
  TIMESTAMPTZ '2026-09-14 10:01:00+00',
  'tenant-alpha:certificate:issue:0005'
);

DO $verify_admin_inventory$
BEGIN
  IF (SELECT count(*) FROM identity.certificates) <> 2
     OR (SELECT count(*) FROM identity.certificate_lifecycle_events) <> 2 THEN
    RAISE EXCEPTION 'tenant administrator did not receive the complete tenant certificate inventory';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM identity.certificates AS certificate
    JOIN identity.certificate_lifecycle_events AS event
      ON event.tenant_id = certificate.tenant_id
     AND event.event_id = certificate.issued_event_id
     AND event.certificate_id = certificate.certificate_id
    WHERE certificate.certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789d0'
      AND certificate.issuer_id = 'iss_018f1234-5678-7abc-8def-0123456789b4'
      AND certificate.subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab'
      AND certificate.serial_number = '00000000000000000000000000000001'
      AND certificate.fingerprint_sha256 = repeat('a', 64)
      AND certificate.public_key_sha256 = repeat('e', 64)
      AND certificate.not_after = TIMESTAMPTZ '2026-09-14 10:59:00+00'
      AND certificate.state = 'active'
      AND event.event_type = 'issued'
      AND event.certificate_state = 'active'
  ) THEN
    RAISE EXCEPTION 'issued inventory metadata or initial lifecycle event is incomplete';
  END IF;

  BEGIN
    INSERT INTO identity.certificates (tenant_id) VALUES ('tnt_018f1234-5678-7abc-8def-0123456789ab');
    RAISE EXCEPTION 'tenant runtime role inserted certificate rows directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM identity.record_certificate_issuance(
      'crt_018f1234-5678-7abc-8def-0123456789d2',
      'evt_018f1234-5678-7abc-8def-0123456789e2',
      'cor_018f1234-5678-7abc-8def-0123456789f2',
      'req_018f1234-5678-7abc-8def-0123456789c4',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b5',
      'tenant-client-auth-v1',
      '00000000000000000000000000000003',
      repeat('c', 64), repeat('1', 64), 'ecdsa-p256',
      TIMESTAMPTZ '2026-09-14 10:00:00+00',
      TIMESTAMPTZ '2026-09-14 11:00:00+00',
      TIMESTAMPTZ '2026-09-14 10:01:00+00',
      'tenant-alpha:certificate:issue:0006'
    );
    RAISE EXCEPTION 'Alpha actor recorded a certificate against the Beta issuer';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM identity.record_certificate_issuance(
      'crt_018f1234-5678-7abc-8def-0123456789d2',
      'evt_018f1234-5678-7abc-8def-0123456789e2',
      'cor_018f1234-5678-7abc-8def-0123456789f2',
      'req_018f1234-5678-7abc-8def-0123456789c4',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1',
      '00000000000000000000000000000001',
      repeat('c', 64), repeat('1', 64), 'ecdsa-p256',
      TIMESTAMPTZ '2026-09-14 10:00:00+00',
      TIMESTAMPTZ '2026-09-14 11:00:00+00',
      TIMESTAMPTZ '2026-09-14 10:01:00+00',
      'tenant-alpha:certificate:issue:0006'
    );
    RAISE EXCEPTION 'duplicate issuer serial was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;

  BEGIN
    PERFORM identity.record_certificate_issuance(
      'crt_018f1234-5678-7abc-8def-0123456789d2',
      'evt_018f1234-5678-7abc-8def-0123456789e2',
      'cor_018f1234-5678-7abc-8def-0123456789f2',
      'req_018f1234-5678-7abc-8def-0123456789c4',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1',
      '00000000000000000000000000000003',
      repeat('c', 64), repeat('1', 64), 'ecdsa-p256',
      TIMESTAMPTZ '2026-09-14 10:00:00+00',
      TIMESTAMPTZ '2026-09-14 11:00:00+00',
      TIMESTAMPTZ '2026-09-14 10:01:00+00',
      'tenant-alpha:certificate:issue:0004'
    );
    RAISE EXCEPTION 'conflicting certificate idempotency key was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
END
$verify_admin_inventory$;

DO $verify_idempotent_replay$
DECLARE
  replay record;
BEGIN
  SELECT * INTO replay FROM identity.record_certificate_issuance(
    'crt_018f1234-5678-7abc-8def-0123456789d3',
    'evt_018f1234-5678-7abc-8def-0123456789e3',
    'cor_018f1234-5678-7abc-8def-0123456789f3',
    'req_018f1234-5678-7abc-8def-0123456789c2',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1',
    '00000000000000000000000000000001',
    repeat('a', 64), repeat('e', 64), 'ecdsa-p256',
    TIMESTAMPTZ '2026-09-14 09:59:00+00',
    TIMESTAMPTZ '2026-09-14 10:59:00+00',
    TIMESTAMPTZ '2026-09-14 10:00:00+00',
    'tenant-alpha:certificate:issue:0004'
  );

  IF replay.recorded_certificate_id <> 'crt_018f1234-5678-7abc-8def-0123456789d0'
     OR replay.recorded_event_id <> 'evt_018f1234-5678-7abc-8def-0123456789e0'
     OR replay.recorded_state <> 'active' THEN
    RAISE EXCEPTION 'identical issuance replay did not return the durable inventory identity';
  END IF;
END
$verify_idempotent_replay$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $verify_member_inventory$
BEGIN
  IF (SELECT count(*) FROM identity.certificates) <> 1
     OR (SELECT count(*) FROM identity.certificate_lifecycle_events) <> 1
     OR NOT EXISTS (
       SELECT 1 FROM identity.certificates
       WHERE subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab'
     ) THEN
    RAISE EXCEPTION 'ordinary member did not receive only their own certificate history';
  END IF;

  BEGIN
    PERFORM identity.record_certificate_issuance(
      'crt_018f1234-5678-7abc-8def-0123456789d4',
      'evt_018f1234-5678-7abc-8def-0123456789e4',
      'cor_018f1234-5678-7abc-8def-0123456789f4',
      'req_018f1234-5678-7abc-8def-0123456789c4',
      'sub_018f1234-5678-7abc-8def-0123456789ac',
      'iss_018f1234-5678-7abc-8def-0123456789b4',
      'tenant-client-auth-v1',
      '00000000000000000000000000000004',
      repeat('d', 64), repeat('2', 64), 'ecdsa-p256',
      TIMESTAMPTZ '2026-09-14 10:00:00+00',
      TIMESTAMPTZ '2026-09-14 11:00:00+00',
      TIMESTAMPTZ '2026-09-14 10:01:00+00',
      'tenant-alpha:certificate:issue:0007'
    );
    RAISE EXCEPTION 'ordinary member recorded a certificate for another subject';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_member_inventory$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ad'
);

DO $verify_foreign_inventory_hidden$
BEGIN
  IF (SELECT count(*) FROM identity.certificates) <> 0
     OR (SELECT count(*) FROM identity.certificate_lifecycle_events) <> 0 THEN
    RAISE EXCEPTION 'Alpha certificate inventory leaked into the Beta tenant context';
  END IF;
END
$verify_foreign_inventory_hidden$;

RESET ROLE;

DO $verify_append_only_event$
BEGIN
  BEGIN
    UPDATE identity.certificate_lifecycle_events
    SET recorded_at = recorded_at
    WHERE event_id = 'evt_018f1234-5678-7abc-8def-0123456789e0';
    RAISE EXCEPTION 'certificate lifecycle event was mutable';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_append_only_event$;

ROLLBACK;

\echo 'PASS certificate inventory is durable, append-only, idempotent and tenant/actor scoped'
