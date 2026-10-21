\set ON_ERROR_STOP on

DO $verify_audit_outbox_privileges$
BEGIN
  IF has_table_privilege('tenant_trust_app', 'audit.fabric_commitment_outbox', 'SELECT')
     OR has_table_privilege('tenant_trust_audit_outbox_worker', 'audit.fabric_commitment_outbox', 'SELECT') THEN
    RAISE EXCEPTION 'audit outbox roles received direct table access';
  END IF;
  IF NOT has_function_privilege(
    'tenant_trust_app',
    'audit.enqueue_fabric_commitment(identity.tenant_id, identity.event_id, text, text, text, jsonb, text, text, identity.sha256_digest, identity.sha256_digest, jsonb, timestamptz)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'tenant_trust_audit_outbox_worker',
    'audit.claim_fabric_commitment(text, audit.audit_outbox_claim_token, timestamptz)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'audit outbox roles lack their constrained functions';
  END IF;
END
$verify_audit_outbox_privileges$;

BEGIN;

INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name)
VALUES ('tnt_018f1234-5678-7abc-8def-0123456789f1', 'audit-outbox-verifier', 'Audit Outbox Verifier');

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_context('tnt_018f1234-5678-7abc-8def-0123456789f1');

DO $enqueue_and_replay$
DECLARE first_enqueue record;
DECLARE replay record;
DECLARE conflict_blocked boolean := false;
BEGIN
  SELECT * INTO first_enqueue FROM audit.enqueue_fabric_commitment(
    'tnt_018f1234-5678-7abc-8def-0123456789f1',
    'evt_018f1234-5678-7abc-8def-0123456789f2',
    'tt-audit-verifier-v1',
    'trust.updated.v1',
    'trust-transition',
    '{"tenantId":"tnt_018f1234-5678-7abc-8def-0123456789f1","eventId":"evt_018f1234-5678-7abc-8def-0123456789f2","eventType":"trust.updated.v1"}'::jsonb,
    '{"canonical":"off-chain-preimage"}',
    'audit~trust-transition~aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    repeat('a', 64),
    repeat('b', 64),
    '{"canonicalizationProfile":"tenant-trust-audit-commitment-json-v1","commitmentHashSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","digestAlgorithm":"sha256","eventKeyHashSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recordType":"trust-transition","schemaVersion":"1.0.0"}'::jsonb,
    clock_timestamp()
  );
  IF first_enqueue.status <> 'pending' THEN RAISE EXCEPTION 'first enqueue was not pending'; END IF;

  SELECT * INTO replay FROM audit.enqueue_fabric_commitment(
    'tnt_018f1234-5678-7abc-8def-0123456789f1',
    'evt_018f1234-5678-7abc-8def-0123456789f2',
    'tt-audit-verifier-v1',
    'trust.updated.v1',
    'trust-transition',
    '{"eventType":"trust.updated.v1","eventId":"evt_018f1234-5678-7abc-8def-0123456789f2","tenantId":"tnt_018f1234-5678-7abc-8def-0123456789f1"}'::jsonb,
    '{"canonical":"off-chain-preimage"}',
    'audit~trust-transition~aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    repeat('a', 64),
    repeat('b', 64),
    '{"schemaVersion":"1.0.0","recordType":"trust-transition","eventKeyHashSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","digestAlgorithm":"sha256","commitmentHashSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","canonicalizationProfile":"tenant-trust-audit-commitment-json-v1"}'::jsonb,
    clock_timestamp()
  );
  IF replay.event_id <> first_enqueue.event_id THEN RAISE EXCEPTION 'idempotent replay changed identity'; END IF;

  BEGIN
    PERFORM audit.enqueue_fabric_commitment(
      'tnt_018f1234-5678-7abc-8def-0123456789f1',
      'evt_018f1234-5678-7abc-8def-0123456789f2',
      'tt-audit-verifier-v1',
      'trust.updated.v1',
      'trust-transition',
      '{"tenantId":"tnt_018f1234-5678-7abc-8def-0123456789f1","eventId":"evt_018f1234-5678-7abc-8def-0123456789f2","eventType":"trust.updated.v1","tampered":true}'::jsonb,
      '{"canonical":"off-chain-preimage"}',
      'audit~trust-transition~aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      repeat('a', 64), repeat('b', 64),
      '{"canonicalizationProfile":"tenant-trust-audit-commitment-json-v1","commitmentHashSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","digestAlgorithm":"sha256","eventKeyHashSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recordType":"trust-transition","schemaVersion":"1.0.0"}'::jsonb,
      clock_timestamp()
    );
  EXCEPTION WHEN unique_violation THEN
    conflict_blocked := true;
  END;
  IF NOT conflict_blocked THEN RAISE EXCEPTION 'conflicting duplicate was accepted'; END IF;
END
$enqueue_and_replay$;

SELECT set_config('tenant_trust.tenant_id', '', true);
RESET ROLE;
SET LOCAL ROLE tenant_trust_audit_outbox_worker;

DO $claim_and_retry$
DECLARE claimed record;
DECLARE failed record;
BEGIN
  SELECT * INTO claimed FROM audit.claim_fabric_commitment(
    'audit-worker.verify-1',
    'clm_018f1234-5678-7abc-8def-0123456789f3',
    clock_timestamp()
  );
  IF claimed.event_id <> 'evt_018f1234-5678-7abc-8def-0123456789f2'
     OR claimed.attempt_count <> 1 THEN
    RAISE EXCEPTION 'first claim was invalid';
  END IF;
  SELECT * INTO failed FROM audit.mark_fabric_commitment_failed(
    claimed.tenant_id, claimed.event_id, claimed.claim_token,
    'SUBMISSION_FAILED', clock_timestamp(), 1
  );
  IF failed.status <> 'pending' THEN RAISE EXCEPTION 'failed claim did not return to pending'; END IF;
END
$claim_and_retry$;

SELECT pg_sleep(1.1);

DO $retry_and_submit$
DECLARE claimed record;
DECLARE submitted record;
BEGIN
  SELECT * INTO claimed FROM audit.claim_fabric_commitment(
    'audit-worker.verify-1',
    'clm_018f1234-5678-7abc-8def-0123456789f4',
    clock_timestamp()
  );
  IF claimed.attempt_count <> 2 THEN RAISE EXCEPTION 'retry did not increment attempt count'; END IF;
  SELECT * INTO submitted FROM audit.mark_fabric_commitment_submitted(
    claimed.tenant_id, claimed.event_id, claimed.claim_token, claimed.ledger_key,
    'duplicate', clock_timestamp()
  );
  IF submitted.status <> 'submitted' OR submitted.submission_status <> 'duplicate' THEN
    RAISE EXCEPTION 'idempotent duplicate did not complete delivery';
  END IF;
END
$retry_and_submit$;

RESET ROLE;

DO $verify_final_state$
DECLARE stored audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  SELECT * INTO stored FROM audit.fabric_commitment_outbox
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f1'
    AND event_id = 'evt_018f1234-5678-7abc-8def-0123456789f2';
  IF stored.status <> 'submitted'
     OR stored.submission_status <> 'duplicate'
     OR stored.attempt_count <> 2
     OR stored.last_failure_code IS NOT NULL THEN
    RAISE EXCEPTION 'final durable outbox state is invalid';
  END IF;
  IF stored.ledger_value ? 'tenantId'
     OR stored.ledger_value ? 'subjectId'
     OR (SELECT count(*) FROM jsonb_object_keys(stored.ledger_value)) <> 6 THEN
    RAISE EXCEPTION 'public ledger value leaked an off-chain field';
  END IF;
END
$verify_final_state$;

ROLLBACK;
