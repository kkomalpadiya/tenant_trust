\set ON_ERROR_STOP on

BEGIN;

DO $fixture$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  INSERT INTO identity.tenants (
    tenant_id, tenant_slug, display_name, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f9',
    'action-operations-verifier', 'Action Operations Verifier', v_now, v_now
  );
  INSERT INTO identity.subjects (
    subject_id, identity_provider, provider_subject, display_name,
    created_at, updated_at
  ) VALUES (
    'sub_018f1234-5678-7abc-8def-0123456789f9',
    'verification', 'action-operations-verifier',
    'Action Operations Verifier', v_now, v_now
  );
  INSERT INTO identity.tenant_memberships (
    tenant_id, subject_id, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f9',
    'sub_018f1234-5678-7abc-8def-0123456789f9', v_now, v_now
  );
  INSERT INTO identity.tenant_role_assignments (
    tenant_id, subject_id, role_name
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f9',
    'sub_018f1234-5678-7abc-8def-0123456789f9', 'tenant-member'
  );
  INSERT INTO identity.tenant_issuer_mappings (
    tenant_id, issuer_id, issuer_name, authority_url, state,
    root_certificate_sha256, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f9',
    'iss_018f1234-5678-7abc-8def-0123456789f9',
    'action-operations-verifier', 'https://ca.operations.invalid', 'active',
    repeat('1', 64), v_now, v_now
  );
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id,
    serial_number, fingerprint_sha256, public_key_algorithm, state,
    not_before, not_after, issued_at, state_changed_at,
    requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version,
    created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f9',
    'crt_018f1234-5678-7abc-8def-0123456789f9',
    'sub_018f1234-5678-7abc-8def-0123456789f9',
    'iss_018f1234-5678-7abc-8def-0123456789f9',
    'tenant-client-auth-v1', '99000000000000000000000000000001',
    repeat('2', 64), 'ed25519', 'active', v_now - interval '1 hour',
    v_now + interval '1 hour', v_now - interval '30 minutes',
    v_now - interval '30 minutes',
    'sub_018f1234-5678-7abc-8def-0123456789f9',
    'req_018f1234-5678-7abc-8def-0123456789f9',
    'action-operations-verifier-certificate',
    'evt_018f1234-5678-7abc-8def-0123456789f9',
    'evt_018f1234-5678-7abc-8def-0123456789f9',
    'cor_018f1234-5678-7abc-8def-0123456789f9', 1, v_now, v_now
  );

  INSERT INTO orchestration.subject_security_states (
    tenant_id, subject_id, certificate_id
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f9',
    'sub_018f1234-5678-7abc-8def-0123456789f9',
    'crt_018f1234-5678-7abc-8def-0123456789f9'
  );

  INSERT INTO orchestration.security_actions (
    tenant_id, action_id, decision_id, correlation_id,
    target_subject_id, target_certificate_id, action_type,
    authority_class, reason_code, trigger_context_hash_sha256,
    status, attempt_count, expected_state_version, claimed_by,
    claim_token, claimed_at, lease_expires_at, next_attempt_at,
    requested_at, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f9',
    'act_018f1234-5678-7abc-8def-0123456789f9',
    'dec_018f1234-5678-7abc-8def-0123456789f9',
    'cor_018f1234-5678-7abc-8def-0123456789f9',
    'sub_018f1234-5678-7abc-8def-0123456789f9',
    'crt_018f1234-5678-7abc-8def-0123456789f9',
    'restrict-access', 'policy-quarantine', 'TRUST_SCORE_QUARANTINE',
    repeat('a', 64), 'executing', 1, 1, 'orchestrator.crashed-1',
    'clm_018f1234-5678-7abc-8def-0123456789f9',
    v_now - interval '6 minutes', v_now - interval '1 minute',
    v_now - interval '10 minutes', v_now - interval '10 minutes',
    v_now - interval '10 minutes', v_now - interval '6 minutes'
  );
  INSERT INTO orchestration.security_action_attempts (
    tenant_id, action_id, attempt_number, claim_token, worker_id,
    status, started_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f9',
    'act_018f1234-5678-7abc-8def-0123456789f9', 1,
    'clm_018f1234-5678-7abc-8def-0123456789f9',
    'orchestrator.crashed-1', 'executing', v_now - interval '6 minutes'
  );
END
$fixture$;

DO $least_privilege$
BEGIN
  IF has_table_privilege(
       'tenant_trust_security_action_operator',
       'orchestration.security_actions', 'SELECT'
     )
     OR has_table_privilege(
       'tenant_trust_security_action_operator',
       'audit.fabric_commitment_outbox', 'SELECT'
     )
     OR NOT has_function_privilege(
       'tenant_trust_security_action_operator',
       'orchestration.recover_expired_security_action_leases(text,timestamptz)',
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'tenant_trust_security_action_operator',
       'orchestration.list_security_action_operational_issues(integer,timestamptz)',
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'security-action operator privileges are not function-only';
  END IF;
END
$least_privilege$;

SET LOCAL ROLE tenant_trust_security_action_operator;

DO $stuck_visible_and_recovered$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_issue record;
  v_recovery record;
BEGIN
  SELECT * INTO v_issue
  FROM orchestration.list_security_action_operational_issues(500, v_now)
  WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789f9'
    AND issue_code = 'ACTION_LEASE_STUCK';
  IF NOT FOUND OR v_issue.severity <> 'critical'
     OR v_issue.action_status <> 'executing' THEN
    RAISE EXCEPTION 'expired action lease was not reported as critical';
  END IF;

  SELECT * INTO v_recovery
  FROM orchestration.recover_expired_security_action_leases(
    'orchestrator.restart-1', v_now
  );
  IF v_recovery.recovered_count <> 1
     OR v_recovery.earliest_retry_at IS DISTINCT FROM v_now THEN
    RAISE EXCEPTION 'startup recovery did not return the expired lease to retry';
  END IF;

  SELECT * INTO v_recovery
  FROM orchestration.recover_expired_security_action_leases(
    'orchestrator.restart-1', v_now
  );
  IF v_recovery.recovered_count <> 0
     OR v_recovery.earliest_retry_at IS NOT NULL THEN
    RAISE EXCEPTION 'startup recovery was not idempotent';
  END IF;
END
$stuck_visible_and_recovered$;

RESET ROLE;

DO $recovery_preserves_state$
DECLARE
  v_action orchestration.security_actions%ROWTYPE;
  v_attempt orchestration.security_action_attempts%ROWTYPE;
  v_state orchestration.subject_security_states%ROWTYPE;
BEGIN
  SELECT * INTO v_action FROM orchestration.security_actions
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f9'
    AND action_id = 'act_018f1234-5678-7abc-8def-0123456789f9';
  SELECT * INTO v_attempt FROM orchestration.security_action_attempts
  WHERE tenant_id = v_action.tenant_id AND action_id = v_action.action_id
    AND attempt_number = 1;
  SELECT * INTO v_state FROM orchestration.subject_security_states
  WHERE tenant_id = v_action.tenant_id
    AND subject_id = v_action.target_subject_id
    AND certificate_id = v_action.target_certificate_id;

  IF v_action.status <> 'failed' OR v_action.attempt_count <> 1
     OR v_action.expected_state_version <> 1
     OR v_action.last_failure_code <> 'ACTION_LEASE_EXPIRED'
     OR v_attempt.status <> 'failed'
     OR v_attempt.failure_code <> 'ACTION_LEASE_EXPIRED'
     OR v_state.access_state <> 'normal' OR v_state.state_version <> 1 THEN
    RAISE EXCEPTION 'restart recovery lost action history or changed security state';
  END IF;
END
$recovery_preserves_state$;

-- Keep pre-existing local work out of this transaction's deterministic claim order.
UPDATE orchestration.security_actions SET next_attempt_at = clock_timestamp() + interval '1 day'
WHERE action_id <> 'act_018f1234-5678-7abc-8def-0123456789f9'
  AND status IN ('pending', 'failed');

SET LOCAL ROLE tenant_trust_security_action_worker;

DO $retry_succeeds$
DECLARE v_claim record; v_result record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_action(
    'orchestrator.restart-1',
    'clm_018f1234-5678-7abc-8def-0123456789fa',
    clock_timestamp()
  );
  IF v_claim.action_id <> 'act_018f1234-5678-7abc-8def-0123456789f9'
     OR v_claim.attempt_count <> 2 THEN
    RAISE EXCEPTION 'restart did not resume the stable action as the next attempt';
  END IF;

  SELECT * INTO v_result FROM orchestration.mark_security_action_succeeded(
    v_claim.tenant_id, v_claim.action_id, v_claim.claim_token,
    '{"access":"restricted","renewal":"allowed","targetCertificate":"active","replacement":"not-required"}'::jsonb,
    NULL, clock_timestamp()
  );
  IF v_result.status <> 'succeeded' OR v_result.attempt_count <> 2 THEN
    RAISE EXCEPTION 'resumed action did not complete under its stable identity';
  END IF;
END
$retry_succeeds$;

RESET ROLE;

SET LOCAL ROLE tenant_trust_security_action_operator;

DO $unprojected_audit_visible$
DECLARE v_count integer;
BEGIN
  SELECT count(*) INTO v_count
  FROM orchestration.list_security_action_operational_issues(500, clock_timestamp())
  WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789f9'
    AND issue_code = 'ACTION_AUDIT_UNPROJECTED';
  IF v_count <> 3 THEN
    RAISE EXCEPTION 'expected requested, failed and succeeded audit gaps, got %', v_count;
  END IF;
END
$unprojected_audit_visible$;

RESET ROLE;

DO $audit_delivery_fixture$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  INSERT INTO audit.fabric_commitment_outbox (
    tenant_id, event_id, channel_name, event_type, record_type,
    event_document, canonical_preimage_json, ledger_key,
    event_key_hash_sha256, commitment_hash_sha256, ledger_value,
    status, attempt_count, next_attempt_at, transaction_id,
    submission_status, submitted_at, validation_code, block_number,
    confirmation_source, committed_at, created_at, updated_at
  )
  SELECT source.tenant_id, source.event_id, 'tt-audit-operations-v1',
    source.event_type, 'security-action',
    jsonb_build_object(
      'tenantId', source.tenant_id::text,
      'eventId', source.event_id::text,
      'eventType', source.event_type
    ), '{}',
    'audit~security-action~' || encode(public.digest(source.event_id::text, 'sha256'), 'hex'),
    encode(public.digest(source.event_id::text, 'sha256'), 'hex'),
    encode(public.digest('commit:' || source.event_id::text, 'sha256'), 'hex'),
    jsonb_build_object(
      'canonicalizationProfile', 'tenant-trust-audit-commitment-json-v1',
      'commitmentHashSha256', encode(public.digest('commit:' || source.event_id::text, 'sha256'), 'hex'),
      'digestAlgorithm', 'sha256',
      'eventKeyHashSha256', encode(public.digest(source.event_id::text, 'sha256'), 'hex'),
      'recordType', 'security-action', 'schemaVersion', '1.0.0'
    ),
    'committed', 1, v_now,
    encode(public.digest('tx:' || source.event_id::text, 'sha256'), 'hex'),
    'created', v_now, 0, 1, 'qscc', v_now, v_now, v_now
  FROM audit.security_action_audit_events AS source
  WHERE source.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f9'
    AND source.action_id = 'act_018f1234-5678-7abc-8def-0123456789f9';

  UPDATE audit.fabric_commitment_outbox AS outbox SET
    status = 'failed', transaction_id = NULL, submission_status = NULL,
    submitted_at = NULL, validation_code = NULL, block_number = NULL,
    confirmation_source = NULL, committed_at = NULL, failed_at = v_now,
    last_failure_code = 'FABRIC_UNAVAILABLE',
    next_attempt_at = v_now + interval '30 seconds', updated_at = v_now
  FROM audit.security_action_audit_events AS source
  WHERE source.tenant_id = outbox.tenant_id AND source.event_id = outbox.event_id
    AND source.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f9'
    AND source.action_id = 'act_018f1234-5678-7abc-8def-0123456789f9'
    AND source.event_status = 'requested';
END
$audit_delivery_fixture$;

SET LOCAL ROLE tenant_trust_security_action_operator;

DO $failed_audit_blocks_health$
DECLARE v_issue record;
BEGIN
  SELECT * INTO v_issue
  FROM orchestration.list_security_action_operational_issues(500, clock_timestamp())
  WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789f9'
    AND issue_code = 'ACTION_AUDIT_DELIVERY_FAILED';
  IF NOT FOUND OR v_issue.severity <> 'critical'
     OR v_issue.action_status <> 'succeeded'
     OR v_issue.audit_delivery_status <> 'failed'
     OR NOT v_issue.retryable THEN
    RAISE EXCEPTION 'failed Fabric delivery did not keep succeeded action unhealthy';
  END IF;
END
$failed_audit_blocks_health$;

RESET ROLE;

DO $audit_reconciled$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  UPDATE audit.fabric_commitment_outbox AS outbox SET
    status = 'committed',
    transaction_id = encode(public.digest('tx:' || outbox.event_id::text, 'sha256'), 'hex'),
    submission_status = 'created', submitted_at = v_now,
    validation_code = 0, block_number = 2, confirmation_source = 'qscc',
    committed_at = v_now, failed_at = NULL, last_failure_code = NULL,
    next_attempt_at = v_now, updated_at = v_now
  WHERE outbox.tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f9'
    AND outbox.status = 'failed';
END
$audit_reconciled$;

SET LOCAL ROLE tenant_trust_security_action_operator;

DO $healthy_after_audit_commit$
BEGIN
  IF EXISTS (
    SELECT 1 FROM orchestration.list_security_action_operational_issues(
      500, clock_timestamp()
    ) WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789f9'
  ) THEN
    RAISE EXCEPTION 'fully executed and committed action still reports an issue';
  END IF;
END
$healthy_after_audit_commit$;

RESET ROLE;
ROLLBACK;

\echo 'Verified stuck-action visibility, idempotent restart recovery, stable retry identity and audit-delivery-gated health.'
