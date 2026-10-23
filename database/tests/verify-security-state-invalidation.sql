\set ON_ERROR_STOP on

BEGIN;

DO $fixture$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_tenant identity.tenant_id := 'tnt_018f1234-5678-7abc-8def-0123456789d1';
  v_subject identity.subject_id := 'sub_018f1234-5678-7abc-8def-0123456789d1';
  v_certificate identity.certificate_id := 'crt_018f1234-5678-7abc-8def-0123456789d1';
  v_action audit.security_action_id := 'act_018f1234-5678-7abc-8def-0123456789d1';
BEGIN
  INSERT INTO identity.tenants (
    tenant_id, tenant_slug, display_name, created_at, updated_at
  ) VALUES (v_tenant, 'invalidation-verifier', 'Invalidation Verifier', v_now, v_now);
  INSERT INTO identity.subjects (
    subject_id, identity_provider, provider_subject, display_name, created_at, updated_at
  ) VALUES (
    v_subject, 'verification', 'invalidation-verifier',
    'Invalidation Verifier', v_now, v_now
  );
  INSERT INTO identity.tenant_memberships (
    tenant_id, subject_id, created_at, updated_at
  ) VALUES (v_tenant, v_subject, v_now, v_now);
  INSERT INTO identity.tenant_issuer_mappings (
    tenant_id, issuer_id, issuer_name, authority_url, state,
    root_certificate_sha256, created_at, updated_at
  ) VALUES (
    v_tenant, 'iss_018f1234-5678-7abc-8def-0123456789d1',
    'invalidation-verifier', 'https://ca.invalidation.invalid', 'active',
    repeat('1', 64), v_now, v_now
  );
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after, issued_at,
    state_changed_at, requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version, created_at, updated_at
  ) VALUES (
    v_tenant, v_certificate, v_subject,
    'iss_018f1234-5678-7abc-8def-0123456789d1',
    'tenant-client-auth-v1', 'D1000000000000000000000000000001',
    repeat('2', 64), 'ed25519', 'active', v_now - interval '1 hour',
    v_now + interval '1 hour', v_now - interval '30 minutes',
    v_now - interval '30 minutes', v_subject,
    'req_018f1234-5678-7abc-8def-0123456789d1',
    'security-invalidation-verifier',
    'evt_018f1234-5678-7abc-8def-0123456789d1',
    'evt_018f1234-5678-7abc-8def-0123456789d1',
    'cor_018f1234-5678-7abc-8def-0123456789d1', 1, v_now, v_now
  );
  INSERT INTO orchestration.subject_security_states (
    tenant_id, subject_id, certificate_id
  ) VALUES (v_tenant, v_subject, v_certificate);
  INSERT INTO orchestration.security_actions (
    tenant_id, action_id, decision_id, correlation_id, target_subject_id,
    target_certificate_id, action_type, authority_class, reason_code,
    trigger_context_hash_sha256, attempt_count, expected_state_version,
    next_attempt_at, requested_at
  ) VALUES (
    v_tenant, v_action, 'dec_018f1234-5678-7abc-8def-0123456789d1',
    'cor_018f1234-5678-7abc-8def-0123456789d2', v_subject, v_certificate,
    'suspend-subject', 'policy-quarantine', 'TRUST_SCORE_QUARANTINE',
    repeat('3', 64), 1, 1, v_now, v_now
  );

  UPDATE orchestration.subject_security_states SET
    access_state = 'suspended', renewal_state = 'blocked',
    state_version = 2, last_action_id = v_action, updated_at = v_now
  WHERE tenant_id = v_tenant AND subject_id = v_subject
    AND certificate_id = v_certificate;
  INSERT INTO orchestration.security_action_attempts (
    tenant_id, action_id, attempt_number, claim_token, worker_id,
    status, started_at, completed_at
  ) VALUES (
    v_tenant, v_action, 1,
    'clm_018f1234-5678-7abc-8def-0123456789d6', 'invalidation.fixture',
    'succeeded', v_now, v_now
  );
  UPDATE orchestration.security_actions SET
    status = 'succeeded', result_state = jsonb_build_object(
      'access', 'suspended', 'renewal', 'blocked',
      'targetCertificate', 'active', 'replacement', 'not-required'
    ), succeeded_at = v_now, updated_at = v_now
  WHERE tenant_id = v_tenant AND action_id = v_action;

  IF NOT EXISTS (
    SELECT 1 FROM orchestration.security_state_invalidations
    WHERE tenant_id = v_tenant AND action_id = v_action
      AND subject_id = v_subject AND certificate_id = v_certificate
      AND action_type = 'suspend-subject' AND security_state_version = 2
      AND status = 'pending' AND action_succeeded_at = v_now
  ) THEN
    RAISE EXCEPTION 'successful suspension did not atomically queue invalidation';
  END IF;

  UPDATE orchestration.security_actions SET status = status
  WHERE tenant_id = v_tenant AND action_id = v_action;
  IF (SELECT count(*) FROM orchestration.security_state_invalidations
      WHERE tenant_id = v_tenant AND action_id = v_action) <> 1 THEN
    RAISE EXCEPTION 'action replay queued duplicate invalidation';
  END IF;
END
$fixture$;

DO $privileges$
BEGIN
  IF has_table_privilege(
       'tenant_trust_security_invalidation_worker',
       'orchestration.security_state_invalidations', 'SELECT'
     )
     OR has_table_privilege(
       'tenant_trust_app', 'orchestration.security_state_invalidations', 'SELECT'
     )
     OR NOT has_function_privilege(
       'tenant_trust_security_invalidation_worker',
       'orchestration.claim_security_state_invalidation(text,text,timestamptz)',
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'security-state invalidation privileges are not function-only';
  END IF;
END
$privileges$;

-- Keep any unrelated local pending work outside this deterministic claim.
UPDATE orchestration.security_state_invalidations
SET next_attempt_at = clock_timestamp() + interval '1 day'
WHERE action_id <> 'act_018f1234-5678-7abc-8def-0123456789d1'
  AND status IN ('pending', 'failed');

SET LOCAL ROLE tenant_trust_security_invalidation_worker;

DO $first_attempt$
DECLARE v_claim record; v_status record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_state_invalidation(
    'invalidation.verify-1',
    'icl_018f1234-5678-7abc-8def-0123456789d2',
    clock_timestamp()
  );
  IF v_claim.action_id <> 'act_018f1234-5678-7abc-8def-0123456789d1'
     OR v_claim.action_type <> 'suspend-subject'
     OR v_claim.attempt_count <> 1 THEN
    RAISE EXCEPTION 'invalidation claim lost its action or target scope';
  END IF;

  BEGIN
    PERFORM orchestration.complete_security_state_invalidation(
      v_claim.tenant_id, v_claim.action_id,
      'icl_018f1234-5678-7abc-8def-0123456789d3',
      2, 3, v_claim.action_succeeded_at + interval '1 second',
      v_claim.action_succeeded_at + interval '1.1 seconds'
    );
    RAISE EXCEPTION 'wrong invalidation claim token completed work';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM <> 'SECURITY_INVALIDATION_CLAIM_CONFLICT' THEN RAISE; END IF;
  END;

  SELECT * INTO v_status FROM orchestration.fail_security_state_invalidation(
    v_claim.tenant_id, v_claim.action_id, v_claim.claim_token,
    'REDIS_TEMPORARILY_UNAVAILABLE', clock_timestamp(), 1
  );
  IF v_status.status <> 'failed' OR v_status.attempt_count <> 1 THEN
    RAISE EXCEPTION 'invalidation failure was not visible for retry';
  END IF;
END
$first_attempt$;

RESET ROLE;
UPDATE orchestration.security_state_invalidations SET next_attempt_at = clock_timestamp()
WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789d1';
SET LOCAL ROLE tenant_trust_security_invalidation_worker;

DO $retry_and_measure$
DECLARE v_claim record; v_status record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_state_invalidation(
    'invalidation.verify-2',
    'icl_018f1234-5678-7abc-8def-0123456789d4',
    clock_timestamp()
  );
  SELECT * INTO v_status FROM orchestration.complete_security_state_invalidation(
    v_claim.tenant_id, v_claim.action_id, v_claim.claim_token,
    2, 3, v_claim.action_succeeded_at + interval '1 second',
    v_claim.action_succeeded_at + interval '1.1 seconds'
  );
  IF v_status.status <> 'completed' OR v_status.attempt_count <> 2
     OR v_status.enforcement_delay_ms <> 1000 OR v_status.within_target <> true THEN
    RAISE EXCEPTION 'invalidation delay or terminal state was not recorded correctly';
  END IF;
END
$retry_and_measure$;

RESET ROLE;

DO $history$
BEGIN
  IF (SELECT count(*) FROM orchestration.security_state_invalidation_attempts
      WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789d1') <> 2
     OR (SELECT count(*) FROM orchestration.security_state_invalidation_attempts
         WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789d1'
           AND status = 'failed') <> 1
     OR NOT EXISTS (
       SELECT 1 FROM orchestration.security_state_invalidations
       WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789d1'
         AND status = 'completed' AND sessions_invalidated = 2
         AND cache_entries_invalidated = 3 AND enforcement_delay_ms = 1000
         AND within_target = true
     ) THEN
    RAISE EXCEPTION 'invalidation attempt history or measured result is incomplete';
  END IF;
END
$history$;

ROLLBACK;
\echo 'Verified atomic invalidation enqueue, leased retry, least privilege and measured five-second target.'
