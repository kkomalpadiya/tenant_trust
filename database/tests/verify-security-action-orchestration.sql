\set ON_ERROR_STOP on

BEGIN;

DO $identity_fixture$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name, created_at, updated_at)
  VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'orchestration-verifier', 'Orchestration Verifier', v_now, v_now
  );
  INSERT INTO identity.subjects (
    subject_id, identity_provider, provider_subject, display_name, created_at, updated_at
  ) VALUES (
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'verification', 'orchestration-verifier', 'Orchestration Verifier', v_now, v_now
  );
  INSERT INTO identity.tenant_memberships (
    tenant_id, subject_id, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'sub_018f1234-5678-7abc-8def-0123456789f0', v_now, v_now
  );
  INSERT INTO identity.tenant_role_assignments (tenant_id, subject_id, role_name)
  VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'sub_018f1234-5678-7abc-8def-0123456789f0', 'tenant-member'
  );
  INSERT INTO identity.tenant_issuer_mappings (
    tenant_id, issuer_id, issuer_name, authority_url, state,
    root_certificate_sha256, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'iss_018f1234-5678-7abc-8def-0123456789f0',
    'orchestration-verifier', 'https://ca.verifier.invalid', 'active', repeat('1', 64),
    v_now, v_now
  );
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after, issued_at,
    state_changed_at, requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'crt_018f1234-5678-7abc-8def-0123456789f0',
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'iss_018f1234-5678-7abc-8def-0123456789f0',
    'tenant-client-auth-v1', '90000000000000000000000000000001', repeat('2', 64),
    'ed25519', 'active', v_now - interval '1 hour', v_now + interval '1 hour',
    v_now - interval '30 minutes', v_now - interval '30 minutes',
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'req_018f1234-5678-7abc-8def-0123456789f0',
    'orchestration-verifier-certificate',
    'evt_018f1234-5678-7abc-8def-0123456789f0',
    'evt_018f1234-5678-7abc-8def-0123456789f0',
    'cor_018f1234-5678-7abc-8def-0123456789f0', 1, v_now, v_now
  );
  INSERT INTO trust.trust_configurations (
    tenant_id, configuration_version, model_version, state, initial_score,
    smoothing_alpha, maximum_source_influence, stale_after_seconds,
    identity_weight, device_weight, behaviour_weight, certificate_weight,
    compliance_weight, created_by_subject_id, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0', 1, '1.0.0', 'draft', 50,
    0.5, 0.25, 300, 0.2, 0.2, 0.2, 0.2, 0.2,
    'sub_018f1234-5678-7abc-8def-0123456789f0', v_now, v_now
  );
  INSERT INTO trust.subject_trust_state_versions (
    tenant_id, subject_id, update_version, model_version, configuration_version,
    identity_component, device_component, behaviour_component, certificate_component,
    compliance_component, observed_at, recorded_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'sub_018f1234-5678-7abc-8def-0123456789f0', 9901, '1.0.0', 1,
    25, 25, 25, 25, 25, v_now - interval '1 minute', v_now
  );
  INSERT INTO trust.subject_trust_transitions (
    tenant_id, subject_id, transition_id, event_id, update_version,
    previous_transition_id, previous_score, previous_band, previous_recovery_streak,
    new_score, new_band, new_recovery_streak, weighted_score, smoothed_score,
    transition_kind, model_version, configuration_version, observed_at, evaluated_at,
    explanation_json, explanation_hash_sha256, recorded_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'trn_018f1234-5678-7abc-8def-0123456789f0',
    'evt_018f1234-5678-7abc-8def-0123456789f8', 9901,
    NULL, 50, 'uninitialized', 0, 25, 'low', 0, 25, 25,
    'deteriorated', '1.0.0', 1, v_now - interval '1 minute', v_now,
    '{}', repeat('3', 64), v_now
  );
  INSERT INTO trust.policy_versions (
    tenant_id, policy_version_id, policy_name, bundle_version, bundle_hash_sha256,
    entrypoint, state, published_by_subject_id, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'pol_018f1234-5678-7abc-8def-0123456789f0',
    'orchestration-verifier', 9901, repeat('4', 64),
    'tenant_trust/authorization/decision', 'published',
    'sub_018f1234-5678-7abc-8def-0123456789f0', v_now, v_now
  );
END
$identity_fixture$;

DO $verify_privileges$
BEGIN
  IF has_table_privilege('tenant_trust_app', 'orchestration.security_actions', 'SELECT')
     OR has_table_privilege('tenant_trust_app', 'orchestration.security_actions', 'INSERT')
     OR has_table_privilege('tenant_trust_security_action_worker', 'orchestration.security_actions', 'UPDATE')
     OR has_table_privilege('tenant_trust_security_action_requester', 'orchestration.security_actions', 'INSERT') THEN
    RAISE EXCEPTION 'security-action orchestration tables expose direct application privileges';
  END IF;
END
$verify_privileges$;

-- Keep pre-existing local work out of this transaction's deterministic claim order.
UPDATE orchestration.security_actions
SET next_attempt_at = clock_timestamp() + interval '1 day'
WHERE status IN ('pending', 'failed');

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789f0',
  'sub_018f1234-5678-7abc-8def-0123456789f0'
);

DO $authorized_request$
DECLARE v_request audit.security_action_requests%ROWTYPE;
BEGIN
  SELECT * INTO v_request FROM audit.request_quarantine_action(
    'act_018f1234-5678-7abc-8def-0123456789f1',
    'dec_018f1234-5678-7abc-8def-0123456789f2',
    'req_018f1234-5678-7abc-8def-0123456789f1',
    'cor_018f1234-5678-7abc-8def-0123456789f3',
    'crt_018f1234-5678-7abc-8def-0123456789f0',
    'record:read', 'restrict-access', 'TRUST_SCORE_QUARANTINE', repeat('9', 64),
    'trn_018f1234-5678-7abc-8def-0123456789f0',
    'pol_018f1234-5678-7abc-8def-0123456789f0', repeat('a', 64),
    clock_timestamp()
  );
  IF v_request.action_id <> 'act_018f1234-5678-7abc-8def-0123456789f1' THEN
    RAISE EXCEPTION 'authorized quarantine request lost its stable action ID';
  END IF;
END
$authorized_request$;

RESET ROLE;

DO $enqueue_fixture$
DECLARE
  v_certificate identity.certificates%ROWTYPE;
  v_action orchestration.security_actions%ROWTYPE;
BEGIN
  SELECT * INTO v_certificate FROM identity.certificates
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f0'
    AND certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789f0';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'verification requires one provisioned active certificate';
  END IF;

  SELECT * INTO v_action FROM orchestration.security_actions
  WHERE tenant_id = v_certificate.tenant_id
    AND action_id = 'act_018f1234-5678-7abc-8def-0123456789f1';
  IF v_action.action_id <> 'act_018f1234-5678-7abc-8def-0123456789f1'
     OR v_action.status <> 'pending' OR v_action.attempt_count <> 0 THEN
    RAISE EXCEPTION 'authorized quarantine trigger did not durably queue its stable identity';
  END IF;

  -- Exact replay returns the original durable action rather than creating another.
  v_action := orchestration.enqueue_security_action_internal(
    v_certificate.tenant_id,
    'act_018f1234-5678-7abc-8def-0123456789f1',
    'dec_018f1234-5678-7abc-8def-0123456789f2',
    'cor_018f1234-5678-7abc-8def-0123456789f3',
    v_certificate.subject_id,
    v_certificate.certificate_id,
    'restrict-access',
    'policy-quarantine',
    'TRUST_SCORE_QUARANTINE',
    repeat('a', 64),
    v_action.requested_at
  );
  IF v_action.action_id <> 'act_018f1234-5678-7abc-8def-0123456789f1'
     OR (SELECT count(*) FROM orchestration.security_actions
         WHERE action_id = v_action.action_id) <> 1 THEN
    RAISE EXCEPTION 'exact replay created a duplicate action';
  END IF;

  BEGIN
    PERFORM orchestration.enqueue_security_action_internal(
      v_certificate.tenant_id,
      'act_018f1234-5678-7abc-8def-0123456789f4',
      'dec_018f1234-5678-7abc-8def-0123456789f2',
      'cor_018f1234-5678-7abc-8def-0123456789f3',
      v_certificate.subject_id,
      v_certificate.certificate_id,
      'restrict-access',
      'policy-quarantine',
      'DIFFERENT_REASON',
      repeat('a', 64),
      clock_timestamp()
    );
    RAISE EXCEPTION 'conflicting replay was accepted';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM <> 'SECURITY_ACTION_IDEMPOTENCY_CONFLICT' THEN RAISE; END IF;
  END;
END
$enqueue_fixture$;

SET LOCAL ROLE tenant_trust_security_action_worker;

DO $first_attempt$
DECLARE v_claim record; v_status record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_action(
    'orchestrator.verify-1',
    'clm_018f1234-5678-7abc-8def-0123456789f5',
    clock_timestamp()
  );
  IF v_claim.action_id <> 'act_018f1234-5678-7abc-8def-0123456789f1'
     OR v_claim.attempt_count <> 1 OR v_claim.access_state <> 'normal'
     OR v_claim.expected_state_version <> 1 THEN
    RAISE EXCEPTION 'first action claim did not preserve scope, identity and state version';
  END IF;

  SELECT * INTO v_status FROM orchestration.mark_security_action_failed(
    v_claim.tenant_id, v_claim.action_id, v_claim.claim_token,
    'DEPENDENCY_TEMPORARILY_UNAVAILABLE', clock_timestamp(), 5
  );
  IF v_status.status <> 'failed' OR v_status.attempt_count <> 1
     OR v_status.last_failure_code <> 'DEPENDENCY_TEMPORARILY_UNAVAILABLE' THEN
    RAISE EXCEPTION 'retryable action failure was not made visible';
  END IF;
END
$first_attempt$;

RESET ROLE;
UPDATE orchestration.security_actions SET next_attempt_at = clock_timestamp()
WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789f1';
SET LOCAL ROLE tenant_trust_security_action_worker;

DO $second_attempt$
DECLARE v_claim record; v_status record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_action(
    'orchestrator.verify-2',
    'clm_018f1234-5678-7abc-8def-0123456789f6',
    clock_timestamp()
  );
  IF v_claim.action_id <> 'act_018f1234-5678-7abc-8def-0123456789f1'
     OR v_claim.attempt_count <> 2 THEN
    RAISE EXCEPTION 'retry did not keep the original action identity';
  END IF;

  BEGIN
    PERFORM orchestration.mark_security_action_succeeded(
      v_claim.tenant_id, v_claim.action_id,
      'clm_018f1234-5678-7abc-8def-0123456789f7',
      '{"access":"restricted","renewal":"allowed","targetCertificate":"active","replacement":"not-required"}',
      NULL, clock_timestamp()
    );
    RAISE EXCEPTION 'a different claim token completed the action';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM <> 'SECURITY_ACTION_CLAIM_CONFLICT' THEN RAISE; END IF;
  END;

  SELECT * INTO v_status FROM orchestration.mark_security_action_succeeded(
    v_claim.tenant_id, v_claim.action_id, v_claim.claim_token,
    '{"access":"restricted","renewal":"allowed","targetCertificate":"active","replacement":"not-required"}',
    NULL, clock_timestamp()
  );
  IF v_status.status <> 'succeeded' OR v_status.attempt_count <> 2
     OR v_status.succeeded_at IS NULL THEN
    RAISE EXCEPTION 'successful retry was not persisted';
  END IF;
END
$second_attempt$;

RESET ROLE;

DO $verify_history_and_state$
DECLARE v_action orchestration.security_actions%ROWTYPE;
BEGIN
  SELECT * INTO v_action FROM orchestration.security_actions
  WHERE action_id = 'act_018f1234-5678-7abc-8def-0123456789f1';
  IF v_action.status <> 'succeeded' OR v_action.result_state ->> 'access' <> 'restricted'
     OR (SELECT count(*) FROM orchestration.security_action_attempts
         WHERE tenant_id = v_action.tenant_id AND action_id = v_action.action_id) <> 2
     OR (SELECT count(*) FROM orchestration.security_action_attempts
         WHERE tenant_id = v_action.tenant_id AND action_id = v_action.action_id
           AND status = 'failed') <> 1
     OR NOT EXISTS (
       SELECT 1 FROM orchestration.subject_security_states AS state
       WHERE state.tenant_id = v_action.tenant_id
         AND state.subject_id = v_action.target_subject_id
         AND state.certificate_id = v_action.target_certificate_id
         AND state.access_state = 'restricted' AND state.state_version = 2
         AND state.last_action_id = v_action.action_id
     ) THEN
    RAISE EXCEPTION 'terminal state or per-attempt history is incomplete';
  END IF;
END
$verify_history_and_state$;

DO $queue_repeated_trigger$
DECLARE v_action orchestration.security_actions%ROWTYPE;
BEGIN
  v_action := orchestration.enqueue_security_action_internal(
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'act_018f1234-5678-7abc-8def-0123456789fa',
    'dec_018f1234-5678-7abc-8def-0123456789fb',
    'cor_018f1234-5678-7abc-8def-0123456789fc',
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'crt_018f1234-5678-7abc-8def-0123456789f0',
    'restrict-access', 'policy-quarantine', 'TRUST_SCORE_QUARANTINE',
    repeat('b', 64), clock_timestamp()
  );
  IF v_action.status <> 'pending' OR v_action.attempt_count <> 0 THEN
    RAISE EXCEPTION 'repeated trigger fixture was not queued';
  END IF;
END
$queue_repeated_trigger$;

SET LOCAL ROLE tenant_trust_security_action_worker;
DO $suppress_repeated_trigger$
DECLARE v_claim record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_action(
    'orchestrator.verify-replay',
    'clm_018f1234-5678-7abc-8def-0123456789fd',
    clock_timestamp()
  );
  IF v_claim.action_id IS NOT NULL THEN
    RAISE EXCEPTION 'an already-satisfied repeated trigger reached execution';
  END IF;
END
$suppress_repeated_trigger$;
RESET ROLE;

DO $verify_repeated_trigger_suppression$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM orchestration.security_actions
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f0'
      AND action_id = 'act_018f1234-5678-7abc-8def-0123456789fa'
      AND status = 'failed'
      AND last_failure_code = 'ACTION_ALREADY_SATISFIED'
      AND next_attempt_at = 'infinity'::timestamptz
      AND attempt_count = 1
  ) OR NOT EXISTS (
    SELECT 1 FROM orchestration.subject_security_states
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f0'
      AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789f0'
      AND certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789f0'
      AND access_state = 'restricted' AND state_version = 2
  ) THEN
    RAISE EXCEPTION 'repeated trigger suppression changed state or remained retryable';
  END IF;
END
$verify_repeated_trigger_suppression$;

DO $queue_conflicting_recovery_and_severity$
DECLARE
  v_now timestamptz := clock_timestamp();
BEGIN
  PERFORM orchestration.enqueue_security_action_internal(
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'act_018f1234-5678-7abc-8def-012345678a00',
    'dec_018f1234-5678-7abc-8def-012345678a01',
    'cor_018f1234-5678-7abc-8def-012345678a02',
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'crt_018f1234-5678-7abc-8def-0123456789f0',
    'restore-access', 'recovery-authorization', 'ACCESS_RECOVERY_ELIGIBLE',
    repeat('c', 64), v_now
  );
  INSERT INTO orchestration.security_recovery_authorizations (
    tenant_id, authorization_id, action_id, decision_id, request_id,
    correlation_id, idempotency_key, authorized_by_subject_id,
    target_subject_id, target_certificate_id, action_type, trust_transition_id,
    expected_state_version, reason_code, eligibility_hash_sha256,
    step_up_proof_id_hash_sha256, cause_resolution_reference,
    authorized_at, expires_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'rca_018f1234-5678-7abc-8def-012345678a03',
    'act_018f1234-5678-7abc-8def-012345678a00',
    'dec_018f1234-5678-7abc-8def-012345678a01',
    'req_018f1234-5678-7abc-8def-012345678a04',
    'cor_018f1234-5678-7abc-8def-012345678a02',
    'orchestration-conflicting-recovery',
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'crt_018f1234-5678-7abc-8def-0123456789f0',
    'restore-access', 'trn_018f1234-5678-7abc-8def-0123456789f0', 2,
    'ACCESS_RECOVERY_ELIGIBLE', repeat('c', 64), repeat('d', 64),
    NULL, v_now, v_now + interval '300 seconds'
  );
  PERFORM orchestration.enqueue_security_action_internal(
    'tnt_018f1234-5678-7abc-8def-0123456789f0',
    'act_018f1234-5678-7abc-8def-012345678a05',
    'dec_018f1234-5678-7abc-8def-012345678a06',
    'cor_018f1234-5678-7abc-8def-012345678a07',
    'sub_018f1234-5678-7abc-8def-0123456789f0',
    'crt_018f1234-5678-7abc-8def-0123456789f0',
    'block-renewal', 'severity-rule', 'SEVERE_EVIDENCE_NOT_CORROBORATED',
    repeat('e', 64), v_now + interval '1 millisecond'
  );
END
$queue_conflicting_recovery_and_severity$;

SET LOCAL ROLE tenant_trust_security_action_worker;
DO $severity_precedes_recovery$
DECLARE v_claim record; v_status record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_action(
    'orchestrator.verify-conflict',
    'clm_018f1234-5678-7abc-8def-012345678a08', clock_timestamp()
  );
  IF v_claim.action_id <> 'act_018f1234-5678-7abc-8def-012345678a05'
     OR v_claim.action_type <> 'block-renewal' THEN
    RAISE EXCEPTION 'older recovery action overtook pending severity work';
  END IF;
  SELECT * INTO v_status FROM orchestration.mark_security_action_succeeded(
    v_claim.tenant_id, v_claim.action_id, v_claim.claim_token,
    '{"access":"restricted","renewal":"blocked","targetCertificate":"active","replacement":"not-required"}',
    NULL, clock_timestamp()
  );
  IF v_status.status <> 'succeeded' THEN
    RAISE EXCEPTION 'precedent severity action did not complete';
  END IF;
END
$severity_precedes_recovery$;

DO $stale_recovery_after_severity$
DECLARE v_claim record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_action(
    'orchestrator.verify-conflict',
    'clm_018f1234-5678-7abc-8def-012345678a09', clock_timestamp()
  );
  IF v_claim.action_id IS NOT NULL THEN
    RAISE EXCEPTION 'recovery authorized before severity execution remained executable';
  END IF;
END
$stale_recovery_after_severity$;
RESET ROLE;

DO $verify_conflict_resolution$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM orchestration.security_actions
    WHERE action_id = 'act_018f1234-5678-7abc-8def-012345678a00'
      AND status = 'failed' AND last_failure_code = 'RECOVERY_STATE_CHANGED'
      AND next_attempt_at = 'infinity'::timestamptz AND attempt_count = 1
  ) OR NOT EXISTS (
    SELECT 1 FROM orchestration.subject_security_states
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789f0'
      AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789f0'
      AND certificate_id = 'crt_018f1234-5678-7abc-8def-0123456789f0'
      AND access_state = 'restricted' AND renewal_state = 'blocked'
      AND state_version = 3
  ) THEN
    RAISE EXCEPTION 'conflicting severity and recovery actions did not fail closed';
  END IF;
END
$verify_conflict_resolution$;

ROLLBACK;
\echo 'Verified stable IDs, retries, repeated-trigger suppression and severity-before-recovery conflict handling.'
