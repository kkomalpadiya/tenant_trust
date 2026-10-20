\set ON_ERROR_STOP on

BEGIN;

DO $fixture$
DECLARE
  v_now timestamptz := clock_timestamp();
BEGIN
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after, issued_at,
    state_changed_at, requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version, created_at, updated_at
  ) VALUES
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'crt_018f1234-5678-7abc-8def-0123456789e1',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1', '10000000000000000000000000000001', repeat('1', 64),
    'ed25519', 'active', v_now - interval '1 hour', v_now + interval '1 hour',
    v_now - interval '30 minutes', v_now - interval '30 minutes',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'req_018f1234-5678-7abc-8def-0123456789e1', 'verify-quarantine-alpha-certificate',
    'evt_018f1234-5678-7abc-8def-0123456789e1',
    'evt_018f1234-5678-7abc-8def-0123456789e1',
    'cor_018f1234-5678-7abc-8def-0123456789e1', 1,
    v_now - interval '30 minutes', v_now - interval '30 minutes'
  ),
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ac',
    'crt_018f1234-5678-7abc-8def-0123456789e2',
    'sub_018f1234-5678-7abc-8def-0123456789ae',
    'iss_018f1234-5678-7abc-8def-0123456789b5',
    'tenant-client-auth-v1', '20000000000000000000000000000001', repeat('2', 64),
    'ed25519', 'active', v_now - interval '1 hour', v_now + interval '1 hour',
    v_now - interval '30 minutes', v_now - interval '30 minutes',
    'sub_018f1234-5678-7abc-8def-0123456789ae',
    'req_018f1234-5678-7abc-8def-0123456789e2', 'verify-quarantine-beta-certificate',
    'evt_018f1234-5678-7abc-8def-0123456789e2',
    'evt_018f1234-5678-7abc-8def-0123456789e2',
    'cor_018f1234-5678-7abc-8def-0123456789e2', 1,
    v_now - interval '30 minutes', v_now - interval '30 minutes'
  );

  INSERT INTO trust.subject_trust_state_versions (
    tenant_id, subject_id, update_version, model_version, configuration_version,
    identity_component, device_component, behaviour_component, certificate_component,
    compliance_component, observed_at, recorded_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ac', 9001, '1.0.0', 1,
    25, 25, 25, 25, 25, v_now - interval '1 minute', v_now
  );

  INSERT INTO trust.subject_trust_transitions (
    tenant_id, subject_id, transition_id, event_id, update_version,
    previous_transition_id, previous_score, previous_band, previous_recovery_streak,
    new_score, new_band, new_recovery_streak, weighted_score, smoothed_score,
    transition_kind, model_version, configuration_version, observed_at, evaluated_at,
    explanation_json, explanation_hash_sha256, recorded_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'trn_018f1234-5678-7abc-8def-0123456789e1',
    'evt_018f1234-5678-7abc-8def-0123456789e3', 9001,
    NULL, 50, 'uninitialized', 0, 25, 'low', 0, 25, 25,
    'deteriorated', '1.0.0', 1, v_now - interval '1 minute', v_now,
    '{}', repeat('3', 64), v_now
  );

  INSERT INTO trust.policy_versions (
    tenant_id, policy_version_id, policy_name, bundle_version, bundle_hash_sha256,
    entrypoint, state, published_by_subject_id, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'pol_018f1234-5678-7abc-8def-0123456789e1', 'access-control', 9001,
    repeat('4', 64), 'tenant_trust/authorization/decision', 'published',
    'sub_018f1234-5678-7abc-8def-0123456789ac', v_now, v_now
  );
END
$fixture$;

DO $verify_privileges$
BEGIN
  IF has_table_privilege('tenant_trust_app', 'audit.security_action_requests', 'SELECT')
     OR has_table_privilege('tenant_trust_app', 'audit.security_action_requests', 'INSERT')
     OR has_table_privilege('tenant_trust_app', 'audit.security_action_requests', 'UPDATE')
     OR has_table_privilege('tenant_trust_app', 'audit.security_action_requests', 'DELETE') THEN
    RAISE EXCEPTION 'application role has direct security-action table access';
  END IF;
END
$verify_privileges$;

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_quarantine_request$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_row audit.security_action_requests%ROWTYPE;
BEGIN
  SELECT * INTO v_row FROM audit.request_quarantine_action(
    'act_018f1234-5678-7abc-8def-0123456789e1',
    'dec_018f1234-5678-7abc-8def-0123456789e1',
    'req_018f1234-5678-7abc-8def-0123456789e3',
    'cor_018f1234-5678-7abc-8def-0123456789e3',
    'crt_018f1234-5678-7abc-8def-0123456789e1',
    'record:read', 'restrict-access', 'TRUST_SCORE_QUARANTINE', repeat('5', 64),
    'trn_018f1234-5678-7abc-8def-0123456789e1',
    'pol_018f1234-5678-7abc-8def-0123456789e1', repeat('6', 64), v_now
  );
  IF v_row.action_id <> 'act_018f1234-5678-7abc-8def-0123456789e1'
     OR v_row.correlation_id <> 'cor_018f1234-5678-7abc-8def-0123456789e3'
     OR v_row.reason_code <> 'TRUST_SCORE_QUARANTINE'
     OR v_row.status <> 'requested'
     OR v_row.actor_subject_id <> 'sub_018f1234-5678-7abc-8def-0123456789ac' THEN
    RAISE EXCEPTION 'quarantine request did not preserve its exact bound values';
  END IF;

  SELECT * INTO v_row FROM audit.request_quarantine_action(
    'act_018f1234-5678-7abc-8def-0123456789e9',
    'dec_018f1234-5678-7abc-8def-0123456789e1',
    'req_018f1234-5678-7abc-8def-0123456789e3',
    'cor_018f1234-5678-7abc-8def-0123456789e3',
    'crt_018f1234-5678-7abc-8def-0123456789e1',
    'record:read', 'restrict-access', 'TRUST_SCORE_QUARANTINE', repeat('5', 64),
    'trn_018f1234-5678-7abc-8def-0123456789e1',
    'pol_018f1234-5678-7abc-8def-0123456789e1', repeat('6', 64), v_now
  );
  IF v_row.action_id <> 'act_018f1234-5678-7abc-8def-0123456789e1' THEN
    RAISE EXCEPTION 'exact replay did not return the original action request';
  END IF;

  BEGIN
    PERFORM audit.request_quarantine_action(
      'act_018f1234-5678-7abc-8def-0123456789e8',
      'dec_018f1234-5678-7abc-8def-0123456789e1',
      'req_018f1234-5678-7abc-8def-0123456789e3',
      'cor_018f1234-5678-7abc-8def-0123456789e3',
      'crt_018f1234-5678-7abc-8def-0123456789e1',
      'record:read', 'restrict-access', 'DIFFERENT_REASON', repeat('5', 64),
      'trn_018f1234-5678-7abc-8def-0123456789e1',
      'pol_018f1234-5678-7abc-8def-0123456789e1', repeat('6', 64), v_now
    );
    RAISE EXCEPTION 'conflicting replay was accepted';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM <> 'QUARANTINE_ACTION_IDEMPOTENCY_CONFLICT' THEN RAISE; END IF;
  END;

  BEGIN
    PERFORM audit.request_quarantine_action(
      'act_018f1234-5678-7abc-8def-0123456789e7',
      'dec_018f1234-5678-7abc-8def-0123456789e7',
      'req_018f1234-5678-7abc-8def-0123456789e7',
      'cor_018f1234-5678-7abc-8def-0123456789e7',
      'crt_018f1234-5678-7abc-8def-0123456789e2',
      'record:read', 'restrict-access', 'TRUST_SCORE_QUARANTINE', repeat('5', 64),
      'trn_018f1234-5678-7abc-8def-0123456789e1',
      'pol_018f1234-5678-7abc-8def-0123456789e1', repeat('6', 64), v_now
    );
    RAISE EXCEPTION 'foreign-tenant certificate was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_quarantine_request$;

RESET ROLE;

DO $verify_append_only$
BEGIN
  BEGIN
    UPDATE audit.security_action_requests SET status = 'requested'
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND action_id = 'act_018f1234-5678-7abc-8def-0123456789e1';
    RAISE EXCEPTION 'security action request was mutable';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_append_only$;

ROLLBACK;
\echo 'Verified DENY/QUARANTINE least privilege, binding, idempotency and append-only enforcement.'
