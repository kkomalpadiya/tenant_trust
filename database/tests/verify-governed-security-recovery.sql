\set ON_ERROR_STOP on

BEGIN;

-- Keep unrelated local queue entries out of this test's deterministic claim order.
UPDATE orchestration.security_actions
SET next_attempt_at = clock_timestamp() + interval '1 day'
WHERE status IN ('pending', 'failed');

DO $fixture$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name, created_at, updated_at)
  VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'governed-recovery-verifier', 'Governed Recovery Verifier', v_now, v_now
  );
  INSERT INTO identity.subjects (
    subject_id, identity_provider, provider_subject, display_name, created_at, updated_at
  ) VALUES
    ('sub_018f1234-5678-7abc-8def-012345678af1', 'verification',
      'recovery-admin', 'Recovery Admin', v_now, v_now),
    ('sub_018f1234-5678-7abc-8def-012345678af2', 'verification',
      'recovery-target', 'Recovery Target', v_now, v_now);
  INSERT INTO identity.tenant_memberships (tenant_id, subject_id, created_at, updated_at)
  VALUES
    ('tnt_018f1234-5678-7abc-8def-012345678af0',
      'sub_018f1234-5678-7abc-8def-012345678af1', v_now, v_now),
    ('tnt_018f1234-5678-7abc-8def-012345678af0',
      'sub_018f1234-5678-7abc-8def-012345678af2', v_now, v_now);
  INSERT INTO identity.tenant_role_assignments (tenant_id, subject_id, role_name)
  VALUES
    ('tnt_018f1234-5678-7abc-8def-012345678af0',
      'sub_018f1234-5678-7abc-8def-012345678af1', 'tenant-admin'),
    ('tnt_018f1234-5678-7abc-8def-012345678af0',
      'sub_018f1234-5678-7abc-8def-012345678af2', 'tenant-member');
  INSERT INTO identity.tenant_issuer_mappings (
    tenant_id, issuer_id, issuer_name, authority_url, state,
    root_certificate_sha256, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'iss_018f1234-5678-7abc-8def-012345678af3',
    'recovery-verifier', 'https://ca.recovery.invalid', 'active', repeat('1', 64),
    v_now, v_now
  );
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after, issued_at,
    state_changed_at, requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'crt_018f1234-5678-7abc-8def-012345678af4',
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'iss_018f1234-5678-7abc-8def-012345678af3',
    'tenant-client-auth-v1', 'A0000000000000000000000000000001', repeat('2', 64),
    'ed25519', 'revoked', v_now - interval '1 hour', v_now + interval '1 hour',
    v_now - interval '30 minutes', v_now - interval '10 minutes',
    'sub_018f1234-5678-7abc-8def-012345678af1',
    'req_018f1234-5678-7abc-8def-012345678af5', 'recovery-target-certificate',
    'evt_018f1234-5678-7abc-8def-012345678af6',
    'evt_018f1234-5678-7abc-8def-012345678af7',
    'cor_018f1234-5678-7abc-8def-012345678af8', 2, v_now, v_now
  );
  INSERT INTO orchestration.subject_security_states (
    tenant_id, subject_id, certificate_id, access_state, renewal_state,
    target_certificate_state, replacement_state, state_version, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'crt_018f1234-5678-7abc-8def-012345678af4',
    'suspended', 'blocked', 'revoked', 'required', 7, v_now
  );
  INSERT INTO trust.trust_configurations (
    tenant_id, configuration_version, model_version, state, initial_score,
    smoothing_alpha, maximum_source_influence, stale_after_seconds,
    identity_weight, device_weight, behaviour_weight, certificate_weight,
    compliance_weight, created_by_subject_id, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0', 1, '1.0.0', 'draft', 50,
    0.5, 0.25, 300, 0.2, 0.2, 0.2, 0.2, 0.2,
    'sub_018f1234-5678-7abc-8def-012345678af1', v_now, v_now
  );
  INSERT INTO trust.subject_trust_state_versions (
    tenant_id, subject_id, update_version, model_version, configuration_version,
    identity_component, device_component, behaviour_component, certificate_component,
    compliance_component, observed_at, recorded_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'sub_018f1234-5678-7abc-8def-012345678af2', 1, '1.0.0', 1,
    75, 75, 75, 75, 75, v_now - interval '30 seconds', v_now
  );
  INSERT INTO trust.subject_trust_transitions (
    tenant_id, subject_id, transition_id, event_id, update_version,
    previous_transition_id, previous_score, previous_band, previous_recovery_streak,
    new_score, new_band, new_recovery_streak, weighted_score, smoothed_score,
    transition_kind, model_version, configuration_version, observed_at, evaluated_at,
    explanation_json, explanation_hash_sha256, recorded_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'trn_018f1234-5678-7abc-8def-012345678af9',
    'evt_018f1234-5678-7abc-8def-012345678afa', 1,
    NULL, 70, 'uninitialized', 0, 75, 'high', 0, 75, 75,
    'recovered', '1.0.0', 1, v_now - interval '30 seconds', v_now,
    jsonb_build_object(
      'transitionControl', jsonb_build_object(
        'sourceInfluence', jsonb_build_object(
          'distinctSourceIds', jsonb_build_array(
            'src_018f1234-5678-7abc-8def-012345678afb',
            'src_018f1234-5678-7abc-8def-012345678afc'
          )
        ),
        'recovery', jsonb_build_object(
          'eligible', true, 'distinctSourceCount', 2,
          'requiredDistinctSourceCount', 2, 'qualifyingStreak', 2,
          'requiredQualifyingStreak', 2
        )
      )
    )::text,
    repeat('3', 64), v_now
  );
  INSERT INTO trust.subject_trust_transition_current (
    tenant_id, subject_id, transition_id, update_version, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'trn_018f1234-5678-7abc-8def-012345678af9', 1, v_now
  );

  INSERT INTO identity.step_up_factors (
    tenant_id, subject_id, factor_id, public_key_base64url,
    public_key_sha256, state, enrolled_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'sub_018f1234-5678-7abc-8def-012345678af1',
    'suf_018f1234-5678-7abc-8def-012345678afd',
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    trust.ed25519_public_key_sha256('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
    'active', v_now - interval '1 minute'
  );
  INSERT INTO audit.step_up_challenges (
    tenant_id, subject_id, challenge_id, factor_id, action, nonce_base64url,
    session_id_hash_sha256, state, issued_at, expires_at, verified_at
  ) VALUES
    ('tnt_018f1234-5678-7abc-8def-012345678af0',
      'sub_018f1234-5678-7abc-8def-012345678af1',
      'suc_018f1234-5678-7abc-8def-012345678afe',
      'suf_018f1234-5678-7abc-8def-012345678afd', 'tenant:admin',
      'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', repeat('4', 64),
      'verified', v_now - interval '30 seconds', v_now + interval '90 seconds',
      v_now - interval '20 seconds'),
    ('tnt_018f1234-5678-7abc-8def-012345678af0',
      'sub_018f1234-5678-7abc-8def-012345678af1',
      'suc_018f1234-5678-7abc-8def-012345678aff',
      'suf_018f1234-5678-7abc-8def-012345678afd', 'tenant:admin',
      'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', repeat('4', 64),
      'verified', v_now - interval '30 seconds', v_now + interval '90 seconds',
      v_now - interval '20 seconds');
  INSERT INTO audit.step_up_proofs (
    tenant_id, subject_id, proof_id_hash_sha256, challenge_id, action,
    session_id_hash_sha256, verified_at, expires_at
  ) VALUES
    ('tnt_018f1234-5678-7abc-8def-012345678af0',
      'sub_018f1234-5678-7abc-8def-012345678af1', repeat('5', 64),
      'suc_018f1234-5678-7abc-8def-012345678afe', 'tenant:admin', repeat('4', 64),
      v_now - interval '20 seconds', v_now + interval '4 minutes'),
    ('tnt_018f1234-5678-7abc-8def-012345678af0',
      'sub_018f1234-5678-7abc-8def-012345678af1', repeat('6', 64),
      'suc_018f1234-5678-7abc-8def-012345678aff', 'tenant:admin', repeat('4', 64),
      v_now - interval '20 seconds', v_now + interval '4 minutes');
END
$fixture$;

DO $least_privilege$
BEGIN
  IF has_table_privilege('tenant_trust_app',
       'orchestration.security_recovery_authorizations', 'SELECT')
     OR has_table_privilege('tenant_trust_app',
       'orchestration.security_recovery_authorizations', 'INSERT')
     OR has_table_privilege('tenant_trust_security_action_worker',
       'orchestration.security_recovery_authorizations', 'UPDATE') THEN
    RAISE EXCEPTION 'recovery authorization history exposes direct table privileges';
  END IF;
END
$least_privilege$;

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-012345678af0',
  'sub_018f1234-5678-7abc-8def-012345678af2'
);
DO $member_denied$
BEGIN
  BEGIN
    PERFORM * FROM orchestration.get_security_recovery_context(
      'sub_018f1234-5678-7abc-8def-012345678af2',
      'crt_018f1234-5678-7abc-8def-012345678af4'
    );
    RAISE EXCEPTION 'tenant member authorized recovery';
  EXCEPTION WHEN SQLSTATE '42501' THEN
    IF SQLERRM <> 'RECOVERY_TENANT_ADMIN_REQUIRED' THEN RAISE; END IF;
  END;
END
$member_denied$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-012345678af0',
  'sub_018f1234-5678-7abc-8def-012345678af1'
);

DO $authorize_replacement$
DECLARE v_context record; v_authorization record; v_replay record;
BEGIN
  SELECT * INTO v_context FROM orchestration.get_security_recovery_context(
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'crt_018f1234-5678-7abc-8def-012345678af4'
  );
  IF v_context.state_version <> 7 OR v_context.transition <> 'recovered'
     OR v_context.score <> 75 OR cardinality(v_context.source_ids) <> 2 THEN
    RAISE EXCEPTION 'recovery context did not bind current state and corroborated trust';
  END IF;

  SELECT * INTO v_authorization FROM orchestration.authorize_security_recovery(
    'rca_018f1234-5678-7abc-8def-012345678b00',
    'act_018f1234-5678-7abc-8def-012345678b01',
    'dec_018f1234-5678-7abc-8def-012345678b02',
    'req_018f1234-5678-7abc-8def-012345678b03',
    'cor_018f1234-5678-7abc-8def-012345678b04',
    'governed-recovery-replacement',
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'crt_018f1234-5678-7abc-8def-012345678af4',
    'issue-replacement-certificate',
    'trn_018f1234-5678-7abc-8def-012345678af9', 7,
    'REPLACEMENT_ELIGIBLE', repeat('7', 64), repeat('5', 64), repeat('4', 64),
    'case:resolved:123', clock_timestamp()
  );
  IF v_authorization.status <> 'pending'
     OR v_authorization.action_type <> 'issue-replacement-certificate' THEN
    RAISE EXCEPTION 'eligible replacement was not durably authorized and queued';
  END IF;

  SELECT * INTO v_replay FROM orchestration.authorize_security_recovery(
    'rca_018f1234-5678-7abc-8def-012345678b05',
    'act_018f1234-5678-7abc-8def-012345678b06',
    'dec_018f1234-5678-7abc-8def-012345678b07',
    'req_018f1234-5678-7abc-8def-012345678b03',
    'cor_018f1234-5678-7abc-8def-012345678b08',
    'governed-recovery-replacement',
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'crt_018f1234-5678-7abc-8def-012345678af4',
    'issue-replacement-certificate',
    'trn_018f1234-5678-7abc-8def-012345678af9', 7,
    'REPLACEMENT_ELIGIBLE', repeat('7', 64), repeat('5', 64), repeat('4', 64),
    'case:resolved:123', clock_timestamp()
  );
  IF v_replay.authorization_id <> v_authorization.authorization_id
     OR v_replay.action_id <> v_authorization.action_id THEN
    RAISE EXCEPTION 'exact recovery replay did not return the original authorization';
  END IF;
END
$authorize_replacement$;

RESET ROLE;
DO $verify_replay_count$
BEGIN
  IF (SELECT count(*) FROM orchestration.security_recovery_authorizations
      WHERE idempotency_key = 'governed-recovery-replacement') <> 1 THEN
    RAISE EXCEPTION 'exact recovery replay created a duplicate authorization';
  END IF;
END
$verify_replay_count$;
SET LOCAL ROLE tenant_trust_security_action_worker;

DO $claim_replacement$
DECLARE v_claim record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_action(
    'orchestrator.recovery-1',
    'clm_018f1234-5678-7abc-8def-012345678b09', clock_timestamp()
  );
  IF v_claim.action_id <> 'act_018f1234-5678-7abc-8def-012345678b01'
     OR v_claim.recovery_authorization_id <> 'rca_018f1234-5678-7abc-8def-012345678b00'
     OR v_claim.recovery_authorized_by_subject_id <>
       'sub_018f1234-5678-7abc-8def-012345678af1'
     OR v_claim.cause_resolution_reference <> 'case:resolved:123' THEN
    RAISE EXCEPTION 'worker claim lost governed recovery authorization metadata';
  END IF;
  BEGIN
    PERFORM orchestration.mark_security_action_succeeded(
      v_claim.tenant_id, v_claim.action_id, v_claim.claim_token,
      '{"access":"suspended","renewal":"blocked","targetCertificate":"revoked","replacement":"issued"}',
      'crt_018f1234-5678-7abc-8def-012345678af4', clock_timestamp()
    );
    RAISE EXCEPTION 'revoked target certificate was accepted as its own replacement';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM <> 'REPLACEMENT_ISSUANCE_UNCONFIRMED' THEN RAISE; END IF;
  END;
END
$claim_replacement$;

RESET ROLE;
DO $fresh_replacement$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after, issued_at,
    state_changed_at, requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'crt_018f1234-5678-7abc-8def-012345678b10',
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'iss_018f1234-5678-7abc-8def-012345678af3',
    'tenant-client-auth-v1', 'A0000000000000000000000000000002', repeat('8', 64),
    'ed25519', 'active', v_now - interval '1 minute', v_now + interval '1 hour',
    v_now, v_now, 'sub_018f1234-5678-7abc-8def-012345678af1',
    'req_018f1234-5678-7abc-8def-012345678b11', 'governed-recovery-fresh-certificate',
    'evt_018f1234-5678-7abc-8def-012345678b12',
    'evt_018f1234-5678-7abc-8def-012345678b12',
    'cor_018f1234-5678-7abc-8def-012345678b13', 1, v_now, v_now
  );
END
$fresh_replacement$;

SET LOCAL ROLE tenant_trust_security_action_worker;
DO $complete_replacement$
DECLARE v_status record;
BEGIN
  SELECT * INTO v_status FROM orchestration.mark_security_action_succeeded(
    'tnt_018f1234-5678-7abc-8def-012345678af0',
    'act_018f1234-5678-7abc-8def-012345678b01',
    'clm_018f1234-5678-7abc-8def-012345678b09',
    '{"access":"suspended","renewal":"blocked","targetCertificate":"revoked","replacement":"issued"}',
    'crt_018f1234-5678-7abc-8def-012345678b10', clock_timestamp()
  );
  IF v_status.status <> 'succeeded' THEN
    RAISE EXCEPTION 'fresh replacement certificate did not complete recovery stage one';
  END IF;
END
$complete_replacement$;

RESET ROLE;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-012345678af0',
  'sub_018f1234-5678-7abc-8def-012345678af1'
);

DO $authorize_restore$
DECLARE v_authorization record;
BEGIN
  SELECT * INTO v_authorization FROM orchestration.authorize_security_recovery(
    'rca_018f1234-5678-7abc-8def-012345678b14',
    'act_018f1234-5678-7abc-8def-012345678b15',
    'dec_018f1234-5678-7abc-8def-012345678b16',
    'req_018f1234-5678-7abc-8def-012345678b17',
    'cor_018f1234-5678-7abc-8def-012345678b18',
    'governed-recovery-restore',
    'sub_018f1234-5678-7abc-8def-012345678af2',
    'crt_018f1234-5678-7abc-8def-012345678af4',
    'restore-access', 'trn_018f1234-5678-7abc-8def-012345678af9', 8,
    'ACCESS_RECOVERY_ELIGIBLE', repeat('9', 64), repeat('6', 64), repeat('4', 64),
    'case:resolved:123', clock_timestamp()
  );
  IF v_authorization.status <> 'pending' OR v_authorization.action_type <> 'restore-access' THEN
    RAISE EXCEPTION 'stage-two access restoration was not authorized';
  END IF;
END
$authorize_restore$;

RESET ROLE;
SET LOCAL ROLE tenant_trust_security_action_worker;
DO $complete_restore$
DECLARE v_claim record; v_status record;
BEGIN
  SELECT * INTO v_claim FROM orchestration.claim_security_action(
    'orchestrator.recovery-2',
    'clm_018f1234-5678-7abc-8def-012345678b19', clock_timestamp()
  );
  SELECT * INTO v_status FROM orchestration.mark_security_action_succeeded(
    v_claim.tenant_id, v_claim.action_id, v_claim.claim_token,
    '{"access":"normal","renewal":"allowed","targetCertificate":"revoked","replacement":"issued"}',
    NULL, clock_timestamp()
  );
  IF v_claim.action_id <> 'act_018f1234-5678-7abc-8def-012345678b15'
     OR v_status.status <> 'succeeded' THEN
    RAISE EXCEPTION 'authorized access restoration did not complete';
  END IF;
END
$complete_restore$;

RESET ROLE;
DO $verify_terminal_state$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM orchestration.subject_security_states AS state
    WHERE state.tenant_id = 'tnt_018f1234-5678-7abc-8def-012345678af0'
      AND state.subject_id = 'sub_018f1234-5678-7abc-8def-012345678af2'
      AND state.certificate_id = 'crt_018f1234-5678-7abc-8def-012345678af4'
      AND state.access_state = 'normal' AND state.renewal_state = 'allowed'
      AND state.target_certificate_state = 'revoked'
      AND state.replacement_state = 'issued' AND state.state_version = 9
  ) OR NOT EXISTS (
    SELECT 1 FROM identity.certificates
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-012345678af0'
      AND certificate_id = 'crt_018f1234-5678-7abc-8def-012345678af4'
      AND state = 'revoked'
  ) OR NOT EXISTS (
    SELECT 1 FROM identity.certificates
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-012345678af0'
      AND certificate_id = 'crt_018f1234-5678-7abc-8def-012345678b10'
      AND state = 'active'
  ) OR (SELECT count(*) FROM audit.step_up_proofs
        WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-012345678af0'
          AND consumed_at IS NOT NULL) <> 2
     OR (SELECT count(*) FROM audit.security_action_audit_events
         WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-012345678af0'
           AND action_id IN (
             'act_018f1234-5678-7abc-8def-012345678b01',
             'act_018f1234-5678-7abc-8def-012345678b15'
           )
           AND authority_class = 'recovery-authorization'
           AND recovery_authorization_id IS NOT NULL
           AND recovery_trust_transition_id = 'trn_018f1234-5678-7abc-8def-012345678af9'
           AND recovery_authorized_by_subject_id = 'sub_018f1234-5678-7abc-8def-012345678af1') <> 4 THEN
    RAISE EXCEPTION 'governed recovery did not preserve revocation and fresh issuance';
  END IF;
END
$verify_terminal_state$;

ROLLBACK;
\echo 'Verified tenant-admin step-up, current trust binding, two-stage recovery and permanent revocation.'
