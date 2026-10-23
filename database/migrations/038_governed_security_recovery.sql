CREATE DOMAIN orchestration.recovery_authorization_id AS text
  CHECK (VALUE ~ '^rca_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TABLE orchestration.security_recovery_authorizations (
  tenant_id identity.tenant_id NOT NULL,
  authorization_id orchestration.recovery_authorization_id NOT NULL,
  action_id audit.security_action_id NOT NULL,
  decision_id audit.policy_decision_id NOT NULL,
  request_id identity.request_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  idempotency_key identity.idempotency_key NOT NULL,
  authorized_by_subject_id identity.subject_id NOT NULL,
  target_subject_id identity.subject_id NOT NULL,
  target_certificate_id identity.certificate_id NOT NULL,
  action_type orchestration.security_action_type NOT NULL,
  trust_transition_id trust.transition_id NOT NULL,
  expected_state_version bigint NOT NULL,
  reason_code text NOT NULL,
  eligibility_hash_sha256 identity.sha256_digest NOT NULL,
  step_up_proof_id_hash_sha256 text NOT NULL,
  cause_resolution_reference text,
  authorized_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT security_recovery_authorizations_pk PRIMARY KEY (tenant_id, authorization_id),
  CONSTRAINT security_recovery_authorizations_action_unique UNIQUE (tenant_id, action_id),
  CONSTRAINT security_recovery_authorizations_idempotency_unique UNIQUE (
    tenant_id, authorized_by_subject_id, idempotency_key
  ),
  CONSTRAINT security_recovery_authorizations_action_fk FOREIGN KEY (tenant_id, action_id)
    REFERENCES orchestration.security_actions (tenant_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT security_recovery_authorizations_actor_fk FOREIGN KEY (
    tenant_id, authorized_by_subject_id
  ) REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT security_recovery_authorizations_target_fk FOREIGN KEY (
    tenant_id, target_subject_id, target_certificate_id
  ) REFERENCES orchestration.subject_security_states (
    tenant_id, subject_id, certificate_id
  ) ON DELETE RESTRICT,
  CONSTRAINT security_recovery_authorizations_transition_fk FOREIGN KEY (
    tenant_id, trust_transition_id
  ) REFERENCES trust.subject_trust_transitions (tenant_id, transition_id) ON DELETE RESTRICT,
  CONSTRAINT security_recovery_authorizations_action CHECK (
    action_type IN ('restore-access', 'issue-replacement-certificate')
  ),
  CONSTRAINT security_recovery_authorizations_reason CHECK (
    reason_code IN ('ACCESS_RECOVERY_ELIGIBLE', 'REPLACEMENT_ELIGIBLE')
  ),
  CONSTRAINT security_recovery_authorizations_version CHECK (expected_state_version > 0),
  CONSTRAINT security_recovery_authorizations_hash CHECK (
    step_up_proof_id_hash_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT security_recovery_authorizations_resolution CHECK (
    cause_resolution_reference IS NULL
    OR cause_resolution_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$'
  ),
  CONSTRAINT security_recovery_authorizations_lifetime CHECK (
    expires_at = authorized_at + interval '300 seconds'
  )
);

CREATE INDEX security_recovery_authorizations_target_history
  ON orchestration.security_recovery_authorizations (
    tenant_id, target_subject_id, target_certificate_id, authorized_at DESC
  );

CREATE FUNCTION orchestration.get_security_recovery_context(
  p_target_subject_id identity.subject_id,
  p_target_certificate_id identity.certificate_id
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  target_subject_id identity.subject_id,
  target_certificate_id identity.certificate_id,
  state_version bigint,
  access_state orchestration.access_state,
  renewal_state orchestration.renewal_state,
  target_certificate_state orchestration.target_certificate_state,
  replacement_state orchestration.replacement_state,
  trust_transition_id trust.transition_id,
  score numeric,
  band text,
  transition text,
  consecutive_qualifying_evaluations integer,
  source_ids text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
BEGIN
  IF v_tenant_id IS NULL OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'RECOVERY_TENANT_ADMIN_REQUIRED';
  END IF;
  RETURN QUERY
  SELECT state.tenant_id, state.subject_id, state.certificate_id,
    state.state_version, state.access_state, state.renewal_state,
    state.target_certificate_state, state.replacement_state,
    transition.transition_id, transition.new_score, transition.new_band,
    transition.transition_kind,
    CASE WHEN transition.transition_kind = 'recovered'
      THEN COALESCE((transition.explanation_json::jsonb #>>
        '{transitionControl,recovery,requiredQualifyingStreak}')::integer, 0)
      ELSE transition.new_recovery_streak::integer END,
    ARRAY(
      SELECT jsonb_array_elements_text(COALESCE(
        transition.explanation_json::jsonb #>
          '{transitionControl,sourceInfluence,distinctSourceIds}', '[]'::jsonb
      )) ORDER BY 1
    )
  FROM orchestration.subject_security_states AS state
  JOIN trust.subject_trust_transition_current AS current_transition
    ON current_transition.tenant_id = state.tenant_id
   AND current_transition.subject_id = state.subject_id
  JOIN trust.subject_trust_transitions AS transition
    ON transition.tenant_id = current_transition.tenant_id
   AND transition.transition_id = current_transition.transition_id
  WHERE state.tenant_id = v_tenant_id
    AND state.subject_id = p_target_subject_id
    AND state.certificate_id = p_target_certificate_id;
END
$function$;

CREATE FUNCTION orchestration.authorize_security_recovery(
  p_authorization_id orchestration.recovery_authorization_id,
  p_action_id audit.security_action_id,
  p_decision_id audit.policy_decision_id,
  p_request_id identity.request_id,
  p_correlation_id identity.correlation_id,
  p_idempotency_key identity.idempotency_key,
  p_target_subject_id identity.subject_id,
  p_target_certificate_id identity.certificate_id,
  p_action_type orchestration.security_action_type,
  p_trust_transition_id trust.transition_id,
  p_expected_state_version bigint,
  p_reason_code text,
  p_eligibility_hash_sha256 identity.sha256_digest,
  p_step_up_proof_id_hash_sha256 text,
  p_session_id_hash_sha256 text,
  p_cause_resolution_reference text,
  p_authorized_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  authorization_id orchestration.recovery_authorization_id,
  action_id audit.security_action_id,
  action_type orchestration.security_action_type,
  status orchestration.action_execution_status,
  authorized_at timestamptz,
  expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, identity, trust, audit
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_actor_id identity.subject_id := identity.current_subject_id();
  v_state orchestration.subject_security_states%ROWTYPE;
  v_transition trust.subject_trust_transitions%ROWTYPE;
  v_existing orchestration.security_recovery_authorizations%ROWTYPE;
  v_authorization orchestration.security_recovery_authorizations%ROWTYPE;
  v_action orchestration.security_actions%ROWTYPE;
  v_distinct_sources integer;
  v_required_streak integer;
  v_proof_count integer;
  v_minimum_score numeric;
  v_minimum_band text;
BEGIN
  SELECT * INTO v_existing
  FROM orchestration.security_recovery_authorizations AS recovery_auth
  WHERE recovery_auth.tenant_id = v_tenant_id
    AND recovery_auth.authorized_by_subject_id = v_actor_id
    AND recovery_auth.idempotency_key = p_idempotency_key;
  IF FOUND THEN
    IF v_existing.request_id <> p_request_id
       OR v_existing.target_subject_id <> p_target_subject_id
       OR v_existing.target_certificate_id <> p_target_certificate_id
       OR v_existing.action_type <> p_action_type
       OR v_existing.trust_transition_id <> p_trust_transition_id
       OR v_existing.expected_state_version <> p_expected_state_version
       OR v_existing.reason_code <> p_reason_code
       OR v_existing.eligibility_hash_sha256 <> p_eligibility_hash_sha256
       OR v_existing.cause_resolution_reference IS DISTINCT FROM p_cause_resolution_reference THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'RECOVERY_IDEMPOTENCY_CONFLICT';
    END IF;
    SELECT * INTO v_action FROM orchestration.security_actions AS action
    WHERE action.tenant_id = v_existing.tenant_id AND action.action_id = v_existing.action_id;
    RETURN QUERY SELECT v_existing.tenant_id, v_existing.authorization_id,
      v_existing.action_id, v_existing.action_type, v_action.status,
      v_existing.authorized_at, v_existing.expires_at;
    RETURN;
  END IF;

  IF v_tenant_id IS NULL OR v_actor_id IS NULL
     OR NOT identity.current_actor_is_tenant_admin()
     OR p_action_type NOT IN ('restore-access', 'issue-replacement-certificate')
     OR p_reason_code NOT IN ('ACCESS_RECOVERY_ELIGIBLE', 'REPLACEMENT_ELIGIBLE')
     OR p_step_up_proof_id_hash_sha256 !~ '^[0-9a-f]{64}$'
     OR p_session_id_hash_sha256 !~ '^[0-9a-f]{64}$'
     OR p_authorized_at IS NULL
     OR p_authorized_at > clock_timestamp() + interval '2 seconds'
     OR p_authorized_at < clock_timestamp() - interval '5 minutes' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'RECOVERY_AUTHORIZATION_DENIED';
  END IF;

  SELECT * INTO v_state FROM orchestration.subject_security_states AS state
  WHERE state.tenant_id = v_tenant_id
    AND state.subject_id = p_target_subject_id
    AND state.certificate_id = p_target_certificate_id
  FOR UPDATE;
  IF NOT FOUND OR v_state.state_version <> p_expected_state_version THEN
    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'RECOVERY_STATE_CHANGED';
  END IF;

  SELECT transition.* INTO v_transition
  FROM trust.subject_trust_transition_current AS current_transition
  JOIN trust.subject_trust_transitions AS transition
    ON transition.tenant_id = current_transition.tenant_id
   AND transition.transition_id = current_transition.transition_id
  WHERE current_transition.tenant_id = v_tenant_id
    AND current_transition.subject_id = p_target_subject_id
    AND current_transition.transition_id = p_trust_transition_id;
  IF NOT FOUND OR v_transition.transition_kind <> 'recovered'
     OR p_authorized_at < v_transition.evaluated_at
     OR p_authorized_at > v_transition.evaluated_at + interval '5 minutes' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'TRUST_RECOVERY_INCOMPLETE';
  END IF;

  v_distinct_sources := COALESCE((v_transition.explanation_json::jsonb #>>
    '{transitionControl,recovery,distinctSourceCount}')::integer, 0);
  v_required_streak := COALESCE((v_transition.explanation_json::jsonb #>>
    '{transitionControl,recovery,requiredQualifyingStreak}')::integer, 0);
  IF v_distinct_sources < 2 OR v_required_streak < 2
     OR COALESCE((v_transition.explanation_json::jsonb #>>
       '{transitionControl,recovery,eligible}')::boolean, false) IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'TRUST_RECOVERY_INCOMPLETE';
  END IF;

  IF v_state.target_certificate_state = 'revoked'
     OR v_state.access_state = 'suspended'
     OR v_state.renewal_state = 'blocked' THEN
    v_minimum_band := 'high';
    v_minimum_score := 75;
  ELSE
    v_minimum_band := 'medium';
    v_minimum_score := 45;
  END IF;
  IF v_transition.new_score < v_minimum_score
     OR (v_minimum_band = 'high' AND v_transition.new_band <> 'high')
     OR (v_minimum_band = 'medium' AND v_transition.new_band NOT IN ('medium', 'high')) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'TRUST_RECOVERY_INCOMPLETE';
  END IF;

  IF p_action_type = 'issue-replacement-certificate' THEN
    IF v_state.target_certificate_state <> 'revoked'
       OR v_state.replacement_state <> 'required'
       OR p_reason_code <> 'REPLACEMENT_ELIGIBLE'
       OR p_cause_resolution_reference IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'RECOVERY_CONDITIONS_NOT_MET';
    END IF;
  ELSIF v_state.access_state = 'normal' AND v_state.renewal_state = 'allowed' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'NO_RECOVERY_NEEDED';
  ELSIF v_state.target_certificate_state = 'revoked'
        AND (v_state.replacement_state <> 'issued'
          OR p_cause_resolution_reference IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'REPLACEMENT_REQUIRED_BEFORE_RECOVERY';
  END IF;

  IF v_state.target_certificate_state = 'revoked' AND NOT EXISTS (
    SELECT 1 FROM identity.certificates AS certificate
    WHERE certificate.tenant_id = v_tenant_id
      AND certificate.certificate_id = p_target_certificate_id
      AND certificate.subject_id = p_target_subject_id
      AND certificate.state = 'revoked'
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'REVOKED_TARGET_REQUIRED';
  END IF;

  SELECT count(*) INTO v_proof_count FROM audit.consume_step_up_proof(
    p_step_up_proof_id_hash_sha256, p_session_id_hash_sha256,
    'tenant:admin', p_request_id::text, p_authorized_at
  );
  IF v_proof_count <> 1 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'RECOVERY_STEP_UP_REQUIRED';
  END IF;

  v_action := orchestration.enqueue_security_action_internal(
    v_tenant_id, p_action_id, p_decision_id, p_correlation_id,
    p_target_subject_id, p_target_certificate_id, p_action_type,
    'recovery-authorization', p_reason_code, p_eligibility_hash_sha256,
    p_authorized_at
  );
  INSERT INTO orchestration.security_recovery_authorizations (
    tenant_id, authorization_id, action_id, decision_id, request_id,
    correlation_id, idempotency_key, authorized_by_subject_id,
    target_subject_id, target_certificate_id, action_type, trust_transition_id,
    expected_state_version, reason_code, eligibility_hash_sha256,
    step_up_proof_id_hash_sha256, cause_resolution_reference,
    authorized_at, expires_at
  ) VALUES (
    v_tenant_id, p_authorization_id, v_action.action_id, p_decision_id,
    p_request_id, p_correlation_id, p_idempotency_key, v_actor_id,
    p_target_subject_id, p_target_certificate_id, p_action_type,
    p_trust_transition_id, p_expected_state_version, p_reason_code,
    p_eligibility_hash_sha256, p_step_up_proof_id_hash_sha256,
    p_cause_resolution_reference, p_authorized_at,
    p_authorized_at + interval '300 seconds'
  ) RETURNING * INTO v_authorization;
  RETURN QUERY SELECT v_authorization.tenant_id, v_authorization.authorization_id,
    v_authorization.action_id, v_authorization.action_type, v_action.status,
    v_authorization.authorized_at, v_authorization.expires_at;
END
$function$;

DROP FUNCTION orchestration.claim_security_action(text, text, timestamptz);

CREATE FUNCTION orchestration.claim_security_action(
  p_worker_id text,
  p_claim_token text,
  p_claimed_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id, action_id audit.security_action_id,
  decision_id audit.policy_decision_id, correlation_id identity.correlation_id,
  target_subject_id identity.subject_id, target_certificate_id identity.certificate_id,
  action_type orchestration.security_action_type,
  authority_class orchestration.action_authority_class, reason_code text,
  trigger_context_hash_sha256 identity.sha256_digest, claim_token text,
  attempt_count integer, expected_state_version bigint,
  access_state orchestration.access_state, renewal_state orchestration.renewal_state,
  target_certificate_state orchestration.target_certificate_state,
  replacement_state orchestration.replacement_state,
  recovery_authorization_id orchestration.recovery_authorization_id,
  recovery_authorized_by_subject_id identity.subject_id,
  recovery_authorized_until timestamptz,
  cause_resolution_reference text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration
SET row_security = off
AS $function$
DECLARE
  v_action orchestration.security_actions%ROWTYPE;
  v_state orchestration.subject_security_states%ROWTYPE;
  v_authorization orchestration.security_recovery_authorizations%ROWTYPE;
BEGIN
  IF p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
     OR p_claim_token !~ '^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_claimed_at IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_CLAIM_INVALID';
  END IF;

  UPDATE orchestration.security_action_attempts AS attempt SET
    status = 'failed', completed_at = p_claimed_at, failure_code = 'ACTION_LEASE_EXPIRED'
  FROM orchestration.security_actions AS action
  WHERE action.tenant_id = attempt.tenant_id AND action.action_id = attempt.action_id
    AND action.status = 'executing' AND action.lease_expires_at <= p_claimed_at
    AND attempt.attempt_number = action.attempt_count AND attempt.status = 'executing';
  UPDATE orchestration.security_actions SET
    status = 'failed', claimed_by = NULL, claim_token = NULL, claimed_at = NULL,
    lease_expires_at = NULL, last_failure_code = 'ACTION_LEASE_EXPIRED',
    next_attempt_at = p_claimed_at, updated_at = p_claimed_at
  WHERE status = 'executing' AND lease_expires_at <= p_claimed_at;

  SELECT action.* INTO v_action
  FROM orchestration.security_actions AS action
  WHERE action.status IN ('pending', 'failed') AND action.next_attempt_at <= p_claimed_at
    AND (action.authority_class <> 'recovery-authorization' OR EXISTS (
      SELECT 1 FROM orchestration.security_recovery_authorizations AS recovery_auth
      WHERE recovery_auth.tenant_id = action.tenant_id
        AND recovery_auth.action_id = action.action_id
        AND recovery_auth.expires_at >= p_claimed_at
    ))
    AND NOT EXISTS (
      SELECT 1 FROM orchestration.security_actions AS active
      WHERE active.tenant_id = action.tenant_id
        AND active.target_subject_id = action.target_subject_id
        AND active.target_certificate_id = action.target_certificate_id
        AND active.status = 'executing'
    )
  ORDER BY action.next_attempt_at, action.requested_at, action.action_id
  FOR UPDATE SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT * INTO v_state FROM orchestration.subject_security_states
  WHERE subject_security_states.tenant_id = v_action.tenant_id
    AND subject_security_states.subject_id = v_action.target_subject_id
    AND subject_security_states.certificate_id = v_action.target_certificate_id
  FOR UPDATE;
  IF v_action.authority_class = 'recovery-authorization' THEN
    SELECT * INTO v_authorization
    FROM orchestration.security_recovery_authorizations AS recovery_auth
    WHERE recovery_auth.tenant_id = v_action.tenant_id
      AND recovery_auth.action_id = v_action.action_id;
  END IF;

  UPDATE orchestration.security_actions SET
    status = 'executing', attempt_count = orchestration.security_actions.attempt_count + 1,
    expected_state_version = v_state.state_version, claimed_by = p_worker_id,
    claim_token = p_claim_token, claimed_at = p_claimed_at,
    lease_expires_at = p_claimed_at + interval '300 seconds',
    last_failure_code = NULL, updated_at = p_claimed_at
  WHERE security_actions.tenant_id = v_action.tenant_id
    AND security_actions.action_id = v_action.action_id
  RETURNING * INTO v_action;

  INSERT INTO orchestration.security_action_attempts (
    tenant_id, action_id, attempt_number, claim_token, worker_id, status, started_at
  ) VALUES (
    v_action.tenant_id, v_action.action_id, v_action.attempt_count,
    p_claim_token, p_worker_id, 'executing', p_claimed_at
  );

  RETURN QUERY SELECT v_action.tenant_id, v_action.action_id, v_action.decision_id,
    v_action.correlation_id, v_action.target_subject_id, v_action.target_certificate_id,
    v_action.action_type, v_action.authority_class, v_action.reason_code,
    v_action.trigger_context_hash_sha256, v_action.claim_token, v_action.attempt_count,
    v_action.expected_state_version, v_state.access_state, v_state.renewal_state,
    v_state.target_certificate_state, v_state.replacement_state,
    v_authorization.authorization_id, v_authorization.authorized_by_subject_id,
    v_authorization.expires_at, v_authorization.cause_resolution_reference;
END
$function$;

CREATE OR REPLACE FUNCTION orchestration.mark_security_action_succeeded(
  p_tenant_id identity.tenant_id,
  p_action_id audit.security_action_id,
  p_claim_token text,
  p_result_state jsonb,
  p_external_reference text,
  p_succeeded_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id, action_id audit.security_action_id,
  status orchestration.action_execution_status, attempt_count integer,
  last_failure_code text, next_attempt_at timestamptz, succeeded_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, identity
SET row_security = off
AS $function$
DECLARE
  v_action orchestration.security_actions%ROWTYPE;
  v_state orchestration.subject_security_states%ROWTYPE;
  v_authorization orchestration.security_recovery_authorizations%ROWTYPE;
  v_expected jsonb;
BEGIN
  SELECT * INTO v_action FROM orchestration.security_actions
  WHERE security_actions.tenant_id = p_tenant_id AND security_actions.action_id = p_action_id
  FOR UPDATE;
  IF NOT FOUND OR v_action.status <> 'executing' OR v_action.claim_token <> p_claim_token
     OR v_action.lease_expires_at < p_succeeded_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SECURITY_ACTION_CLAIM_CONFLICT';
  END IF;
  SELECT * INTO v_state FROM orchestration.subject_security_states
  WHERE subject_security_states.tenant_id = v_action.tenant_id
    AND subject_security_states.subject_id = v_action.target_subject_id
    AND subject_security_states.certificate_id = v_action.target_certificate_id
  FOR UPDATE;
  IF v_state.state_version <> v_action.expected_state_version THEN
    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'SECURITY_ACTION_STATE_CONFLICT';
  END IF;

  v_expected := jsonb_build_object(
    'access', CASE v_action.action_type
      WHEN 'restrict-access' THEN CASE WHEN v_state.access_state = 'normal' THEN 'restricted' ELSE v_state.access_state::text END
      WHEN 'suspend-subject' THEN 'suspended'
      WHEN 'revoke-certificate' THEN 'suspended'
      WHEN 'restore-access' THEN 'normal'
      ELSE v_state.access_state::text END,
    'renewal', CASE v_action.action_type
      WHEN 'suspend-subject' THEN 'blocked'
      WHEN 'block-renewal' THEN 'blocked'
      WHEN 'revoke-certificate' THEN 'blocked'
      WHEN 'restore-access' THEN 'allowed'
      ELSE v_state.renewal_state::text END,
    'targetCertificate', CASE WHEN v_action.action_type = 'revoke-certificate'
      THEN 'revoked' ELSE v_state.target_certificate_state::text END,
    'replacement', CASE
      WHEN v_action.action_type = 'revoke-certificate'
        AND v_state.target_certificate_state <> 'revoked' THEN 'required'
      WHEN v_action.action_type = 'issue-replacement-certificate' THEN 'issued'
      ELSE v_state.replacement_state::text END
  );
  IF p_result_state IS DISTINCT FROM v_expected THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_RESULT_INVALID';
  END IF;

  IF v_action.authority_class = 'recovery-authorization' THEN
    SELECT * INTO v_authorization
    FROM orchestration.security_recovery_authorizations AS recovery_auth
    WHERE recovery_auth.tenant_id = v_action.tenant_id
      AND recovery_auth.action_id = v_action.action_id
    FOR SHARE;
    IF NOT FOUND OR v_authorization.action_type <> v_action.action_type
       OR v_authorization.expires_at < p_succeeded_at THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'RECOVERY_AUTHORIZATION_INVALID';
    END IF;
    IF v_action.action_type = 'issue-replacement-certificate' THEN
      IF p_external_reference IS NULL
         OR p_external_reference !~ '^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
         OR p_external_reference = v_action.target_certificate_id::text
         OR NOT EXISTS (
           SELECT 1 FROM identity.certificates AS replacement
           WHERE replacement.tenant_id = v_action.tenant_id
             AND replacement.certificate_id = p_external_reference::identity.certificate_id
             AND replacement.subject_id = v_action.target_subject_id
             AND replacement.state = 'active'
             AND replacement.issued_at >= v_authorization.authorized_at
             AND replacement.requested_by_subject_id = v_authorization.authorized_by_subject_id
         ) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'REPLACEMENT_ISSUANCE_UNCONFIRMED';
      END IF;
    ELSIF p_external_reference IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_RESULT_INVALID';
    END IF;
  ELSIF v_action.action_type IN ('restore-access', 'issue-replacement-certificate') THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'RECOVERY_AUTHORIZATION_REQUIRED';
  END IF;

  IF v_action.action_type = 'revoke-certificate' AND NOT EXISTS (
    SELECT 1 FROM identity.certificates AS certificate
    WHERE certificate.tenant_id = v_action.tenant_id
      AND certificate.certificate_id = v_action.target_certificate_id
      AND certificate.state = 'revoked'
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'REVOCATION_EXECUTION_UNCONFIRMED';
  END IF;
  IF v_state.target_certificate_state = 'revoked' AND NOT EXISTS (
    SELECT 1 FROM identity.certificates AS certificate
    WHERE certificate.tenant_id = v_action.tenant_id
      AND certificate.certificate_id = v_action.target_certificate_id
      AND certificate.state = 'revoked'
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'REVOKED_TARGET_CHANGED';
  END IF;

  UPDATE orchestration.subject_security_states SET
    access_state = (p_result_state ->> 'access')::orchestration.access_state,
    renewal_state = (p_result_state ->> 'renewal')::orchestration.renewal_state,
    target_certificate_state = (p_result_state ->> 'targetCertificate')::orchestration.target_certificate_state,
    replacement_state = (p_result_state ->> 'replacement')::orchestration.replacement_state,
    state_version = state_version + 1, last_action_id = v_action.action_id,
    updated_at = p_succeeded_at
  WHERE subject_security_states.tenant_id = v_action.tenant_id
    AND subject_security_states.subject_id = v_action.target_subject_id
    AND subject_security_states.certificate_id = v_action.target_certificate_id;
  UPDATE orchestration.security_action_attempts SET status = 'succeeded',
    completed_at = p_succeeded_at, external_reference = p_external_reference
  WHERE security_action_attempts.tenant_id = v_action.tenant_id
    AND security_action_attempts.action_id = v_action.action_id
    AND attempt_number = v_action.attempt_count AND claim_token = p_claim_token;
  UPDATE orchestration.security_actions SET status = 'succeeded',
    claimed_by = NULL, claim_token = NULL, claimed_at = NULL, lease_expires_at = NULL,
    external_reference = p_external_reference, result_state = p_result_state,
    succeeded_at = p_succeeded_at, updated_at = p_succeeded_at
  WHERE security_actions.tenant_id = v_action.tenant_id
    AND security_actions.action_id = v_action.action_id
  RETURNING * INTO v_action;
  RETURN QUERY SELECT v_action.tenant_id, v_action.action_id, v_action.status,
    v_action.attempt_count, v_action.last_failure_code, v_action.next_attempt_at,
    v_action.succeeded_at;
END
$function$;

ALTER TABLE orchestration.security_recovery_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE orchestration.security_recovery_authorizations FORCE ROW LEVEL SECURITY;

GRANT USAGE ON SCHEMA orchestration TO tenant_trust_app;
REVOKE ALL ON TABLE orchestration.security_recovery_authorizations FROM PUBLIC,
  tenant_trust_app, tenant_trust_security_action_requester,
  tenant_trust_security_action_worker, tenant_trust_security_invalidation_worker;
REVOKE ALL ON FUNCTION orchestration.get_security_recovery_context(
  identity.subject_id, identity.certificate_id
) FROM PUBLIC;
REVOKE ALL ON FUNCTION orchestration.authorize_security_recovery(
  orchestration.recovery_authorization_id, audit.security_action_id,
  audit.policy_decision_id, identity.request_id, identity.correlation_id,
  identity.idempotency_key, identity.subject_id, identity.certificate_id,
  orchestration.security_action_type, trust.transition_id, bigint, text,
  identity.sha256_digest, text, text, text, timestamptz
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION orchestration.get_security_recovery_context(
  identity.subject_id, identity.certificate_id
), orchestration.authorize_security_recovery(
  orchestration.recovery_authorization_id, audit.security_action_id,
  audit.policy_decision_id, identity.request_id, identity.correlation_id,
  identity.idempotency_key, identity.subject_id, identity.certificate_id,
  orchestration.security_action_type, trust.transition_id, bigint, text,
  identity.sha256_digest, text, text, text, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION orchestration.claim_security_action(text, text, timestamptz)
  TO tenant_trust_security_action_worker;

COMMENT ON TABLE orchestration.security_recovery_authorizations IS
  'Append-only tenant-admin step-up authorizations bound to current trust recovery and security-action state';
COMMENT ON COLUMN orchestration.security_recovery_authorizations.cause_resolution_reference IS
  'External case or evidence reference attesting that the severe revocation cause was resolved';
