CREATE INDEX security_recovery_authorizations_state_guard
  ON orchestration.security_recovery_authorizations (
    tenant_id, target_subject_id, target_certificate_id,
    trust_transition_id, expected_state_version, action_type
  );

CREATE FUNCTION orchestration.reject_duplicate_recovery_authorization()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration
SET row_security = off
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM orchestration.security_recovery_authorizations AS existing
    WHERE existing.tenant_id = NEW.tenant_id
      AND existing.target_subject_id = NEW.target_subject_id
      AND existing.target_certificate_id = NEW.target_certificate_id
      AND existing.trust_transition_id = NEW.trust_transition_id
      AND existing.expected_state_version = NEW.expected_state_version
      AND existing.action_type = NEW.action_type
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001',
      MESSAGE = 'RECOVERY_ALREADY_AUTHORIZED';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER security_recovery_authorizations_one_per_state
BEFORE INSERT ON orchestration.security_recovery_authorizations
FOR EACH ROW EXECUTE FUNCTION orchestration.reject_duplicate_recovery_authorization();

CREATE OR REPLACE FUNCTION orchestration.claim_security_action(
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

  -- A recovery authorization is a snapshot. It cannot follow an intervening action.
  WITH stale AS (
    UPDATE orchestration.security_actions AS action SET
      status = 'failed', attempt_count = action.attempt_count + 1,
      last_failure_code = 'RECOVERY_STATE_CHANGED',
      next_attempt_at = 'infinity'::timestamptz, updated_at = p_claimed_at
    FROM orchestration.security_recovery_authorizations AS recovery_auth,
         orchestration.subject_security_states AS state
    WHERE action.authority_class = 'recovery-authorization'
      AND action.status IN ('pending', 'failed')
      AND action.next_attempt_at <> 'infinity'::timestamptz
      AND recovery_auth.tenant_id = action.tenant_id
      AND recovery_auth.action_id = action.action_id
      AND state.tenant_id = action.tenant_id
      AND state.subject_id = action.target_subject_id
      AND state.certificate_id = action.target_certificate_id
      AND recovery_auth.expected_state_version <> state.state_version
    RETURNING action.tenant_id, action.action_id, action.attempt_count
  )
  INSERT INTO orchestration.security_action_attempts (
    tenant_id, action_id, attempt_number, claim_token, worker_id, status,
    started_at, completed_at, failure_code
  )
  SELECT stale.tenant_id, stale.action_id, stale.attempt_count,
    'clm_' || public.gen_random_uuid()::text, p_worker_id, 'failed',
    p_claimed_at, p_claimed_at, 'RECOVERY_STATE_CHANGED'
  FROM stale;

  -- A new trigger cannot reapply a control already represented by durable state.
  WITH redundant AS (
    UPDATE orchestration.security_actions AS action SET
      status = 'failed', attempt_count = action.attempt_count + 1,
      last_failure_code = 'ACTION_ALREADY_SATISFIED',
      next_attempt_at = 'infinity'::timestamptz, updated_at = p_claimed_at
    FROM orchestration.subject_security_states AS state
    WHERE action.status IN ('pending', 'failed')
      AND action.attempt_count = 0
      AND action.authority_class <> 'recovery-authorization'
      AND state.tenant_id = action.tenant_id
      AND state.subject_id = action.target_subject_id
      AND state.certificate_id = action.target_certificate_id
      AND (
        (action.action_type = 'restrict-access' AND state.access_state <> 'normal')
        OR (action.action_type = 'suspend-subject'
          AND state.access_state = 'suspended' AND state.renewal_state = 'blocked')
        OR (action.action_type = 'block-renewal' AND state.renewal_state = 'blocked')
        OR (action.action_type = 'revoke-certificate'
          AND state.target_certificate_state = 'revoked')
      )
    RETURNING action.tenant_id, action.action_id, action.attempt_count
  )
  INSERT INTO orchestration.security_action_attempts (
    tenant_id, action_id, attempt_number, claim_token, worker_id, status,
    started_at, completed_at, failure_code
  )
  SELECT redundant.tenant_id, redundant.action_id, redundant.attempt_count,
    'clm_' || public.gen_random_uuid()::text, p_worker_id, 'failed',
    p_claimed_at, p_claimed_at, 'ACTION_ALREADY_SATISFIED'
  FROM redundant;

  SELECT action.* INTO v_action
  FROM orchestration.security_actions AS action
  WHERE action.status IN ('pending', 'failed')
    AND action.next_attempt_at <= p_claimed_at
    AND (action.authority_class <> 'recovery-authorization' OR (
      EXISTS (
        SELECT 1 FROM orchestration.security_recovery_authorizations AS recovery_auth
        WHERE recovery_auth.tenant_id = action.tenant_id
          AND recovery_auth.action_id = action.action_id
          AND recovery_auth.expires_at >= p_claimed_at
      )
      AND NOT EXISTS (
        SELECT 1 FROM orchestration.security_actions AS severity
        WHERE severity.tenant_id = action.tenant_id
          AND severity.target_subject_id = action.target_subject_id
          AND severity.target_certificate_id = action.target_certificate_id
          AND severity.authority_class = 'severity-rule'
          AND severity.action_id <> action.action_id
          AND (
            severity.status IN ('pending', 'executing')
            OR (severity.status = 'failed'
              AND severity.next_attempt_at <> 'infinity'::timestamptz)
          )
      )
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
    IF NOT FOUND OR v_authorization.expected_state_version <> v_state.state_version THEN
      WITH stale AS (
        UPDATE orchestration.security_actions SET
          status = 'failed', attempt_count = orchestration.security_actions.attempt_count + 1,
          last_failure_code = 'RECOVERY_STATE_CHANGED',
          next_attempt_at = 'infinity'::timestamptz, updated_at = p_claimed_at
        WHERE security_actions.tenant_id = v_action.tenant_id
          AND security_actions.action_id = v_action.action_id
        RETURNING tenant_id, action_id, attempt_count
      )
      INSERT INTO orchestration.security_action_attempts (
        tenant_id, action_id, attempt_number, claim_token, worker_id, status,
        started_at, completed_at, failure_code
      )
      SELECT stale.tenant_id, stale.action_id, stale.attempt_count,
        'clm_' || public.gen_random_uuid()::text, p_worker_id, 'failed',
        p_claimed_at, p_claimed_at, 'RECOVERY_STATE_CHANGED'
      FROM stale;
      RETURN;
    END IF;
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

REVOKE ALL ON FUNCTION orchestration.reject_duplicate_recovery_authorization() FROM PUBLIC;
