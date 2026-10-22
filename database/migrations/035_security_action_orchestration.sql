CREATE SCHEMA orchestration;

CREATE TYPE orchestration.security_action_type AS ENUM (
  'restrict-access', 'suspend-subject', 'block-renewal', 'revoke-certificate',
  'restore-access', 'issue-replacement-certificate'
);
CREATE TYPE orchestration.action_authority_class AS ENUM (
  'policy-quarantine', 'severity-rule', 'recovery-authorization'
);
CREATE TYPE orchestration.action_execution_status AS ENUM (
  'pending', 'executing', 'succeeded', 'failed'
);
CREATE TYPE orchestration.action_attempt_status AS ENUM ('executing', 'succeeded', 'failed');
CREATE TYPE orchestration.access_state AS ENUM ('normal', 'restricted', 'suspended');
CREATE TYPE orchestration.renewal_state AS ENUM ('allowed', 'blocked');
CREATE TYPE orchestration.target_certificate_state AS ENUM ('active', 'revoked');
CREATE TYPE orchestration.replacement_state AS ENUM ('not-required', 'required', 'issued');

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_security_action_requester') THEN
    CREATE ROLE tenant_trust_security_action_requester;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_security_action_worker') THEN
    CREATE ROLE tenant_trust_security_action_worker;
  END IF;
END
$roles$;

ALTER ROLE tenant_trust_security_action_requester
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;
ALTER ROLE tenant_trust_security_action_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;

CREATE TABLE orchestration.subject_security_states (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  certificate_id identity.certificate_id NOT NULL,
  access_state orchestration.access_state NOT NULL DEFAULT 'normal',
  renewal_state orchestration.renewal_state NOT NULL DEFAULT 'allowed',
  target_certificate_state orchestration.target_certificate_state NOT NULL DEFAULT 'active',
  replacement_state orchestration.replacement_state NOT NULL DEFAULT 'not-required',
  state_version bigint NOT NULL DEFAULT 1,
  last_action_id audit.security_action_id,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT subject_security_states_pk PRIMARY KEY (tenant_id, subject_id, certificate_id),
  CONSTRAINT subject_security_states_membership_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT subject_security_states_certificate_fk FOREIGN KEY (tenant_id, certificate_id)
    REFERENCES identity.certificates (tenant_id, certificate_id) ON DELETE RESTRICT,
  CONSTRAINT subject_security_states_positive_version CHECK (state_version > 0),
  CONSTRAINT subject_security_states_replacement_shape CHECK (
    (target_certificate_state = 'active' AND replacement_state = 'not-required')
    OR target_certificate_state = 'revoked'
  )
);

CREATE TABLE orchestration.security_actions (
  tenant_id identity.tenant_id NOT NULL,
  action_id audit.security_action_id NOT NULL,
  decision_id audit.policy_decision_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  target_subject_id identity.subject_id NOT NULL,
  target_certificate_id identity.certificate_id NOT NULL,
  action_type orchestration.security_action_type NOT NULL,
  authority_class orchestration.action_authority_class NOT NULL,
  reason_code text NOT NULL,
  trigger_context_hash_sha256 identity.sha256_digest NOT NULL,
  status orchestration.action_execution_status NOT NULL DEFAULT 'pending',
  attempt_count integer NOT NULL DEFAULT 0,
  expected_state_version bigint NOT NULL,
  claimed_by text,
  claim_token text,
  claimed_at timestamptz,
  lease_expires_at timestamptz,
  next_attempt_at timestamptz NOT NULL,
  last_failure_code text,
  external_reference text,
  result_state jsonb,
  requested_at timestamptz NOT NULL,
  succeeded_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT security_actions_pk PRIMARY KEY (tenant_id, action_id),
  CONSTRAINT security_actions_semantic_unique UNIQUE (
    tenant_id, decision_id, action_type, authority_class
  ),
  CONSTRAINT security_actions_target_fk FOREIGN KEY (
    tenant_id, target_subject_id, target_certificate_id
  ) REFERENCES orchestration.subject_security_states (
    tenant_id, subject_id, certificate_id
  ) ON DELETE RESTRICT,
  CONSTRAINT security_actions_reason CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  CONSTRAINT security_actions_claim_token CHECK (
    claim_token IS NULL OR claim_token ~ '^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CONSTRAINT security_actions_worker CHECK (
    claimed_by IS NULL OR claimed_by ~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
  ),
  CONSTRAINT security_actions_counts CHECK (attempt_count >= 0 AND expected_state_version > 0),
  CONSTRAINT security_actions_failure CHECK (
    last_failure_code IS NULL OR last_failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT security_actions_external_reference CHECK (
    external_reference IS NULL OR external_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$'
  ),
  CONSTRAINT security_actions_authority CHECK (
    (authority_class = 'policy-quarantine' AND action_type IN ('restrict-access', 'suspend-subject'))
    OR (authority_class = 'severity-rule' AND action_type IN ('block-renewal', 'revoke-certificate'))
    OR (authority_class = 'recovery-authorization' AND action_type IN ('restore-access', 'issue-replacement-certificate'))
  ),
  CONSTRAINT security_actions_execution_shape CHECK (
    (status = 'executing' AND claimed_by IS NOT NULL AND claim_token IS NOT NULL
      AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status <> 'executing' AND claimed_by IS NULL AND claim_token IS NULL
      AND claimed_at IS NULL AND lease_expires_at IS NULL)
  ),
  CONSTRAINT security_actions_success_shape CHECK (
    (status = 'succeeded' AND succeeded_at IS NOT NULL AND result_state IS NOT NULL)
    OR (status <> 'succeeded' AND succeeded_at IS NULL)
  )
);

CREATE UNIQUE INDEX security_actions_one_executing_per_target
  ON orchestration.security_actions (tenant_id, target_subject_id, target_certificate_id)
  WHERE status = 'executing';
CREATE INDEX security_actions_claim_order
  ON orchestration.security_actions (next_attempt_at, requested_at, action_id)
  WHERE status IN ('pending', 'failed');

CREATE TABLE orchestration.security_action_attempts (
  tenant_id identity.tenant_id NOT NULL,
  action_id audit.security_action_id NOT NULL,
  attempt_number integer NOT NULL,
  claim_token text NOT NULL,
  worker_id text NOT NULL,
  status orchestration.action_attempt_status NOT NULL,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  failure_code text,
  external_reference text,
  CONSTRAINT security_action_attempts_pk PRIMARY KEY (tenant_id, action_id, attempt_number),
  CONSTRAINT security_action_attempts_action_fk FOREIGN KEY (tenant_id, action_id)
    REFERENCES orchestration.security_actions (tenant_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT security_action_attempts_claim_unique UNIQUE (tenant_id, claim_token),
  CONSTRAINT security_action_attempts_completion CHECK (
    (status = 'executing' AND completed_at IS NULL AND failure_code IS NULL)
    OR (status = 'succeeded' AND completed_at IS NOT NULL AND failure_code IS NULL)
    OR (status = 'failed' AND completed_at IS NOT NULL
      AND failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$')
  )
);

CREATE FUNCTION orchestration.enqueue_security_action_internal(
  p_tenant_id identity.tenant_id,
  p_action_id audit.security_action_id,
  p_decision_id audit.policy_decision_id,
  p_correlation_id identity.correlation_id,
  p_target_subject_id identity.subject_id,
  p_target_certificate_id identity.certificate_id,
  p_action_type orchestration.security_action_type,
  p_authority_class orchestration.action_authority_class,
  p_reason_code text,
  p_trigger_context_hash_sha256 identity.sha256_digest,
  p_requested_at timestamptz
)
RETURNS orchestration.security_actions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, identity, audit
SET row_security = off
AS $function$
DECLARE
  v_state orchestration.subject_security_states%ROWTYPE;
  v_existing orchestration.security_actions%ROWTYPE;
  v_created orchestration.security_actions%ROWTYPE;
BEGIN
  IF p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_requested_at IS NULL
     OR p_requested_at > clock_timestamp() + interval '2 seconds'
     OR p_requested_at < clock_timestamp() - interval '5 minutes' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_REQUEST_INVALID';
  END IF;

  INSERT INTO orchestration.subject_security_states (
    tenant_id, subject_id, certificate_id, target_certificate_state
  )
  SELECT certificate.tenant_id, certificate.subject_id, certificate.certificate_id,
    CASE WHEN certificate.state = 'revoked' THEN 'revoked'::orchestration.target_certificate_state
      ELSE 'active'::orchestration.target_certificate_state END
  FROM identity.certificates AS certificate
  WHERE certificate.tenant_id = p_tenant_id
    AND certificate.subject_id = p_target_subject_id
    AND certificate.certificate_id = p_target_certificate_id
  ON CONFLICT (tenant_id, subject_id, certificate_id) DO NOTHING;

  SELECT * INTO v_state FROM orchestration.subject_security_states
  WHERE tenant_id = p_tenant_id AND subject_id = p_target_subject_id
    AND certificate_id = p_target_certificate_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'SECURITY_ACTION_TARGET_INVALID';
  END IF;

  SELECT * INTO v_existing FROM orchestration.security_actions
  WHERE tenant_id = p_tenant_id AND decision_id = p_decision_id
    AND action_type = p_action_type AND authority_class = p_authority_class;
  IF FOUND THEN
    IF v_existing.action_id <> p_action_id
       OR v_existing.correlation_id <> p_correlation_id
       OR v_existing.target_subject_id <> p_target_subject_id
       OR v_existing.target_certificate_id <> p_target_certificate_id
       OR v_existing.reason_code <> p_reason_code
       OR v_existing.trigger_context_hash_sha256 <> p_trigger_context_hash_sha256 THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SECURITY_ACTION_IDEMPOTENCY_CONFLICT';
    END IF;
    RETURN v_existing;
  END IF;

  INSERT INTO orchestration.security_actions (
    tenant_id, action_id, decision_id, correlation_id, target_subject_id,
    target_certificate_id, action_type, authority_class, reason_code,
    trigger_context_hash_sha256, expected_state_version, next_attempt_at, requested_at
  ) VALUES (
    p_tenant_id, p_action_id, p_decision_id, p_correlation_id, p_target_subject_id,
    p_target_certificate_id, p_action_type, p_authority_class, p_reason_code,
    p_trigger_context_hash_sha256, v_state.state_version, p_requested_at, p_requested_at
  ) RETURNING * INTO v_created;
  RETURN v_created;
END
$function$;

CREATE FUNCTION orchestration.capture_quarantine_action_request()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, identity, audit
SET row_security = off
AS $function$
BEGIN
  PERFORM orchestration.enqueue_security_action_internal(
    NEW.tenant_id, NEW.action_id, NEW.decision_id, NEW.correlation_id,
    NEW.target_subject_id, NEW.target_certificate_id,
    NEW.action_type::text::orchestration.security_action_type,
    'policy-quarantine', NEW.reason_code, NEW.policy_input_hash_sha256, NEW.requested_at
  );
  RETURN NEW;
END
$function$;

CREATE TRIGGER security_action_requests_enqueue_execution
AFTER INSERT ON audit.security_action_requests
FOR EACH ROW EXECUTE FUNCTION orchestration.capture_quarantine_action_request();

INSERT INTO orchestration.security_actions
SELECT queued.* FROM audit.security_action_requests AS request
CROSS JOIN LATERAL orchestration.enqueue_security_action_internal(
  request.tenant_id, request.action_id, request.decision_id, request.correlation_id,
  request.target_subject_id, request.target_certificate_id,
  request.action_type::text::orchestration.security_action_type,
  'policy-quarantine', request.reason_code, request.policy_input_hash_sha256, request.requested_at
) AS queued
ON CONFLICT DO NOTHING;

CREATE FUNCTION orchestration.enqueue_severity_security_action(
  p_tenant_id identity.tenant_id,
  p_action_id audit.security_action_id,
  p_decision_id audit.policy_decision_id,
  p_target_subject_id identity.subject_id,
  p_target_certificate_id identity.certificate_id,
  p_action_type orchestration.security_action_type,
  p_reason_code text,
  p_trigger_context_hash_sha256 identity.sha256_digest,
  p_requested_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id, action_id audit.security_action_id,
  status orchestration.action_execution_status, attempt_count integer,
  last_failure_code text, next_attempt_at timestamptz, succeeded_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, audit, identity
SET row_security = off
AS $function$
DECLARE
  v_provenance audit.policy_decision_provenance%ROWTYPE;
  v_action orchestration.security_actions%ROWTYPE;
BEGIN
  IF p_action_type NOT IN ('block-renewal', 'revoke-certificate') THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_REQUEST_INVALID';
  END IF;
  SELECT * INTO v_provenance FROM audit.policy_decision_provenance AS provenance
  WHERE provenance.tenant_id = p_tenant_id AND provenance.decision_id = p_decision_id
    AND provenance.actor_subject_id = p_target_subject_id
    AND provenance.certificate_id = p_target_certificate_id
    AND provenance.outcome = 'QUARANTINE'
    AND provenance.trust_transition_id IS NOT NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'SECURITY_ACTION_PROVENANCE_REQUIRED';
  END IF;
  v_action := orchestration.enqueue_security_action_internal(
    p_tenant_id, p_action_id, p_decision_id, v_provenance.correlation_id,
    p_target_subject_id, p_target_certificate_id, p_action_type, 'severity-rule',
    p_reason_code, p_trigger_context_hash_sha256, p_requested_at
  );
  RETURN QUERY SELECT v_action.tenant_id, v_action.action_id, v_action.status,
    v_action.attempt_count, v_action.last_failure_code, v_action.next_attempt_at,
    v_action.succeeded_at;
END
$function$;

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
  replacement_state orchestration.replacement_state
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration
SET row_security = off
AS $function$
DECLARE
  v_action orchestration.security_actions%ROWTYPE;
  v_state orchestration.subject_security_states%ROWTYPE;
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
    v_state.target_certificate_state, v_state.replacement_state;
END
$function$;

CREATE FUNCTION orchestration.mark_security_action_succeeded(
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
      ELSE v_state.access_state::text END,
    'renewal', CASE v_action.action_type
      WHEN 'suspend-subject' THEN 'blocked'
      WHEN 'block-renewal' THEN 'blocked'
      WHEN 'revoke-certificate' THEN 'blocked'
      ELSE v_state.renewal_state::text END,
    'targetCertificate', CASE WHEN v_action.action_type = 'revoke-certificate'
      THEN 'revoked' ELSE v_state.target_certificate_state::text END,
    'replacement', CASE WHEN v_action.action_type = 'revoke-certificate'
      AND v_state.target_certificate_state <> 'revoked' THEN 'required'
      ELSE v_state.replacement_state::text END
  );
  IF v_action.authority_class = 'recovery-authorization'
     OR p_result_state IS DISTINCT FROM v_expected THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_RESULT_INVALID';
  END IF;
  IF v_action.action_type = 'revoke-certificate' AND NOT EXISTS (
    SELECT 1 FROM identity.certificates AS certificate
    WHERE certificate.tenant_id = v_action.tenant_id
      AND certificate.certificate_id = v_action.target_certificate_id
      AND certificate.state = 'revoked'
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'REVOCATION_EXECUTION_UNCONFIRMED';
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

CREATE FUNCTION orchestration.mark_security_action_failed(
  p_tenant_id identity.tenant_id,
  p_action_id audit.security_action_id,
  p_claim_token text,
  p_failure_code text,
  p_failed_at timestamptz,
  p_retry_delay_seconds integer
)
RETURNS TABLE (
  tenant_id identity.tenant_id, action_id audit.security_action_id,
  status orchestration.action_execution_status, attempt_count integer,
  last_failure_code text, next_attempt_at timestamptz, succeeded_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration
SET row_security = off
AS $function$
DECLARE v_action orchestration.security_actions%ROWTYPE;
BEGIN
  IF p_failure_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_retry_delay_seconds NOT BETWEEN 1 AND 600 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_FAILURE_INVALID';
  END IF;
  SELECT * INTO v_action FROM orchestration.security_actions
  WHERE security_actions.tenant_id = p_tenant_id AND security_actions.action_id = p_action_id
  FOR UPDATE;
  IF NOT FOUND OR v_action.status <> 'executing' OR v_action.claim_token <> p_claim_token
     OR v_action.lease_expires_at < p_failed_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SECURITY_ACTION_CLAIM_CONFLICT';
  END IF;
  UPDATE orchestration.security_action_attempts SET status = 'failed',
    completed_at = p_failed_at, failure_code = p_failure_code
  WHERE security_action_attempts.tenant_id = v_action.tenant_id
    AND security_action_attempts.action_id = v_action.action_id
    AND attempt_number = v_action.attempt_count AND claim_token = p_claim_token;
  UPDATE orchestration.security_actions SET status = 'failed',
    claimed_by = NULL, claim_token = NULL, claimed_at = NULL, lease_expires_at = NULL,
    last_failure_code = p_failure_code,
    next_attempt_at = p_failed_at + make_interval(secs => p_retry_delay_seconds),
    updated_at = p_failed_at
  WHERE security_actions.tenant_id = v_action.tenant_id
    AND security_actions.action_id = v_action.action_id
  RETURNING * INTO v_action;
  RETURN QUERY SELECT v_action.tenant_id, v_action.action_id, v_action.status,
    v_action.attempt_count, v_action.last_failure_code, v_action.next_attempt_at,
    v_action.succeeded_at;
END
$function$;

CREATE FUNCTION orchestration.get_security_action_status(
  p_tenant_id identity.tenant_id,
  p_action_id audit.security_action_id
)
RETURNS TABLE (
  tenant_id identity.tenant_id, action_id audit.security_action_id,
  status orchestration.action_execution_status, attempt_count integer,
  last_failure_code text, next_attempt_at timestamptz, succeeded_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration
SET row_security = off
AS $function$
  SELECT action.tenant_id, action.action_id, action.status, action.attempt_count,
    action.last_failure_code, action.next_attempt_at, action.succeeded_at
  FROM orchestration.security_actions AS action
  WHERE action.tenant_id = p_tenant_id AND action.action_id = p_action_id;
$function$;

REVOKE ALL ON SCHEMA orchestration FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA orchestration FROM PUBLIC,
  tenant_trust_app, tenant_trust_security_action_requester,
  tenant_trust_security_action_worker;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA orchestration FROM PUBLIC;
GRANT USAGE ON SCHEMA orchestration TO tenant_trust_security_action_requester,
  tenant_trust_security_action_worker;
GRANT EXECUTE ON FUNCTION orchestration.enqueue_severity_security_action(
  identity.tenant_id, audit.security_action_id, audit.policy_decision_id,
  identity.subject_id, identity.certificate_id, orchestration.security_action_type,
  text, identity.sha256_digest, timestamptz
) TO tenant_trust_security_action_requester;
GRANT EXECUTE ON FUNCTION orchestration.claim_security_action(text, text, timestamptz),
  orchestration.mark_security_action_succeeded(
    identity.tenant_id, audit.security_action_id, text, jsonb, text, timestamptz
  ),
  orchestration.mark_security_action_failed(
    identity.tenant_id, audit.security_action_id, text, text, timestamptz, integer
  ),
  orchestration.get_security_action_status(identity.tenant_id, audit.security_action_id)
TO tenant_trust_security_action_worker;

COMMENT ON TABLE orchestration.security_actions IS
  'Durable tenant-scoped action queue keyed by the original stable authorized action ID';
COMMENT ON TABLE orchestration.security_action_attempts IS
  'Per-attempt lease and success/failure history for retryable security actions';
COMMENT ON TABLE orchestration.subject_security_states IS
  'Authoritative composite T9.1 enforcement posture advanced with optimistic version checks';
