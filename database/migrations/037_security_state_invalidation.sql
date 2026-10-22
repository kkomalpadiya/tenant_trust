CREATE TYPE orchestration.security_invalidation_status AS ENUM (
  'pending', 'executing', 'completed', 'failed'
);
CREATE TYPE orchestration.security_invalidation_attempt_status AS ENUM (
  'executing', 'completed', 'failed'
);

DO $role$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_security_invalidation_worker'
  ) THEN
    CREATE ROLE tenant_trust_security_invalidation_worker;
  END IF;
END
$role$;

ALTER ROLE tenant_trust_security_invalidation_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;

CREATE TABLE orchestration.security_state_invalidations (
  tenant_id identity.tenant_id NOT NULL,
  action_id audit.security_action_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  certificate_id identity.certificate_id NOT NULL,
  action_type orchestration.security_action_type NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  security_state_version bigint NOT NULL,
  action_succeeded_at timestamptz NOT NULL,
  status orchestration.security_invalidation_status NOT NULL DEFAULT 'pending',
  attempt_count integer NOT NULL DEFAULT 0,
  claimed_by text,
  claim_token text,
  claimed_at timestamptz,
  lease_expires_at timestamptz,
  next_attempt_at timestamptz NOT NULL,
  last_failure_code text,
  sessions_invalidated integer,
  cache_entries_invalidated integer,
  invalidated_at timestamptz,
  enforcement_delay_ms bigint,
  within_target boolean,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT security_state_invalidations_pk PRIMARY KEY (tenant_id, action_id),
  CONSTRAINT security_state_invalidations_action_fk FOREIGN KEY (tenant_id, action_id)
    REFERENCES orchestration.security_actions (tenant_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT security_state_invalidations_target_fk FOREIGN KEY (
    tenant_id, subject_id, certificate_id
  ) REFERENCES orchestration.subject_security_states (
    tenant_id, subject_id, certificate_id
  ) ON DELETE RESTRICT,
  CONSTRAINT security_state_invalidations_action CHECK (
    action_type IN ('suspend-subject', 'revoke-certificate')
  ),
  CONSTRAINT security_state_invalidations_version CHECK (security_state_version > 0),
  CONSTRAINT security_state_invalidations_counts CHECK (
    attempt_count >= 0
    AND (sessions_invalidated IS NULL OR sessions_invalidated >= 0)
    AND (cache_entries_invalidated IS NULL OR cache_entries_invalidated >= 0)
    AND (enforcement_delay_ms IS NULL OR enforcement_delay_ms >= 0)
  ),
  CONSTRAINT security_state_invalidations_worker CHECK (
    claimed_by IS NULL OR claimed_by ~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
  ),
  CONSTRAINT security_state_invalidations_claim CHECK (
    claim_token IS NULL OR claim_token ~ '^icl_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CONSTRAINT security_state_invalidations_failure CHECK (
    last_failure_code IS NULL OR last_failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT security_state_invalidations_execution_shape CHECK (
    (status = 'executing' AND claimed_by IS NOT NULL AND claim_token IS NOT NULL
      AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status <> 'executing' AND claimed_by IS NULL AND claim_token IS NULL
      AND claimed_at IS NULL AND lease_expires_at IS NULL)
  ),
  CONSTRAINT security_state_invalidations_completion_shape CHECK (
    (status = 'completed' AND sessions_invalidated IS NOT NULL
      AND cache_entries_invalidated IS NOT NULL AND invalidated_at IS NOT NULL
      AND enforcement_delay_ms IS NOT NULL AND within_target IS NOT NULL
      AND completed_at IS NOT NULL)
    OR (status <> 'completed' AND sessions_invalidated IS NULL
      AND cache_entries_invalidated IS NULL AND invalidated_at IS NULL
      AND enforcement_delay_ms IS NULL AND within_target IS NULL
      AND completed_at IS NULL)
  )
);

CREATE UNIQUE INDEX security_state_invalidations_one_claim_per_subject
  ON orchestration.security_state_invalidations (tenant_id, subject_id)
  WHERE status = 'executing';
CREATE INDEX security_state_invalidations_claim_order
  ON orchestration.security_state_invalidations (next_attempt_at, action_succeeded_at, action_id)
  WHERE status IN ('pending', 'failed');

CREATE TABLE orchestration.security_state_invalidation_attempts (
  tenant_id identity.tenant_id NOT NULL,
  action_id audit.security_action_id NOT NULL,
  attempt_number integer NOT NULL,
  claim_token text NOT NULL,
  worker_id text NOT NULL,
  status orchestration.security_invalidation_attempt_status NOT NULL,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  failure_code text,
  sessions_invalidated integer,
  cache_entries_invalidated integer,
  invalidated_at timestamptz,
  CONSTRAINT security_state_invalidation_attempts_pk PRIMARY KEY (
    tenant_id, action_id, attempt_number
  ),
  CONSTRAINT security_state_invalidation_attempts_action_fk FOREIGN KEY (
    tenant_id, action_id
  ) REFERENCES orchestration.security_state_invalidations (
    tenant_id, action_id
  ) ON DELETE RESTRICT,
  CONSTRAINT security_state_invalidation_attempts_claim_unique UNIQUE (
    tenant_id, claim_token
  ),
  CONSTRAINT security_state_invalidation_attempts_claim CHECK (
    claim_token ~ '^icl_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND worker_id ~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
    AND attempt_number > 0
  ),
  CONSTRAINT security_state_invalidation_attempts_completion CHECK (
    (status = 'executing' AND completed_at IS NULL AND failure_code IS NULL
      AND sessions_invalidated IS NULL AND cache_entries_invalidated IS NULL
      AND invalidated_at IS NULL)
    OR (status = 'failed' AND completed_at IS NOT NULL
      AND failure_code IS NOT NULL
      AND failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
      AND sessions_invalidated IS NULL AND cache_entries_invalidated IS NULL
      AND invalidated_at IS NULL)
    OR (status = 'completed' AND completed_at IS NOT NULL AND failure_code IS NULL
      AND sessions_invalidated IS NOT NULL AND cache_entries_invalidated IS NOT NULL
      AND sessions_invalidated >= 0 AND cache_entries_invalidated >= 0
      AND invalidated_at IS NOT NULL)
  )
);

CREATE FUNCTION orchestration.queue_security_state_invalidation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, identity, audit
SET row_security = off
AS $function$
DECLARE v_state_version bigint;
BEGIN
  IF NEW.status = 'succeeded'
     AND OLD.status IS DISTINCT FROM NEW.status
     AND NEW.action_type IN ('suspend-subject', 'revoke-certificate') THEN
    SELECT state.state_version INTO v_state_version
    FROM orchestration.subject_security_states AS state
    WHERE state.tenant_id = NEW.tenant_id
      AND state.subject_id = NEW.target_subject_id
      AND state.certificate_id = NEW.target_certificate_id
      AND state.last_action_id = NEW.action_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SECURITY_INVALIDATION_STATE_REQUIRED';
    END IF;
    INSERT INTO orchestration.security_state_invalidations (
      tenant_id, action_id, subject_id, certificate_id, action_type,
      correlation_id, security_state_version, action_succeeded_at, next_attempt_at
    ) VALUES (
      NEW.tenant_id, NEW.action_id, NEW.target_subject_id, NEW.target_certificate_id,
      NEW.action_type, NEW.correlation_id, v_state_version,
      NEW.succeeded_at, NEW.succeeded_at
    ) ON CONFLICT (tenant_id, action_id) DO NOTHING;
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER security_action_success_queues_invalidation
AFTER UPDATE OF status ON orchestration.security_actions
FOR EACH ROW EXECUTE FUNCTION orchestration.queue_security_state_invalidation();

INSERT INTO orchestration.security_state_invalidations (
  tenant_id, action_id, subject_id, certificate_id, action_type,
  correlation_id, security_state_version, action_succeeded_at, next_attempt_at
)
SELECT action.tenant_id, action.action_id, action.target_subject_id,
  action.target_certificate_id, action.action_type, action.correlation_id,
  state.state_version, action.succeeded_at, clock_timestamp()
FROM orchestration.security_actions AS action
JOIN orchestration.subject_security_states AS state
  ON state.tenant_id = action.tenant_id
  AND state.subject_id = action.target_subject_id
  AND state.certificate_id = action.target_certificate_id
  AND state.last_action_id = action.action_id
WHERE action.status = 'succeeded'
  AND action.action_type IN ('suspend-subject', 'revoke-certificate')
ON CONFLICT (tenant_id, action_id) DO NOTHING;

CREATE FUNCTION orchestration.claim_security_state_invalidation(
  p_worker_id text,
  p_claim_token text,
  p_claimed_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  action_id audit.security_action_id,
  subject_id identity.subject_id,
  certificate_id identity.certificate_id,
  action_type orchestration.security_action_type,
  claim_token text,
  attempt_count integer,
  action_succeeded_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, identity, audit
SET row_security = off
AS $function$
DECLARE v_invalidation orchestration.security_state_invalidations%ROWTYPE;
BEGIN
  IF p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
     OR p_claim_token !~ '^icl_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_claimed_at IS NULL OR p_claimed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_INVALIDATION_CLAIM_INVALID';
  END IF;

  UPDATE orchestration.security_state_invalidation_attempts AS attempt
  SET status = 'failed', completed_at = p_claimed_at,
      failure_code = 'INVALIDATION_LEASE_EXPIRED'
  FROM orchestration.security_state_invalidations AS invalidation
  WHERE attempt.tenant_id = invalidation.tenant_id
    AND attempt.action_id = invalidation.action_id
    AND attempt.attempt_number = invalidation.attempt_count
    AND attempt.status = 'executing'
    AND invalidation.status = 'executing'
    AND invalidation.lease_expires_at < p_claimed_at;

  UPDATE orchestration.security_state_invalidations SET
    status = 'failed', claimed_by = NULL, claim_token = NULL,
    claimed_at = NULL, lease_expires_at = NULL,
    last_failure_code = 'INVALIDATION_LEASE_EXPIRED',
    next_attempt_at = p_claimed_at, updated_at = p_claimed_at
  WHERE status = 'executing' AND lease_expires_at < p_claimed_at;

  SELECT * INTO v_invalidation
  FROM orchestration.security_state_invalidations AS candidate
  WHERE candidate.status IN ('pending', 'failed')
    AND candidate.next_attempt_at <= p_claimed_at
    AND pg_try_advisory_xact_lock(hashtextextended(
      candidate.tenant_id::text || ':' || candidate.subject_id::text, 0
    ))
    AND NOT EXISTS (
      SELECT 1 FROM orchestration.security_state_invalidations AS active
      WHERE active.tenant_id = candidate.tenant_id
        AND active.subject_id = candidate.subject_id
        AND active.status = 'executing'
    )
  ORDER BY candidate.next_attempt_at, candidate.action_succeeded_at, candidate.action_id
  FOR UPDATE SKIP LOCKED
  LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;

  UPDATE orchestration.security_state_invalidations SET
    status = 'executing',
    attempt_count = security_state_invalidations.attempt_count + 1,
    claimed_by = p_worker_id, claim_token = p_claim_token,
    claimed_at = p_claimed_at,
    lease_expires_at = p_claimed_at + interval '30 seconds',
    last_failure_code = NULL, updated_at = p_claimed_at
  WHERE security_state_invalidations.tenant_id = v_invalidation.tenant_id
    AND security_state_invalidations.action_id = v_invalidation.action_id
  RETURNING * INTO v_invalidation;

  INSERT INTO orchestration.security_state_invalidation_attempts (
    tenant_id, action_id, attempt_number, claim_token, worker_id, status, started_at
  ) VALUES (
    v_invalidation.tenant_id, v_invalidation.action_id,
    v_invalidation.attempt_count, p_claim_token, p_worker_id, 'executing', p_claimed_at
  );

  RETURN QUERY SELECT v_invalidation.tenant_id, v_invalidation.action_id,
    v_invalidation.subject_id, v_invalidation.certificate_id,
    v_invalidation.action_type, v_invalidation.claim_token,
    v_invalidation.attempt_count, v_invalidation.action_succeeded_at;
END
$function$;

CREATE FUNCTION orchestration.complete_security_state_invalidation(
  p_tenant_id identity.tenant_id,
  p_action_id audit.security_action_id,
  p_claim_token text,
  p_sessions_invalidated integer,
  p_cache_entries_invalidated integer,
  p_invalidated_at timestamptz,
  p_completed_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  action_id audit.security_action_id,
  status orchestration.security_invalidation_status,
  attempt_count integer,
  enforcement_delay_ms bigint,
  within_target boolean,
  completed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, identity, audit
SET row_security = off
AS $function$
DECLARE
  v_invalidation orchestration.security_state_invalidations%ROWTYPE;
  v_delay bigint;
BEGIN
  IF p_sessions_invalidated < 0 OR p_cache_entries_invalidated < 0
     OR p_invalidated_at IS NULL OR p_completed_at IS NULL
     OR p_invalidated_at > p_completed_at THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_INVALIDATION_COMPLETION_INVALID';
  END IF;
  SELECT * INTO v_invalidation
  FROM orchestration.security_state_invalidations AS invalidation
  WHERE invalidation.tenant_id = p_tenant_id AND invalidation.action_id = p_action_id
  FOR UPDATE;
  IF NOT FOUND OR v_invalidation.status <> 'executing'
     OR v_invalidation.claim_token <> p_claim_token
     OR v_invalidation.lease_expires_at < p_completed_at
     OR p_invalidated_at < v_invalidation.action_succeeded_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SECURITY_INVALIDATION_CLAIM_CONFLICT';
  END IF;
  v_delay := round(extract(epoch FROM (
    p_invalidated_at - v_invalidation.action_succeeded_at
  )) * 1000)::bigint;

  UPDATE orchestration.security_state_invalidation_attempts SET
    status = 'completed', completed_at = p_completed_at,
    sessions_invalidated = p_sessions_invalidated,
    cache_entries_invalidated = p_cache_entries_invalidated,
    invalidated_at = p_invalidated_at
  WHERE security_state_invalidation_attempts.tenant_id = v_invalidation.tenant_id
    AND security_state_invalidation_attempts.action_id = v_invalidation.action_id
    AND attempt_number = v_invalidation.attempt_count
    AND claim_token = p_claim_token;

  UPDATE orchestration.security_state_invalidations SET
    status = 'completed', claimed_by = NULL, claim_token = NULL,
    claimed_at = NULL, lease_expires_at = NULL,
    sessions_invalidated = p_sessions_invalidated,
    cache_entries_invalidated = p_cache_entries_invalidated,
    invalidated_at = p_invalidated_at, enforcement_delay_ms = v_delay,
    within_target = v_delay <= 5000, completed_at = p_completed_at,
    updated_at = p_completed_at
  WHERE security_state_invalidations.tenant_id = v_invalidation.tenant_id
    AND security_state_invalidations.action_id = v_invalidation.action_id
  RETURNING * INTO v_invalidation;

  RETURN QUERY SELECT v_invalidation.tenant_id, v_invalidation.action_id,
    v_invalidation.status, v_invalidation.attempt_count,
    v_invalidation.enforcement_delay_ms, v_invalidation.within_target,
    v_invalidation.completed_at;
END
$function$;

CREATE FUNCTION orchestration.fail_security_state_invalidation(
  p_tenant_id identity.tenant_id,
  p_action_id audit.security_action_id,
  p_claim_token text,
  p_failure_code text,
  p_failed_at timestamptz,
  p_retry_delay_seconds integer
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  action_id audit.security_action_id,
  status orchestration.security_invalidation_status,
  attempt_count integer,
  enforcement_delay_ms bigint,
  within_target boolean,
  completed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, audit
SET row_security = off
AS $function$
DECLARE v_invalidation orchestration.security_state_invalidations%ROWTYPE;
BEGIN
  IF p_failure_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_retry_delay_seconds NOT BETWEEN 1 AND 60 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SECURITY_INVALIDATION_FAILURE_INVALID';
  END IF;
  SELECT * INTO v_invalidation
  FROM orchestration.security_state_invalidations AS invalidation
  WHERE invalidation.tenant_id = p_tenant_id AND invalidation.action_id = p_action_id
  FOR UPDATE;
  IF NOT FOUND OR v_invalidation.status <> 'executing'
     OR v_invalidation.claim_token <> p_claim_token
     OR v_invalidation.lease_expires_at < p_failed_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SECURITY_INVALIDATION_CLAIM_CONFLICT';
  END IF;
  UPDATE orchestration.security_state_invalidation_attempts SET
    status = 'failed', completed_at = p_failed_at, failure_code = p_failure_code
  WHERE security_state_invalidation_attempts.tenant_id = v_invalidation.tenant_id
    AND security_state_invalidation_attempts.action_id = v_invalidation.action_id
    AND attempt_number = v_invalidation.attempt_count
    AND claim_token = p_claim_token;
  UPDATE orchestration.security_state_invalidations SET
    status = 'failed', claimed_by = NULL, claim_token = NULL,
    claimed_at = NULL, lease_expires_at = NULL,
    last_failure_code = p_failure_code,
    next_attempt_at = p_failed_at + make_interval(secs => p_retry_delay_seconds),
    updated_at = p_failed_at
  WHERE security_state_invalidations.tenant_id = v_invalidation.tenant_id
    AND security_state_invalidations.action_id = v_invalidation.action_id
  RETURNING * INTO v_invalidation;
  RETURN QUERY SELECT v_invalidation.tenant_id, v_invalidation.action_id,
    v_invalidation.status, v_invalidation.attempt_count,
    v_invalidation.enforcement_delay_ms, v_invalidation.within_target,
    v_invalidation.completed_at;
END
$function$;

ALTER TABLE orchestration.security_state_invalidations ENABLE ROW LEVEL SECURITY;
ALTER TABLE orchestration.security_state_invalidations FORCE ROW LEVEL SECURITY;
ALTER TABLE orchestration.security_state_invalidation_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE orchestration.security_state_invalidation_attempts FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE orchestration.security_state_invalidations,
  orchestration.security_state_invalidation_attempts FROM PUBLIC,
  tenant_trust_app, tenant_trust_security_action_requester,
  tenant_trust_security_action_worker, tenant_trust_security_invalidation_worker;
REVOKE ALL ON FUNCTION orchestration.queue_security_state_invalidation() FROM PUBLIC;
REVOKE ALL ON FUNCTION orchestration.claim_security_state_invalidation(text, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION orchestration.complete_security_state_invalidation(
  identity.tenant_id, audit.security_action_id, text, integer, integer, timestamptz, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION orchestration.fail_security_state_invalidation(
  identity.tenant_id, audit.security_action_id, text, text, timestamptz, integer
) FROM PUBLIC;

GRANT USAGE ON SCHEMA orchestration TO tenant_trust_security_invalidation_worker;
GRANT EXECUTE ON FUNCTION orchestration.claim_security_state_invalidation(text, text, timestamptz),
  orchestration.complete_security_state_invalidation(
    identity.tenant_id, audit.security_action_id, text, integer, integer, timestamptz, timestamptz
  ),
  orchestration.fail_security_state_invalidation(
    identity.tenant_id, audit.security_action_id, text, text, timestamptz, integer
  ) TO tenant_trust_security_invalidation_worker;

COMMENT ON TABLE orchestration.security_state_invalidations IS
  'Durable subject session and security-cache invalidation queued atomically from successful suspension or revocation';
COMMENT ON COLUMN orchestration.security_state_invalidations.enforcement_delay_ms IS
  'Measured milliseconds from durable security-action success to atomic Redis invalidation';
COMMENT ON COLUMN orchestration.security_state_invalidations.within_target IS
  'True when the measured invalidation delay is no more than the five-second T9.5 target';
