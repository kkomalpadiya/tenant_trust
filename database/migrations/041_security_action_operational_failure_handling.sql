DO $create_security_action_operator$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_security_action_operator'
  ) THEN
    CREATE ROLE tenant_trust_security_action_operator;
  END IF;
END
$create_security_action_operator$;

ALTER ROLE tenant_trust_security_action_operator
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS PASSWORD NULL;

CREATE INDEX security_actions_operational_state
  ON orchestration.security_actions (
    status, lease_expires_at, next_attempt_at, updated_at, tenant_id, action_id
  );

CREATE FUNCTION orchestration.recover_expired_security_action_leases(
  p_recovered_by text,
  p_recovered_at timestamptz
)
RETURNS TABLE (recovered_count integer, earliest_retry_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration
SET row_security = off
AS $function$
BEGIN
  IF p_recovered_by !~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
     OR p_recovered_at IS NULL
     OR p_recovered_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING
      ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_RECOVERY_INVALID';
  END IF;

  UPDATE orchestration.security_action_attempts AS attempt SET
    status = 'failed', completed_at = p_recovered_at,
    failure_code = 'ACTION_LEASE_EXPIRED'
  FROM orchestration.security_actions AS action
  WHERE action.tenant_id = attempt.tenant_id
    AND action.action_id = attempt.action_id
    AND action.status = 'executing'
    AND action.lease_expires_at <= p_recovered_at
    AND attempt.attempt_number = action.attempt_count
    AND attempt.status = 'executing';

  RETURN QUERY WITH recovered AS (
    UPDATE orchestration.security_actions AS action SET
      status = 'failed', claimed_by = NULL, claim_token = NULL,
      claimed_at = NULL, lease_expires_at = NULL,
      last_failure_code = 'ACTION_LEASE_EXPIRED',
      next_attempt_at = p_recovered_at, updated_at = p_recovered_at
    WHERE action.status = 'executing'
      AND action.lease_expires_at <= p_recovered_at
    RETURNING action.next_attempt_at
  )
  SELECT count(*)::integer, min(recovered.next_attempt_at) FROM recovered;
END
$function$;

CREATE FUNCTION orchestration.list_security_action_operational_issues(
  p_limit integer DEFAULT 100,
  p_observed_at timestamptz DEFAULT clock_timestamp()
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  action_id audit.security_action_id,
  correlation_id identity.correlation_id,
  issue_code text,
  severity text,
  action_status orchestration.action_execution_status,
  attempt_count integer,
  last_failure_code text,
  next_attempt_at timestamptz,
  lease_expires_at timestamptz,
  audit_event_id identity.event_id,
  audit_delivery_status audit.audit_outbox_state,
  retryable boolean,
  observed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, orchestration, audit, identity
SET row_security = off
AS $function$
BEGIN
  IF p_limit NOT BETWEEN 1 AND 500
     OR p_observed_at IS NULL
     OR p_observed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING
      ERRCODE = '22023', MESSAGE = 'SECURITY_ACTION_OPERATIONS_QUERY_INVALID';
  END IF;

  RETURN QUERY
  WITH action_issues AS (
    SELECT action.tenant_id, action.action_id, action.correlation_id,
      CASE
        WHEN action.status = 'executing' AND action.lease_expires_at <= p_observed_at
          THEN 'ACTION_LEASE_STUCK'
        WHEN action.status = 'pending'
          AND action.next_attempt_at <= p_observed_at - interval '5 minutes'
          THEN 'ACTION_PENDING_STUCK'
        WHEN action.status = 'failed'
          AND action.next_attempt_at = 'infinity'::timestamptz
          AND action.last_failure_code IN (
            'ACTION_ALREADY_SATISFIED', 'RECOVERY_STATE_CHANGED'
          ) THEN 'ACTION_SUPPRESSED'
        WHEN action.status = 'failed'
          AND action.next_attempt_at = 'infinity'::timestamptz
          THEN 'ACTION_TERMINAL_FAILURE'
        WHEN action.status = 'failed' THEN 'ACTION_RETRY_SCHEDULED'
      END AS issue_code,
      CASE
        WHEN action.status = 'executing' AND action.lease_expires_at <= p_observed_at
          THEN 'critical'
        WHEN action.status = 'failed'
          AND action.next_attempt_at = 'infinity'::timestamptz
          AND action.last_failure_code NOT IN (
            'ACTION_ALREADY_SATISFIED', 'RECOVERY_STATE_CHANGED'
          ) THEN 'critical'
        WHEN action.status = 'failed'
          AND action.next_attempt_at = 'infinity'::timestamptz
          THEN 'info'
        ELSE 'warning'
      END AS severity,
      action.status AS action_status, action.attempt_count,
      action.last_failure_code, action.next_attempt_at,
      action.lease_expires_at, NULL::identity.event_id AS audit_event_id,
      NULL::audit.audit_outbox_state AS audit_delivery_status,
      action.status = 'failed'
        AND action.next_attempt_at <> 'infinity'::timestamptz AS retryable,
      p_observed_at AS observed_at,
      action.updated_at AS issue_at
    FROM orchestration.security_actions AS action
    WHERE (action.status = 'executing' AND action.lease_expires_at <= p_observed_at)
      OR action.status = 'failed'
      OR (action.status = 'pending'
        AND action.next_attempt_at <= p_observed_at - interval '5 minutes')
  ), audit_issues AS (
    SELECT source.tenant_id, source.action_id, source.correlation_id,
      CASE
        WHEN outbox.event_id IS NULL THEN 'ACTION_AUDIT_UNPROJECTED'
        WHEN outbox.status = 'failed' THEN 'ACTION_AUDIT_DELIVERY_FAILED'
        WHEN outbox.status IN ('submitting', 'confirming')
          AND outbox.claimed_at <= p_observed_at - interval '5 minutes'
          THEN 'ACTION_AUDIT_DELIVERY_STUCK'
        WHEN outbox.status = 'submitted'
          AND outbox.next_confirmation_at <= p_observed_at - interval '5 minutes'
          THEN 'ACTION_AUDIT_CONFIRMATION_STUCK'
        ELSE 'ACTION_AUDIT_DELIVERY_PENDING'
      END AS issue_code,
      CASE
        WHEN outbox.status = 'failed' THEN 'critical'
        WHEN outbox.status IN ('submitting', 'confirming')
          AND outbox.claimed_at <= p_observed_at - interval '5 minutes'
          THEN 'critical'
        WHEN outbox.status = 'submitted'
          AND outbox.next_confirmation_at <= p_observed_at - interval '5 minutes'
          THEN 'critical'
        ELSE 'warning'
      END AS severity,
      action.status AS action_status, action.attempt_count,
      action.last_failure_code, action.next_attempt_at,
      action.lease_expires_at, source.event_id AS audit_event_id,
      outbox.status AS audit_delivery_status,
      COALESCE(outbox.status IN ('pending', 'failed', 'submitted'), true) AS retryable,
      p_observed_at AS observed_at,
      COALESCE(outbox.updated_at, source.recorded_at) AS issue_at
    FROM audit.security_action_audit_events AS source
    JOIN orchestration.security_actions AS action
      ON action.tenant_id = source.tenant_id
      AND action.action_id = source.action_id
    LEFT JOIN audit.fabric_commitment_outbox AS outbox
      ON outbox.tenant_id = source.tenant_id
      AND outbox.event_id = source.event_id
    WHERE outbox.status IS DISTINCT FROM 'committed'
  ), issues AS (
    SELECT * FROM action_issues
    UNION ALL
    SELECT * FROM audit_issues
  )
  SELECT issue.tenant_id, issue.action_id, issue.correlation_id,
    issue.issue_code, issue.severity, issue.action_status,
    issue.attempt_count, issue.last_failure_code, issue.next_attempt_at,
    issue.lease_expires_at, issue.audit_event_id,
    issue.audit_delivery_status, issue.retryable, issue.observed_at
  FROM issues AS issue
  ORDER BY CASE issue.severity
      WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
    issue.issue_at, issue.tenant_id, issue.action_id, issue.audit_event_id
  LIMIT p_limit;
END
$function$;

REVOKE ALL ON FUNCTION orchestration.recover_expired_security_action_leases(
  text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION orchestration.list_security_action_operational_issues(
  integer, timestamptz
) FROM PUBLIC;

GRANT USAGE ON SCHEMA orchestration TO tenant_trust_security_action_operator;
GRANT EXECUTE ON FUNCTION orchestration.recover_expired_security_action_leases(
  text, timestamptz
) TO tenant_trust_security_action_operator, tenant_trust_security_action_worker;
GRANT EXECUTE ON FUNCTION orchestration.list_security_action_operational_issues(
  integer, timestamptz
) TO tenant_trust_security_action_operator;

COMMENT ON FUNCTION orchestration.recover_expired_security_action_leases(
  text, timestamptz
) IS 'Recovers expired action claims without changing target state or losing the stable action and attempt history';
COMMENT ON FUNCTION orchestration.list_security_action_operational_issues(
  integer, timestamptz
) IS 'Lists active action execution and required audit-delivery gaps through a least-privilege operational boundary';
