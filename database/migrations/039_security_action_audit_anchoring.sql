CREATE TABLE audit.security_action_audit_events (
  tenant_id identity.tenant_id NOT NULL,
  event_id identity.event_id NOT NULL,
  action_id audit.security_action_id NOT NULL,
  event_type text NOT NULL,
  event_status text NOT NULL,
  attempt_number integer NOT NULL,
  decision_id audit.policy_decision_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  target_subject_id identity.subject_id NOT NULL,
  target_certificate_id identity.certificate_id NOT NULL,
  action_type orchestration.security_action_type NOT NULL,
  authority_class orchestration.action_authority_class NOT NULL,
  reason_code text NOT NULL,
  recovery_authorization_id orchestration.recovery_authorization_id,
  recovery_trust_transition_id trust.transition_id,
  recovery_authorized_by_subject_id identity.subject_id,
  cause_resolution_reference text,
  external_reference text,
  failure_code text,
  occurred_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT security_action_audit_events_pk PRIMARY KEY (tenant_id, event_id),
  CONSTRAINT security_action_audit_events_semantic_unique UNIQUE (
    tenant_id, action_id, event_type, attempt_number
  ),
  CONSTRAINT security_action_audit_events_action_fk FOREIGN KEY (tenant_id, action_id)
    REFERENCES orchestration.security_actions (tenant_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT security_action_audit_events_recovery_fk FOREIGN KEY (
    tenant_id, recovery_authorization_id
  ) REFERENCES orchestration.security_recovery_authorizations (
    tenant_id, authorization_id
  ) ON DELETE RESTRICT,
  CONSTRAINT security_action_audit_events_type_status CHECK (
    (event_type = 'security-action.requested.v1' AND event_status = 'requested' AND attempt_number = 0)
    OR (event_type = 'security-action.succeeded.v1' AND event_status = 'succeeded' AND attempt_number > 0)
    OR (event_type = 'security-action.failed.v1' AND event_status = 'failed' AND attempt_number > 0)
  ),
  CONSTRAINT security_action_audit_events_recovery_shape CHECK (
    (authority_class = 'recovery-authorization'
      AND recovery_authorization_id IS NOT NULL
      AND recovery_trust_transition_id IS NOT NULL
      AND recovery_authorized_by_subject_id IS NOT NULL)
    OR (authority_class <> 'recovery-authorization'
      AND recovery_authorization_id IS NULL
      AND recovery_trust_transition_id IS NULL
      AND recovery_authorized_by_subject_id IS NULL
      AND cause_resolution_reference IS NULL)
  ),
  CONSTRAINT security_action_audit_events_failure_shape CHECK (
    (event_status = 'failed' AND failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$')
    OR (event_status <> 'failed' AND failure_code IS NULL)
  ),
  CONSTRAINT security_action_audit_events_time_order CHECK (recorded_at >= occurred_at)
);

CREATE INDEX security_action_audit_events_projection_order
  ON audit.security_action_audit_events (recorded_at, tenant_id, event_id);
CREATE INDEX security_action_audit_events_correlation
  ON audit.security_action_audit_events (tenant_id, correlation_id, occurred_at, event_id);

CREATE FUNCTION audit.prevent_security_action_audit_event_rewrite()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'SECURITY_ACTION_AUDIT_EVENT_IMMUTABLE';
END
$function$;

CREATE TRIGGER security_action_audit_events_append_only
BEFORE UPDATE OR DELETE ON audit.security_action_audit_events
FOR EACH ROW EXECUTE FUNCTION audit.prevent_security_action_audit_event_rewrite();

CREATE FUNCTION audit.capture_security_action_audit_event()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, orchestration, identity
SET row_security = off
AS $function$
DECLARE
  v_event_type text;
  v_event_status text;
  v_attempt_number integer;
  v_occurred_at timestamptz;
  v_recovery orchestration.security_recovery_authorizations%ROWTYPE;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.authority_class = 'recovery-authorization' THEN
      RETURN NEW;
    END IF;
    v_event_type := 'security-action.requested.v1';
    v_event_status := 'requested';
    v_attempt_number := 0;
    v_occurred_at := NEW.requested_at;
  ELSIF NEW.status IS DISTINCT FROM OLD.status AND NEW.status IN ('succeeded', 'failed') THEN
    v_event_type := CASE NEW.status
      WHEN 'succeeded' THEN 'security-action.succeeded.v1'
      ELSE 'security-action.failed.v1'
    END;
    v_event_status := NEW.status::text;
    v_attempt_number := NEW.attempt_count;
    v_occurred_at := COALESCE(NEW.succeeded_at, NEW.updated_at);
    IF NEW.authority_class = 'recovery-authorization' THEN
      SELECT * INTO v_recovery
      FROM orchestration.security_recovery_authorizations AS recovery
      WHERE recovery.tenant_id = NEW.tenant_id AND recovery.action_id = NEW.action_id;
      IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'RECOVERY_AUDIT_AUTHORIZATION_MISSING';
      END IF;
    END IF;
  ELSE
    RETURN NEW;
  END IF;

  INSERT INTO audit.security_action_audit_events (
    tenant_id, event_id, action_id, event_type, event_status, attempt_number,
    decision_id, correlation_id, target_subject_id, target_certificate_id,
    action_type, authority_class, reason_code, recovery_authorization_id,
    recovery_trust_transition_id, recovery_authorized_by_subject_id,
    cause_resolution_reference, external_reference, failure_code,
    occurred_at, recorded_at
  ) VALUES (
    NEW.tenant_id, ('evt_' || public.gen_random_uuid()::text)::identity.event_id,
    NEW.action_id, v_event_type, v_event_status, v_attempt_number,
    NEW.decision_id, NEW.correlation_id, NEW.target_subject_id,
    NEW.target_certificate_id, NEW.action_type, NEW.authority_class,
    NEW.reason_code, v_recovery.authorization_id, v_recovery.trust_transition_id,
    v_recovery.authorized_by_subject_id, v_recovery.cause_resolution_reference,
    CASE WHEN v_event_status = 'succeeded' THEN NEW.external_reference ELSE NULL END,
    CASE WHEN v_event_status = 'failed' THEN NEW.last_failure_code ELSE NULL END,
    v_occurred_at, GREATEST(clock_timestamp(), v_occurred_at)
  ) ON CONFLICT ON CONSTRAINT security_action_audit_events_semantic_unique DO NOTHING;
  RETURN NEW;
END
$function$;

CREATE TRIGGER security_actions_capture_audit_event
AFTER INSERT OR UPDATE OF status ON orchestration.security_actions
FOR EACH ROW EXECUTE FUNCTION audit.capture_security_action_audit_event();

CREATE FUNCTION audit.capture_recovery_authorization_audit_event()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, orchestration, identity
SET row_security = off
AS $function$
DECLARE
  v_action orchestration.security_actions%ROWTYPE;
BEGIN
  SELECT * INTO v_action FROM orchestration.security_actions AS action
  WHERE action.tenant_id = NEW.tenant_id AND action.action_id = NEW.action_id;
  IF NOT FOUND OR v_action.authority_class <> 'recovery-authorization' THEN
    RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'RECOVERY_AUDIT_ACTION_MISSING';
  END IF;
  INSERT INTO audit.security_action_audit_events (
    tenant_id, event_id, action_id, event_type, event_status, attempt_number,
    decision_id, correlation_id, target_subject_id, target_certificate_id,
    action_type, authority_class, reason_code, recovery_authorization_id,
    recovery_trust_transition_id, recovery_authorized_by_subject_id,
    cause_resolution_reference, occurred_at, recorded_at
  ) VALUES (
    v_action.tenant_id, ('evt_' || public.gen_random_uuid()::text)::identity.event_id,
    v_action.action_id, 'security-action.requested.v1', 'requested', 0,
    v_action.decision_id, v_action.correlation_id, v_action.target_subject_id,
    v_action.target_certificate_id, v_action.action_type, v_action.authority_class,
    v_action.reason_code, NEW.authorization_id, NEW.trust_transition_id,
    NEW.authorized_by_subject_id, NEW.cause_resolution_reference,
    v_action.requested_at, GREATEST(clock_timestamp(), v_action.requested_at)
  ) ON CONFLICT ON CONSTRAINT security_action_audit_events_semantic_unique DO NOTHING;
  RETURN NEW;
END
$function$;

CREATE TRIGGER security_recovery_authorizations_capture_audit_event
AFTER INSERT ON orchestration.security_recovery_authorizations
FOR EACH ROW EXECUTE FUNCTION audit.capture_recovery_authorization_audit_event();

INSERT INTO audit.security_action_audit_events (
  tenant_id, event_id, action_id, event_type, event_status, attempt_number,
  decision_id, correlation_id, target_subject_id, target_certificate_id,
  action_type, authority_class, reason_code, recovery_authorization_id,
  recovery_trust_transition_id, recovery_authorized_by_subject_id,
  cause_resolution_reference, occurred_at, recorded_at
)
SELECT action.tenant_id, ('evt_' || public.gen_random_uuid()::text)::identity.event_id,
  action.action_id, 'security-action.requested.v1', 'requested', 0,
  action.decision_id, action.correlation_id, action.target_subject_id,
  action.target_certificate_id, action.action_type, action.authority_class,
  action.reason_code, recovery.authorization_id, recovery.trust_transition_id,
  recovery.authorized_by_subject_id, recovery.cause_resolution_reference,
  action.requested_at, GREATEST(clock_timestamp(), action.requested_at)
FROM orchestration.security_actions AS action
LEFT JOIN orchestration.security_recovery_authorizations AS recovery
  ON recovery.tenant_id = action.tenant_id AND recovery.action_id = action.action_id
WHERE action.authority_class <> 'recovery-authorization' OR recovery.authorization_id IS NOT NULL
ON CONFLICT ON CONSTRAINT security_action_audit_events_semantic_unique DO NOTHING;

INSERT INTO audit.security_action_audit_events (
  tenant_id, event_id, action_id, event_type, event_status, attempt_number,
  decision_id, correlation_id, target_subject_id, target_certificate_id,
  action_type, authority_class, reason_code, recovery_authorization_id,
  recovery_trust_transition_id, recovery_authorized_by_subject_id,
  cause_resolution_reference, external_reference, failure_code,
  occurred_at, recorded_at
)
SELECT action.tenant_id, ('evt_' || public.gen_random_uuid()::text)::identity.event_id,
  action.action_id,
  CASE attempt.status WHEN 'succeeded' THEN 'security-action.succeeded.v1'
    ELSE 'security-action.failed.v1' END,
  attempt.status::text, attempt.attempt_number,
  action.decision_id, action.correlation_id, action.target_subject_id,
  action.target_certificate_id, action.action_type, action.authority_class,
  action.reason_code, recovery.authorization_id, recovery.trust_transition_id,
  recovery.authorized_by_subject_id, recovery.cause_resolution_reference,
  CASE WHEN attempt.status = 'succeeded' THEN action.external_reference ELSE NULL END,
  attempt.failure_code, attempt.completed_at, GREATEST(clock_timestamp(), attempt.completed_at)
FROM orchestration.security_action_attempts AS attempt
JOIN orchestration.security_actions AS action
  ON action.tenant_id = attempt.tenant_id AND action.action_id = attempt.action_id
LEFT JOIN orchestration.security_recovery_authorizations AS recovery
  ON recovery.tenant_id = action.tenant_id AND recovery.action_id = action.action_id
WHERE attempt.status IN ('succeeded', 'failed')
  AND (action.authority_class <> 'recovery-authorization' OR recovery.authorization_id IS NOT NULL)
ON CONFLICT ON CONSTRAINT security_action_audit_events_semantic_unique DO NOTHING;

CREATE FUNCTION audit.get_pending_security_action_audit_event()
RETURNS TABLE (
  tenant_id identity.tenant_id, event_id identity.event_id,
  action_id audit.security_action_id, event_type text, event_status text,
  attempt_number integer, decision_id audit.policy_decision_id,
  correlation_id identity.correlation_id, target_subject_id identity.subject_id,
  target_certificate_id identity.certificate_id,
  action_type orchestration.security_action_type,
  authority_class orchestration.action_authority_class, reason_code text,
  recovery_authorization_id orchestration.recovery_authorization_id,
  recovery_trust_transition_id trust.transition_id,
  recovery_authorized_by_subject_id identity.subject_id,
  cause_resolution_reference text, external_reference text, failure_code text,
  occurred_at timestamptz, recorded_at timestamptz,
  causation_event_id identity.event_id, certificate_event_id identity.event_id
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, audit, orchestration, identity, trust
SET row_security = off
AS $function$
  WITH candidate AS (
    SELECT source.*
    FROM audit.security_action_audit_events AS source
    WHERE NOT EXISTS (
      SELECT 1 FROM audit.fabric_commitment_outbox AS anchored
      WHERE anchored.tenant_id = source.tenant_id AND anchored.event_id = source.event_id
    )
    AND (
      (source.event_status <> 'requested' AND EXISTS (
        SELECT 1 FROM audit.security_action_audit_events AS requested
        JOIN audit.fabric_commitment_outbox AS requested_outbox
          ON requested_outbox.tenant_id = requested.tenant_id
         AND requested_outbox.event_id = requested.event_id
        WHERE requested.tenant_id = source.tenant_id
          AND requested.action_id = source.action_id
          AND requested.event_status = 'requested'
      ))
      OR (source.event_status = 'requested'
        AND source.authority_class = 'recovery-authorization' AND EXISTS (
          SELECT 1 FROM audit.fabric_commitment_outbox AS trust_event
          WHERE trust_event.tenant_id = source.tenant_id
            AND trust_event.event_type = 'trust.updated.v1'
            AND trust_event.event_document #>> '{payload,transitionId}' = source.recovery_trust_transition_id::text
        ))
      OR (source.event_status = 'requested'
        AND source.authority_class <> 'recovery-authorization' AND EXISTS (
          SELECT 1 FROM audit.fabric_commitment_outbox AS decision_event
          WHERE decision_event.tenant_id = source.tenant_id
            AND decision_event.event_type = 'access.decided.v1'
            AND decision_event.event_document #>> '{payload,decisionId}' = source.decision_id::text
        ))
    )
    AND (
      source.event_status <> 'succeeded'
      OR source.action_type NOT IN ('revoke-certificate', 'issue-replacement-certificate')
      OR (source.action_type = 'revoke-certificate'
        AND source.external_reference ~ '^evt_[0-9a-f-]{36}$'
        AND EXISTS (
          SELECT 1 FROM audit.fabric_commitment_outbox AS certificate_event
          WHERE certificate_event.tenant_id = source.tenant_id
            AND certificate_event.event_id::text = source.external_reference
            AND certificate_event.event_type = 'certificate.revoked.v1'
        ))
      OR (source.action_type = 'issue-replacement-certificate' AND EXISTS (
        SELECT 1 FROM identity.certificates AS certificate
        JOIN audit.fabric_commitment_outbox AS certificate_event
          ON certificate_event.tenant_id = certificate.tenant_id
         AND certificate_event.event_id = certificate.issued_event_id
         AND certificate_event.event_type = 'certificate.issued.v1'
        WHERE certificate.tenant_id = source.tenant_id
          AND certificate.certificate_id::text = source.external_reference
          AND certificate.subject_id = source.target_subject_id
          AND certificate.state = 'active'
      ))
    )
    ORDER BY source.recorded_at, source.tenant_id, source.event_id
    LIMIT 1
  )
  SELECT candidate.tenant_id, candidate.event_id, candidate.action_id,
    candidate.event_type, candidate.event_status, candidate.attempt_number,
    candidate.decision_id, candidate.correlation_id, candidate.target_subject_id,
    candidate.target_certificate_id, candidate.action_type, candidate.authority_class,
    candidate.reason_code, candidate.recovery_authorization_id,
    candidate.recovery_trust_transition_id,
    candidate.recovery_authorized_by_subject_id,
    candidate.cause_resolution_reference, candidate.external_reference,
    candidate.failure_code, candidate.occurred_at, candidate.recorded_at,
    CASE
      WHEN candidate.event_status <> 'requested' THEN (
        SELECT requested.event_id FROM audit.security_action_audit_events AS requested
        WHERE requested.tenant_id = candidate.tenant_id
          AND requested.action_id = candidate.action_id
          AND requested.event_status = 'requested'
      )
      WHEN candidate.authority_class = 'recovery-authorization' THEN (
        SELECT outbox.event_id FROM audit.fabric_commitment_outbox AS outbox
        WHERE outbox.tenant_id = candidate.tenant_id
          AND outbox.event_type = 'trust.updated.v1'
          AND outbox.event_document #>> '{payload,transitionId}' = candidate.recovery_trust_transition_id::text
        ORDER BY outbox.created_at, outbox.event_id LIMIT 1
      )
      ELSE (
        SELECT outbox.event_id FROM audit.fabric_commitment_outbox AS outbox
        WHERE outbox.tenant_id = candidate.tenant_id
          AND outbox.event_type = 'access.decided.v1'
          AND outbox.event_document #>> '{payload,decisionId}' = candidate.decision_id::text
        ORDER BY outbox.created_at, outbox.event_id LIMIT 1
      )
    END,
    CASE
      WHEN candidate.event_status = 'succeeded'
        AND candidate.action_type = 'revoke-certificate'
        AND candidate.external_reference ~ '^evt_[0-9a-f-]{36}$'
        THEN candidate.external_reference::identity.event_id
      WHEN candidate.event_status = 'succeeded'
        AND candidate.action_type = 'issue-replacement-certificate' THEN (
          SELECT certificate.issued_event_id FROM identity.certificates AS certificate
          WHERE certificate.tenant_id = candidate.tenant_id
            AND certificate.certificate_id::text = candidate.external_reference
            AND certificate.subject_id = candidate.target_subject_id
            AND certificate.state = 'active'
        )
      ELSE NULL
    END
  FROM candidate;
$function$;

CREATE FUNCTION audit.record_security_action_audit_commitment(
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_channel_name text,
  p_event_document jsonb,
  p_canonical_preimage_json text,
  p_ledger_key text,
  p_event_key_hash_sha256 identity.sha256_digest,
  p_commitment_hash_sha256 identity.sha256_digest,
  p_ledger_value jsonb,
  p_queued_at timestamptz
)
RETURNS TABLE (event_id identity.event_id, status audit.audit_outbox_state)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, orchestration, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_source audit.security_action_audit_events%ROWTYPE;
  v_causation_event_id identity.event_id;
  v_certificate_event_id identity.event_id;
  v_existing audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  SELECT * INTO v_source FROM audit.security_action_audit_events AS source
  WHERE source.tenant_id = p_tenant_id AND source.event_id = p_event_id;
  IF NOT FOUND OR p_channel_name !~ '^tt-audit-[a-z0-9-]+-v[1-9][0-9]*$'
     OR p_queued_at > clock_timestamp() + interval '2 seconds'
     OR p_queued_at < clock_timestamp() - interval '10 minutes' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACTION_AUDIT_COMMITMENT_DENIED';
  END IF;

  IF v_source.event_status <> 'requested' THEN
    SELECT requested.event_id INTO v_causation_event_id
    FROM audit.security_action_audit_events AS requested
    WHERE requested.tenant_id = v_source.tenant_id
      AND requested.action_id = v_source.action_id
      AND requested.event_status = 'requested';
  ELSIF v_source.authority_class = 'recovery-authorization' THEN
    SELECT outbox.event_id INTO v_causation_event_id
    FROM audit.fabric_commitment_outbox AS outbox
    WHERE outbox.tenant_id = v_source.tenant_id
      AND outbox.event_type = 'trust.updated.v1'
      AND outbox.event_document #>> '{payload,transitionId}' = v_source.recovery_trust_transition_id::text
    ORDER BY outbox.created_at, outbox.event_id LIMIT 1;
  ELSE
    SELECT outbox.event_id INTO v_causation_event_id
    FROM audit.fabric_commitment_outbox AS outbox
    WHERE outbox.tenant_id = v_source.tenant_id
      AND outbox.event_type = 'access.decided.v1'
      AND outbox.event_document #>> '{payload,decisionId}' = v_source.decision_id::text
    ORDER BY outbox.created_at, outbox.event_id LIMIT 1;
  END IF;
  IF v_causation_event_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM audit.fabric_commitment_outbox AS cause
    WHERE cause.tenant_id = v_source.tenant_id AND cause.event_id = v_causation_event_id
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'ACTION_AUDIT_CAUSATION_PENDING';
  END IF;

  IF v_source.event_status = 'succeeded' AND v_source.action_type = 'revoke-certificate'
     AND v_source.external_reference ~ '^evt_[0-9a-f-]{36}$' THEN
    v_certificate_event_id := v_source.external_reference::identity.event_id;
  ELSIF v_source.event_status = 'succeeded'
        AND v_source.action_type = 'issue-replacement-certificate' THEN
    SELECT certificate.issued_event_id INTO v_certificate_event_id
    FROM identity.certificates AS certificate
    WHERE certificate.tenant_id = v_source.tenant_id
      AND certificate.certificate_id::text = v_source.external_reference
      AND certificate.subject_id = v_source.target_subject_id
      AND certificate.state = 'active';
  END IF;
  IF v_source.event_status = 'succeeded'
     AND v_source.action_type IN ('revoke-certificate', 'issue-replacement-certificate')
     AND (v_certificate_event_id IS NULL OR NOT EXISTS (
       SELECT 1 FROM audit.fabric_commitment_outbox AS certificate_event
       WHERE certificate_event.tenant_id = v_source.tenant_id
         AND certificate_event.event_id = v_certificate_event_id
         AND certificate_event.event_type = CASE v_source.action_type
           WHEN 'revoke-certificate' THEN 'certificate.revoked.v1'
           ELSE 'certificate.issued.v1' END
     )) THEN
    RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'ACTION_AUDIT_CERTIFICATE_EVENT_PENDING';
  END IF;

  IF p_event_document ->> 'schemaVersion' <> '1.0.0'
     OR p_event_document ->> 'eventId' <> v_source.event_id::text
     OR p_event_document ->> 'eventType' <> v_source.event_type
     OR p_event_document ->> 'tenantId' <> v_source.tenant_id::text
     OR p_event_document ->> 'subjectId' <> v_source.target_subject_id::text
     OR p_event_document ->> 'aggregateId' <> v_source.action_id::text
     OR p_event_document ->> 'correlationId' <> v_source.correlation_id::text
     OR p_event_document ->> 'causationId' <> v_causation_event_id::text
     OR p_event_document ->> 'idempotencyKey' <>
       'security-action-audit:' || v_source.action_id::text || ':' || v_source.event_status || ':' || v_source.attempt_number::text
     OR (p_event_document ->> 'occurredAt')::timestamptz <>
       date_trunc('milliseconds', v_source.occurred_at)
     OR (p_event_document ->> 'recordedAt')::timestamptz <>
       date_trunc('milliseconds', v_source.recorded_at)
     OR p_event_document #>> '{producer,service}' <> 'security-action-audit'
     OR p_event_document #>> '{producer,instanceId}' <> 'projection-v1'
     OR p_event_document #>> '{payload,actionId}' <> v_source.action_id::text
     OR p_event_document #>> '{payload,decisionId}' <> v_source.decision_id::text
     OR p_event_document #>> '{payload,actionType}' <> v_source.action_type::text
     OR p_event_document #>> '{payload,status}' <> v_source.event_status
     OR (p_event_document #>> '{payload,attemptNumber}')::integer <> v_source.attempt_number
     OR p_event_document #>> '{payload,targetCertificateId}' <> v_source.target_certificate_id::text
     OR p_event_document #>> '{payload,reasonCode}' <> v_source.reason_code
     OR p_event_document #>> '{payload,authorityClass}' <> v_source.authority_class::text
     OR p_event_document #>> '{payload,recoveryAuthorizationId}' IS DISTINCT FROM v_source.recovery_authorization_id::text
     OR p_event_document #>> '{payload,recoveryTrustTransitionId}' IS DISTINCT FROM v_source.recovery_trust_transition_id::text
     OR p_event_document #>> '{payload,authorizedBySubjectId}' IS DISTINCT FROM v_source.recovery_authorized_by_subject_id::text
     OR p_event_document #>> '{payload,causeResolutionReference}' IS DISTINCT FROM v_source.cause_resolution_reference
     OR p_event_document #>> '{payload,externalReference}' IS DISTINCT FROM v_source.external_reference
     OR p_event_document #>> '{payload,certificateEventId}' IS DISTINCT FROM v_certificate_event_id::text
     OR p_event_document #>> '{payload,failureCode}' IS DISTINCT FROM v_source.failure_code
     OR p_ledger_value ->> 'recordType' <> 'security-action'
     OR p_ledger_value ->> 'eventKeyHashSha256' <> p_event_key_hash_sha256::text
     OR p_ledger_value ->> 'commitmentHashSha256' <> p_commitment_hash_sha256::text
     OR p_ledger_key <> 'audit~security-action~' || p_event_key_hash_sha256::text THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'ACTION_AUDIT_EVENT_MISMATCH';
  END IF;

  INSERT INTO audit.fabric_commitment_outbox (
    tenant_id, event_id, channel_name, event_type, record_type,
    event_document, canonical_preimage_json, ledger_key,
    event_key_hash_sha256, commitment_hash_sha256, ledger_value,
    next_attempt_at, created_at, updated_at
  ) VALUES (
    v_source.tenant_id, v_source.event_id, p_channel_name,
    v_source.event_type, 'security-action', p_event_document,
    p_canonical_preimage_json, p_ledger_key, p_event_key_hash_sha256,
    p_commitment_hash_sha256, p_ledger_value, p_queued_at, p_queued_at, p_queued_at
  ) ON CONFLICT ON CONSTRAINT fabric_commitment_outbox_pk DO NOTHING;

  SELECT * INTO v_existing FROM audit.fabric_commitment_outbox AS outbox
  WHERE outbox.tenant_id = v_source.tenant_id AND outbox.event_id = v_source.event_id;
  IF v_existing.event_document <> p_event_document
     OR v_existing.canonical_preimage_json <> p_canonical_preimage_json
     OR v_existing.ledger_key <> p_ledger_key
     OR v_existing.event_key_hash_sha256 <> p_event_key_hash_sha256
     OR v_existing.commitment_hash_sha256 <> p_commitment_hash_sha256
     OR v_existing.ledger_value <> p_ledger_value THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'ACTION_AUDIT_COMMITMENT_CONFLICT';
  END IF;
  RETURN QUERY SELECT v_existing.event_id, v_existing.status;
END
$function$;

CREATE FUNCTION audit.list_security_action_audit_expectations(
  p_tenant_id identity.tenant_id,
  p_correlation_id identity.correlation_id
)
RETURNS TABLE (
  tenant_id identity.tenant_id, event_id identity.event_id,
  action_id audit.security_action_id, event_type text, event_status text,
  attempt_number integer, decision_id audit.policy_decision_id,
  correlation_id identity.correlation_id, target_subject_id identity.subject_id,
  target_certificate_id identity.certificate_id,
  action_type orchestration.security_action_type,
  authority_class orchestration.action_authority_class, reason_code text,
  recovery_authorization_id orchestration.recovery_authorization_id,
  recovery_trust_transition_id trust.transition_id,
  recovery_authorized_by_subject_id identity.subject_id,
  cause_resolution_reference text, external_reference text, failure_code text,
  occurred_at timestamptz, recorded_at timestamptz,
  causation_event_id identity.event_id, certificate_event_id identity.event_id
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, audit, orchestration, identity, trust
SET row_security = off
AS $function$
  SELECT source.tenant_id, source.event_id, source.action_id, source.event_type,
    source.event_status, source.attempt_number, source.decision_id,
    source.correlation_id, source.target_subject_id, source.target_certificate_id,
    source.action_type, source.authority_class, source.reason_code,
    source.recovery_authorization_id, source.recovery_trust_transition_id,
    source.recovery_authorized_by_subject_id, source.cause_resolution_reference,
    source.external_reference, source.failure_code, source.occurred_at,
    source.recorded_at,
    CASE
      WHEN source.event_status <> 'requested' THEN (
        SELECT requested.event_id FROM audit.security_action_audit_events AS requested
        WHERE requested.tenant_id = source.tenant_id
          AND requested.action_id = source.action_id
          AND requested.event_status = 'requested'
      )
      WHEN source.authority_class = 'recovery-authorization' THEN (
        SELECT outbox.event_id FROM audit.fabric_commitment_outbox AS outbox
        WHERE outbox.tenant_id = source.tenant_id
          AND outbox.event_type = 'trust.updated.v1'
          AND outbox.event_document #>> '{payload,transitionId}' = source.recovery_trust_transition_id::text
        ORDER BY outbox.created_at, outbox.event_id LIMIT 1
      )
      ELSE (
        SELECT outbox.event_id FROM audit.fabric_commitment_outbox AS outbox
        WHERE outbox.tenant_id = source.tenant_id
          AND outbox.event_type = 'access.decided.v1'
          AND outbox.event_document #>> '{payload,decisionId}' = source.decision_id::text
        ORDER BY outbox.created_at, outbox.event_id LIMIT 1
      )
    END,
    CASE
      WHEN source.event_status = 'succeeded'
        AND source.action_type = 'revoke-certificate'
        AND source.external_reference ~ '^evt_[0-9a-f-]{36}$'
        THEN source.external_reference::identity.event_id
      WHEN source.event_status = 'succeeded'
        AND source.action_type = 'issue-replacement-certificate' THEN (
          SELECT certificate.issued_event_id FROM identity.certificates AS certificate
          WHERE certificate.tenant_id = source.tenant_id
            AND certificate.certificate_id::text = source.external_reference
            AND certificate.subject_id = source.target_subject_id
            AND certificate.state = 'active'
        )
      ELSE NULL
    END
  FROM audit.security_action_audit_events AS source
  WHERE source.tenant_id = p_tenant_id AND source.correlation_id = p_correlation_id
  ORDER BY source.occurred_at, source.event_id;
$function$;

CREATE FUNCTION audit.list_security_action_audit_records(
  p_tenant_id identity.tenant_id,
  p_correlation_id identity.correlation_id
)
RETURNS TABLE (
  tenant_id identity.tenant_id, event_id identity.event_id,
  channel_name text, event_document jsonb, canonical_preimage_json text,
  ledger_key text, ledger_value jsonb, delivery_status audit.audit_outbox_state,
  transaction_id identity.sha256_digest, validation_code integer, block_number bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity
SET row_security = off
AS $function$
  WITH expected AS (
    SELECT expectation.event_id, expectation.causation_event_id,
      expectation.certificate_event_id
    FROM audit.list_security_action_audit_expectations(
      p_tenant_id, p_correlation_id
    ) AS expectation
  ), event_ids AS (
    SELECT event_id FROM expected
    UNION SELECT causation_event_id FROM expected WHERE causation_event_id IS NOT NULL
    UNION SELECT certificate_event_id FROM expected WHERE certificate_event_id IS NOT NULL
  )
  SELECT outbox.tenant_id, outbox.event_id, outbox.channel_name,
    outbox.event_document, outbox.canonical_preimage_json, outbox.ledger_key,
    outbox.ledger_value, outbox.status, outbox.transaction_id,
    outbox.validation_code, outbox.block_number
  FROM audit.fabric_commitment_outbox AS outbox
  JOIN event_ids ON event_ids.event_id = outbox.event_id
  WHERE outbox.tenant_id = p_tenant_id
  ORDER BY outbox.event_document ->> 'occurredAt', outbox.event_id;
$function$;

DO $create_projector_role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_security_action_audit_projector') THEN
    CREATE ROLE tenant_trust_security_action_audit_projector;
  END IF;
END
$create_projector_role$;

ALTER ROLE tenant_trust_security_action_audit_projector
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;

ALTER TABLE audit.security_action_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.security_action_audit_events FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE audit.security_action_audit_events FROM PUBLIC,
  tenant_trust_app, tenant_trust_security_action_requester,
  tenant_trust_security_action_worker, tenant_trust_audit_outbox_worker,
  tenant_trust_audit_verifier, tenant_trust_security_action_audit_projector;
REVOKE ALL ON FUNCTION audit.prevent_security_action_audit_event_rewrite(),
  audit.capture_security_action_audit_event(),
  audit.capture_recovery_authorization_audit_event(),
  audit.get_pending_security_action_audit_event(),
  audit.record_security_action_audit_commitment(
    identity.tenant_id, identity.event_id, text, jsonb, text, text,
    identity.sha256_digest, identity.sha256_digest, jsonb, timestamptz
  ),
  audit.list_security_action_audit_expectations(identity.tenant_id, identity.correlation_id),
  audit.list_security_action_audit_records(identity.tenant_id, identity.correlation_id)
FROM PUBLIC;

GRANT USAGE ON SCHEMA audit TO tenant_trust_security_action_audit_projector;
GRANT EXECUTE ON FUNCTION audit.get_pending_security_action_audit_event(),
  audit.record_security_action_audit_commitment(
    identity.tenant_id, identity.event_id, text, jsonb, text, text,
    identity.sha256_digest, identity.sha256_digest, jsonb, timestamptz
  ) TO tenant_trust_security_action_audit_projector;
GRANT EXECUTE ON FUNCTION
  audit.list_security_action_audit_expectations(identity.tenant_id, identity.correlation_id),
  audit.list_security_action_audit_records(identity.tenant_id, identity.correlation_id)
TO tenant_trust_audit_verifier;

COMMENT ON TABLE audit.security_action_audit_events IS
  'Immutable authoritative expectations for security-action and governed-recovery Fabric commitments';
COMMENT ON FUNCTION audit.get_pending_security_action_audit_event() IS
  'Returns one unanchored action event with its exact decision, recovery, terminal and certificate causation';
COMMENT ON FUNCTION audit.record_security_action_audit_commitment(
  identity.tenant_id, identity.event_id, text, jsonb, text, text,
  identity.sha256_digest, identity.sha256_digest, jsonb, timestamptz
) IS 'Validates an exact authoritative action event before atomically adding its Fabric commitment to the durable outbox';
