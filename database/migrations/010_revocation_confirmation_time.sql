CREATE OR REPLACE FUNCTION identity.record_certificate_revocation(
  p_event_id identity.event_id,
  p_correlation_id identity.correlation_id,
  p_request_id identity.request_id,
  p_certificate_id identity.certificate_id,
  p_reason_code identity.certificate_revocation_reason,
  p_revoked_at timestamptz,
  p_idempotency_key identity.idempotency_key,
  p_issuer_confirmation_id identity.issuer_confirmation_id
)
RETURNS TABLE (
  recorded_certificate_id identity.certificate_id,
  recorded_event_id identity.event_id,
  recorded_correlation_id identity.correlation_id,
  recorded_state identity.certificate_state,
  recorded_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
DECLARE
  actor_id identity.subject_id := identity.current_subject_id();
  target identity.certificates%ROWTYPE;
  existing_event identity.certificate_lifecycle_events%ROWTYPE;
BEGIN
  IF NOT identity.current_actor_is_active() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate revocation denied.';
  END IF;

  SELECT * INTO existing_event
  FROM identity.certificate_lifecycle_events AS event
  WHERE event.tenant_id = identity.current_tenant_id()
    AND event.idempotency_key = p_idempotency_key
    AND event.event_type = 'revoked';

  IF FOUND THEN
    IF existing_event.certificate_id <> p_certificate_id
       OR existing_event.request_id <> p_request_id
       OR existing_event.reason_code <> p_reason_code
       OR existing_event.actor_subject_id <> actor_id
       OR existing_event.issuer_confirmation_id <> p_issuer_confirmation_id THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Certificate revocation idempotency key conflicts with another request.';
    END IF;

    SELECT * INTO target
    FROM identity.certificates AS certificate
    WHERE certificate.tenant_id = identity.current_tenant_id()
      AND certificate.certificate_id = existing_event.certificate_id;

    IF NOT FOUND OR target.state <> 'revoked' OR target.last_event_id <> existing_event.event_id THEN
      RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Certificate revocation durable state is inconsistent.';
    END IF;

    RETURN QUERY SELECT target.certificate_id, existing_event.event_id,
      existing_event.correlation_id, target.state, target.version;
    RETURN;
  END IF;

  SELECT * INTO target
  FROM identity.certificates AS certificate
  WHERE certificate.tenant_id = identity.current_tenant_id()
    AND certificate.certificate_id = p_certificate_id
  FOR UPDATE;

  IF NOT FOUND
     OR target.state <> 'active'
     OR p_revoked_at < target.issued_at
     OR p_revoked_at >= target.not_after
     OR p_revoked_at > clock_timestamp() + interval '2 seconds'
     OR (target.subject_id <> actor_id AND NOT identity.current_actor_is_tenant_admin())
     OR NOT EXISTS (
       SELECT 1
       FROM identity.tenant_issuer_mappings AS issuer
       WHERE issuer.tenant_id = identity.current_tenant_id()
         AND issuer.issuer_id = target.issuer_id
         AND issuer.state = 'active'
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate revocation denied.';
  END IF;

  UPDATE identity.certificates
  SET state = 'revoked',
      state_changed_at = p_revoked_at,
      last_event_id = p_event_id,
      version = version + 1,
      updated_at = GREATEST(clock_timestamp(), p_revoked_at)
  WHERE tenant_id = identity.current_tenant_id()
    AND certificate_id = p_certificate_id;

  INSERT INTO identity.certificate_lifecycle_events (
    tenant_id, event_id, certificate_id, event_type, certificate_state,
    subject_id, issuer_id, serial_number, fingerprint_sha256, not_after,
    request_id, correlation_id, causation_event_id, idempotency_key,
    actor_subject_id, reason_code, issuer_confirmation_id, occurred_at
  ) VALUES (
    identity.current_tenant_id(), p_event_id, target.certificate_id,
    'revoked', 'revoked', target.subject_id, target.issuer_id,
    target.serial_number, target.fingerprint_sha256, target.not_after,
    p_request_id, p_correlation_id, target.last_event_id, p_idempotency_key,
    actor_id, p_reason_code, p_issuer_confirmation_id, p_revoked_at
  );

  RETURN QUERY SELECT target.certificate_id, p_event_id, p_correlation_id,
    'revoked'::identity.certificate_state, target.version + 1;
END
$function$;

COMMENT ON FUNCTION identity.record_certificate_revocation(
  identity.event_id, identity.correlation_id, identity.request_id,
  identity.certificate_id, identity.certificate_revocation_reason,
  timestamptz, identity.idempotency_key, identity.issuer_confirmation_id
) IS 'Atomically and idempotently revokes one active certificate after an issuer confirmation time within trusted clock skew';
