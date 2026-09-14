CREATE DOMAIN identity.certificate_revocation_reason AS text
  CHECK (VALUE IN (
    'KEY_COMPROMISE',
    'CA_COMPROMISE',
    'AFFILIATION_CHANGED',
    'SUPERSEDED',
    'CESSATION_OF_OPERATION',
    'PRIVILEGE_WITHDRAWN',
    'AA_COMPROMISE'
  ));

CREATE DOMAIN identity.issuer_confirmation_id AS text
  CHECK (
    length(VALUE) BETWEEN 8 AND 256
    AND VALUE ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]+$'
  );

ALTER TABLE identity.certificate_lifecycle_events
  ADD COLUMN issuer_confirmation_id identity.issuer_confirmation_id,
  ADD CONSTRAINT certificate_lifecycle_events_revocation_shape CHECK (
    (
      event_type = 'revoked'
      AND certificate_state = 'revoked'
      AND causation_event_id IS NOT NULL
      AND reason_code IS NOT NULL
      AND issuer_confirmation_id IS NOT NULL
    )
    OR (
      event_type <> 'revoked'
      AND issuer_confirmation_id IS NULL
    )
  );

CREATE UNIQUE INDEX certificate_revocation_request_unique
  ON identity.certificate_lifecycle_events (tenant_id, request_id)
  WHERE event_type = 'revoked';

CREATE UNIQUE INDEX certificate_revocation_confirmation_unique
  ON identity.certificate_lifecycle_events (tenant_id, issuer_id, issuer_confirmation_id)
  WHERE issuer_confirmation_id IS NOT NULL;

CREATE OR REPLACE FUNCTION identity.prevent_certificate_identity_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, identity
AS $function$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.certificate_id IS DISTINCT FROM OLD.certificate_id
     OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
     OR NEW.issuer_id IS DISTINCT FROM OLD.issuer_id
     OR NEW.profile_id IS DISTINCT FROM OLD.profile_id
     OR NEW.serial_number IS DISTINCT FROM OLD.serial_number
     OR NEW.fingerprint_sha256 IS DISTINCT FROM OLD.fingerprint_sha256
     OR NEW.public_key_sha256 IS DISTINCT FROM OLD.public_key_sha256
     OR NEW.public_key_algorithm IS DISTINCT FROM OLD.public_key_algorithm
     OR NEW.not_before IS DISTINCT FROM OLD.not_before
     OR NEW.not_after IS DISTINCT FROM OLD.not_after
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.requested_by_subject_id IS DISTINCT FROM OLD.requested_by_subject_id
     OR NEW.request_id IS DISTINCT FROM OLD.request_id
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.issued_event_id IS DISTINCT FROM OLD.issued_event_id
     OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
     OR NEW.supersedes_certificate_id IS DISTINCT FROM OLD.supersedes_certificate_id THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'Certificate identity and issuance metadata are immutable.';
  END IF;

  IF OLD.state <> 'active' AND NEW.state IS DISTINCT FROM OLD.state THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'A terminal certificate state is immutable.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE FUNCTION identity.record_certificate_revocation(
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

REVOKE ALL ON FUNCTION identity.record_certificate_revocation(
  identity.event_id, identity.correlation_id, identity.request_id,
  identity.certificate_id, identity.certificate_revocation_reason,
  timestamptz, identity.idempotency_key, identity.issuer_confirmation_id
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION identity.record_certificate_revocation(
  identity.event_id, identity.correlation_id, identity.request_id,
  identity.certificate_id, identity.certificate_revocation_reason,
  timestamptz, identity.idempotency_key, identity.issuer_confirmation_id
) TO tenant_trust_app;

COMMENT ON DOMAIN identity.certificate_revocation_reason IS
  'Permanent RFC 5280 revocation reasons supported by the application contract; reversible hold reasons are excluded';
COMMENT ON COLUMN identity.certificate_lifecycle_events.issuer_confirmation_id IS
  'Opaque authenticated issuer confirmation retained for a permanent revocation';
COMMENT ON FUNCTION identity.record_certificate_revocation(
  identity.event_id, identity.correlation_id, identity.request_id,
  identity.certificate_id, identity.certificate_revocation_reason,
  timestamptz, identity.idempotency_key, identity.issuer_confirmation_id
) IS 'Atomically and idempotently revokes one active certificate for its owner or a same-tenant administrator and appends the reasoned issuer-confirmed lifecycle event';
