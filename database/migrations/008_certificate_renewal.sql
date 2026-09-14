ALTER TABLE identity.certificates
  ADD COLUMN public_key_sha256 identity.sha256_digest;

COMMENT ON COLUMN identity.certificates.public_key_sha256 IS
  'SHA-256 digest of canonical SubjectPublicKeyInfo; legacy null rows fail renewal closed';

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
  RETURN NEW;
END
$function$;

REVOKE ALL ON FUNCTION identity.record_certificate_issuance(
  identity.certificate_id, identity.event_id, identity.correlation_id,
  identity.request_id, identity.subject_id, identity.issuer_id,
  identity.certificate_profile_id, identity.x509_serial_number,
  identity.sha256_digest, text, timestamptz, timestamptz, timestamptz,
  identity.idempotency_key
) FROM tenant_trust_app;

DROP FUNCTION identity.record_certificate_issuance(
  identity.certificate_id, identity.event_id, identity.correlation_id,
  identity.request_id, identity.subject_id, identity.issuer_id,
  identity.certificate_profile_id, identity.x509_serial_number,
  identity.sha256_digest, text, timestamptz, timestamptz, timestamptz,
  identity.idempotency_key
);

CREATE FUNCTION identity.record_certificate_issuance(
  p_certificate_id identity.certificate_id,
  p_event_id identity.event_id,
  p_correlation_id identity.correlation_id,
  p_request_id identity.request_id,
  p_subject_id identity.subject_id,
  p_issuer_id identity.issuer_id,
  p_profile_id identity.certificate_profile_id,
  p_serial_number identity.x509_serial_number,
  p_fingerprint_sha256 identity.sha256_digest,
  p_public_key_sha256 identity.sha256_digest,
  p_public_key_algorithm text,
  p_not_before timestamptz,
  p_not_after timestamptz,
  p_issued_at timestamptz,
  p_idempotency_key identity.idempotency_key
)
RETURNS TABLE (
  recorded_certificate_id identity.certificate_id,
  recorded_event_id identity.event_id,
  recorded_state identity.certificate_state
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
DECLARE
  actor_id identity.subject_id := identity.current_subject_id();
  existing identity.certificates%ROWTYPE;
BEGIN
  IF NOT identity.current_actor_is_active() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate inventory write denied.';
  END IF;
  IF p_subject_id <> actor_id AND NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate inventory write denied.';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM identity.tenant_memberships AS membership
    JOIN identity.subjects AS subject ON subject.subject_id = membership.subject_id
    WHERE membership.tenant_id = identity.current_tenant_id()
      AND membership.subject_id = p_subject_id
      AND membership.state = 'active'
      AND subject.state = 'active'
  ) OR NOT EXISTS (
    SELECT 1
    FROM identity.tenant_issuer_mappings AS issuer
    WHERE issuer.tenant_id = identity.current_tenant_id()
      AND issuer.issuer_id = p_issuer_id
      AND issuer.state = 'active'
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate inventory write denied.';
  END IF;

  SELECT * INTO existing
  FROM identity.certificates AS certificate
  WHERE certificate.tenant_id = identity.current_tenant_id()
    AND certificate.idempotency_key = p_idempotency_key;

  IF FOUND THEN
    IF existing.request_id <> p_request_id
       OR existing.subject_id <> p_subject_id
       OR existing.issuer_id <> p_issuer_id
       OR existing.profile_id <> p_profile_id
       OR existing.serial_number <> p_serial_number
       OR existing.fingerprint_sha256 <> p_fingerprint_sha256
       OR existing.public_key_sha256 IS DISTINCT FROM p_public_key_sha256
       OR existing.public_key_algorithm <> p_public_key_algorithm
       OR existing.not_before <> p_not_before
       OR existing.not_after <> p_not_after
       OR existing.issued_at <> p_issued_at
       OR existing.supersedes_certificate_id IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Certificate idempotency key conflicts with another issuance.';
    END IF;
    RETURN QUERY SELECT existing.certificate_id, existing.issued_event_id, existing.state;
    RETURN;
  END IF;

  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_sha256, public_key_algorithm, state,
    not_before, not_after, issued_at, state_changed_at, requested_by_subject_id,
    request_id, idempotency_key, issued_event_id, last_event_id, correlation_id
  ) VALUES (
    identity.current_tenant_id(), p_certificate_id, p_subject_id, p_issuer_id,
    p_profile_id, p_serial_number, p_fingerprint_sha256, p_public_key_sha256,
    p_public_key_algorithm, 'active', p_not_before, p_not_after, p_issued_at,
    p_issued_at, actor_id, p_request_id, p_idempotency_key, p_event_id,
    p_event_id, p_correlation_id
  );

  INSERT INTO identity.certificate_lifecycle_events (
    tenant_id, event_id, certificate_id, event_type, certificate_state,
    subject_id, issuer_id, serial_number, fingerprint_sha256, not_after,
    request_id, correlation_id, causation_event_id, idempotency_key,
    actor_subject_id, occurred_at
  ) VALUES (
    identity.current_tenant_id(), p_event_id, p_certificate_id, 'issued', 'active',
    p_subject_id, p_issuer_id, p_serial_number, p_fingerprint_sha256, p_not_after,
    p_request_id, p_correlation_id, NULL, p_idempotency_key, actor_id, p_issued_at
  );

  RETURN QUERY SELECT p_certificate_id, p_event_id, 'active'::identity.certificate_state;
END
$function$;

CREATE FUNCTION identity.record_certificate_renewal(
  p_certificate_id identity.certificate_id,
  p_renewed_event_id identity.event_id,
  p_superseded_event_id identity.event_id,
  p_correlation_id identity.correlation_id,
  p_request_id identity.request_id,
  p_supersedes_certificate_id identity.certificate_id,
  p_subject_id identity.subject_id,
  p_issuer_id identity.issuer_id,
  p_profile_id identity.certificate_profile_id,
  p_serial_number identity.x509_serial_number,
  p_fingerprint_sha256 identity.sha256_digest,
  p_public_key_sha256 identity.sha256_digest,
  p_public_key_algorithm text,
  p_not_before timestamptz,
  p_not_after timestamptz,
  p_issued_at timestamptz,
  p_idempotency_key identity.idempotency_key
)
RETURNS TABLE (
  recorded_certificate_id identity.certificate_id,
  recorded_renewed_event_id identity.event_id,
  recorded_superseded_event_id identity.event_id,
  recorded_state identity.certificate_state,
  recorded_predecessor_state identity.certificate_state
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
DECLARE
  actor_id identity.subject_id := identity.current_subject_id();
  existing identity.certificates%ROWTYPE;
  predecessor identity.certificates%ROWTYPE;
  durable_renewed_event_id identity.event_id;
  durable_superseded_event_id identity.event_id;
BEGIN
  IF p_renewed_event_id = p_superseded_event_id
     OR NOT identity.current_actor_is_active() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate renewal denied.';
  END IF;
  IF p_subject_id <> actor_id AND NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate renewal denied.';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM identity.tenant_memberships AS membership
    JOIN identity.subjects AS subject ON subject.subject_id = membership.subject_id
    WHERE membership.tenant_id = identity.current_tenant_id()
      AND membership.subject_id = p_subject_id
      AND membership.state = 'active'
      AND subject.state = 'active'
  ) OR NOT EXISTS (
    SELECT 1
    FROM identity.tenant_issuer_mappings AS issuer
    WHERE issuer.tenant_id = identity.current_tenant_id()
      AND issuer.issuer_id = p_issuer_id
      AND issuer.state = 'active'
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate renewal denied.';
  END IF;

  SELECT * INTO existing
  FROM identity.certificates AS certificate
  WHERE certificate.tenant_id = identity.current_tenant_id()
    AND certificate.idempotency_key = p_idempotency_key;

  IF FOUND THEN
    IF existing.request_id <> p_request_id
       OR existing.subject_id <> p_subject_id
       OR existing.issuer_id <> p_issuer_id
       OR existing.profile_id <> p_profile_id
       OR existing.serial_number <> p_serial_number
       OR existing.fingerprint_sha256 <> p_fingerprint_sha256
       OR existing.public_key_sha256 IS DISTINCT FROM p_public_key_sha256
       OR existing.public_key_algorithm <> p_public_key_algorithm
       OR existing.not_before <> p_not_before
       OR existing.not_after <> p_not_after
       OR existing.issued_at <> p_issued_at
       OR existing.supersedes_certificate_id IS DISTINCT FROM p_supersedes_certificate_id THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Certificate idempotency key conflicts with another renewal.';
    END IF;
    SELECT event_id INTO durable_renewed_event_id
    FROM identity.certificate_lifecycle_events
    WHERE tenant_id = identity.current_tenant_id()
      AND idempotency_key = p_idempotency_key
      AND event_type = 'renewed';
    SELECT event_id INTO durable_superseded_event_id
    FROM identity.certificate_lifecycle_events
    WHERE tenant_id = identity.current_tenant_id()
      AND idempotency_key = p_idempotency_key
      AND event_type = 'superseded';
    RETURN QUERY SELECT existing.certificate_id, durable_renewed_event_id,
      durable_superseded_event_id, existing.state, 'superseded'::identity.certificate_state;
    RETURN;
  END IF;

  SELECT * INTO predecessor
  FROM identity.certificates AS certificate
  WHERE certificate.tenant_id = identity.current_tenant_id()
    AND certificate.certificate_id = p_supersedes_certificate_id
  FOR UPDATE;

  IF NOT FOUND
     OR predecessor.subject_id <> p_subject_id
     OR predecessor.profile_id <> p_profile_id
     OR predecessor.state <> 'active'
     OR predecessor.public_key_sha256 IS NULL
     OR predecessor.public_key_sha256 = p_public_key_sha256
     OR p_issued_at < predecessor.not_before
     OR p_issued_at >= predecessor.not_after
     OR p_issued_at < predecessor.not_after - ((predecessor.not_after - predecessor.not_before) / 4.0) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate renewal denied.';
  END IF;

  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_sha256, public_key_algorithm, state,
    not_before, not_after, issued_at, state_changed_at, requested_by_subject_id,
    request_id, idempotency_key, issued_event_id, last_event_id, correlation_id,
    supersedes_certificate_id
  ) VALUES (
    identity.current_tenant_id(), p_certificate_id, p_subject_id, p_issuer_id,
    p_profile_id, p_serial_number, p_fingerprint_sha256, p_public_key_sha256,
    p_public_key_algorithm, 'active', p_not_before, p_not_after, p_issued_at,
    p_issued_at, actor_id, p_request_id, p_idempotency_key, p_renewed_event_id,
    p_renewed_event_id, p_correlation_id, p_supersedes_certificate_id
  );

  INSERT INTO identity.certificate_lifecycle_events (
    tenant_id, event_id, certificate_id, event_type, certificate_state,
    subject_id, issuer_id, serial_number, fingerprint_sha256, not_after,
    request_id, correlation_id, causation_event_id, idempotency_key,
    actor_subject_id, occurred_at
  ) VALUES (
    identity.current_tenant_id(), p_renewed_event_id, p_certificate_id,
    'renewed', 'active', p_subject_id, p_issuer_id, p_serial_number,
    p_fingerprint_sha256, p_not_after, p_request_id, p_correlation_id,
    predecessor.last_event_id, p_idempotency_key, actor_id, p_issued_at
  );

  UPDATE identity.certificates
  SET state = 'superseded',
      state_changed_at = p_issued_at,
      last_event_id = p_superseded_event_id,
      version = version + 1,
      updated_at = GREATEST(clock_timestamp(), p_issued_at)
  WHERE tenant_id = identity.current_tenant_id()
    AND certificate_id = p_supersedes_certificate_id;

  INSERT INTO identity.certificate_lifecycle_events (
    tenant_id, event_id, certificate_id, event_type, certificate_state,
    subject_id, issuer_id, serial_number, fingerprint_sha256, not_after,
    request_id, correlation_id, causation_event_id, idempotency_key,
    actor_subject_id, reason_code, occurred_at
  ) VALUES (
    identity.current_tenant_id(), p_superseded_event_id,
    p_supersedes_certificate_id, 'superseded', 'superseded',
    predecessor.subject_id, predecessor.issuer_id, predecessor.serial_number,
    predecessor.fingerprint_sha256, predecessor.not_after, p_request_id,
    p_correlation_id, p_renewed_event_id, p_idempotency_key, actor_id,
    'CERTIFICATE_RENEWED', p_issued_at
  );

  RETURN QUERY SELECT p_certificate_id, p_renewed_event_id,
    p_superseded_event_id, 'active'::identity.certificate_state,
    'superseded'::identity.certificate_state;
END
$function$;

REVOKE ALL ON FUNCTION identity.record_certificate_issuance(
  identity.certificate_id, identity.event_id, identity.correlation_id,
  identity.request_id, identity.subject_id, identity.issuer_id,
  identity.certificate_profile_id, identity.x509_serial_number,
  identity.sha256_digest, identity.sha256_digest, text, timestamptz,
  timestamptz, timestamptz, identity.idempotency_key
) FROM PUBLIC;

REVOKE ALL ON FUNCTION identity.record_certificate_renewal(
  identity.certificate_id, identity.event_id, identity.event_id,
  identity.correlation_id, identity.request_id, identity.certificate_id,
  identity.subject_id, identity.issuer_id, identity.certificate_profile_id,
  identity.x509_serial_number, identity.sha256_digest, identity.sha256_digest,
  text, timestamptz, timestamptz, timestamptz, identity.idempotency_key
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION identity.record_certificate_issuance(
  identity.certificate_id, identity.event_id, identity.correlation_id,
  identity.request_id, identity.subject_id, identity.issuer_id,
  identity.certificate_profile_id, identity.x509_serial_number,
  identity.sha256_digest, identity.sha256_digest, text, timestamptz,
  timestamptz, timestamptz, identity.idempotency_key
) TO tenant_trust_app;

GRANT EXECUTE ON FUNCTION identity.record_certificate_renewal(
  identity.certificate_id, identity.event_id, identity.event_id,
  identity.correlation_id, identity.request_id, identity.certificate_id,
  identity.subject_id, identity.issuer_id, identity.certificate_profile_id,
  identity.x509_serial_number, identity.sha256_digest, identity.sha256_digest,
  text, timestamptz, timestamptz, timestamptz, identity.idempotency_key
) TO tenant_trust_app;

COMMENT ON FUNCTION identity.record_certificate_issuance(
  identity.certificate_id, identity.event_id, identity.correlation_id,
  identity.request_id, identity.subject_id, identity.issuer_id,
  identity.certificate_profile_id, identity.x509_serial_number,
  identity.sha256_digest, identity.sha256_digest, text, timestamptz,
  timestamptz, timestamptz, identity.idempotency_key
) IS 'Atomically records a verified issued certificate, SPKI digest and initial lifecycle event for the bound tenant actor';

COMMENT ON FUNCTION identity.record_certificate_renewal(
  identity.certificate_id, identity.event_id, identity.event_id,
  identity.correlation_id, identity.request_id, identity.certificate_id,
  identity.subject_id, identity.issuer_id, identity.certificate_profile_id,
  identity.x509_serial_number, identity.sha256_digest, identity.sha256_digest,
  text, timestamptz, timestamptz, timestamptz, identity.idempotency_key
) IS 'Atomically records a fresh-key renewal, activates its certificate, supersedes the locked predecessor and appends both lifecycle events';
