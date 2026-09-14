CREATE DOMAIN identity.certificate_id AS text
  CHECK (VALUE ~ '^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN identity.request_id AS text
  CHECK (VALUE ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN identity.event_id AS text
  CHECK (VALUE ~ '^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN identity.correlation_id AS text
  CHECK (VALUE ~ '^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN identity.certificate_profile_id AS text
  CHECK (VALUE ~ '^tenant-client-auth-v[1-9][0-9]*$');

CREATE DOMAIN identity.x509_serial_number AS text
  CHECK (VALUE ~ '^[0-9A-F]{32}$' AND VALUE <> repeat('0', 32));

CREATE DOMAIN identity.sha256_digest AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN identity.idempotency_key AS text
  CHECK (VALUE ~ '^[a-z0-9][a-z0-9._:/-]{7,159}$');

CREATE TYPE identity.certificate_state AS ENUM ('active', 'revoked', 'expired', 'superseded');
CREATE TYPE identity.certificate_lifecycle_event_type AS ENUM ('issued', 'renewed', 'revoked', 'expired', 'superseded');

CREATE TABLE identity.certificates (
  tenant_id identity.tenant_id NOT NULL,
  certificate_id identity.certificate_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  issuer_id identity.issuer_id NOT NULL,
  profile_id identity.certificate_profile_id NOT NULL,
  serial_number identity.x509_serial_number NOT NULL,
  fingerprint_sha256 identity.sha256_digest NOT NULL,
  public_key_algorithm text NOT NULL,
  state identity.certificate_state NOT NULL DEFAULT 'active',
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,
  issued_at timestamptz NOT NULL,
  state_changed_at timestamptz NOT NULL,
  requested_by_subject_id identity.subject_id NOT NULL,
  request_id identity.request_id NOT NULL,
  idempotency_key identity.idempotency_key NOT NULL,
  issued_event_id identity.event_id NOT NULL,
  last_event_id identity.event_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  supersedes_certificate_id identity.certificate_id,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT certificates_pk PRIMARY KEY (tenant_id, certificate_id),
  CONSTRAINT certificates_id_global_unique UNIQUE (certificate_id),
  CONSTRAINT certificates_tenant_fk FOREIGN KEY (tenant_id)
    REFERENCES identity.tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT certificates_subject_membership_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT certificates_requester_membership_fk FOREIGN KEY (tenant_id, requested_by_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT certificates_issuer_fk FOREIGN KEY (tenant_id, issuer_id)
    REFERENCES identity.tenant_issuer_mappings (tenant_id, issuer_id) ON DELETE RESTRICT,
  CONSTRAINT certificates_supersedes_fk FOREIGN KEY (tenant_id, supersedes_certificate_id)
    REFERENCES identity.certificates (tenant_id, certificate_id) ON DELETE RESTRICT,
  CONSTRAINT certificates_issuer_serial_unique UNIQUE (tenant_id, issuer_id, serial_number),
  CONSTRAINT certificates_fingerprint_unique UNIQUE (fingerprint_sha256),
  CONSTRAINT certificates_request_unique UNIQUE (tenant_id, request_id),
  CONSTRAINT certificates_idempotency_unique UNIQUE (tenant_id, idempotency_key),
  CONSTRAINT certificates_issued_event_unique UNIQUE (issued_event_id),
  CONSTRAINT certificates_algorithm_allowed CHECK (public_key_algorithm IN ('ecdsa-p256', 'ed25519')),
  CONSTRAINT certificates_validity_ordered CHECK (
    not_before <= issued_at
    AND issued_at < not_after
  ),
  CONSTRAINT certificates_initial_event_matches CHECK (
    version > 1 OR last_event_id = issued_event_id
  ),
  CONSTRAINT certificates_state_change_ordered CHECK (
    state_changed_at >= issued_at
    AND state_changed_at <= updated_at
  ),
  CONSTRAINT certificates_not_self_superseding CHECK (
    supersedes_certificate_id IS NULL OR supersedes_certificate_id <> certificate_id
  ),
  CONSTRAINT certificates_version_positive CHECK (version > 0),
  CONSTRAINT certificates_timestamps_ordered CHECK (
    created_at >= issued_at
    AND updated_at >= created_at
  )
);

CREATE INDEX certificates_subject_lookup
  ON identity.certificates (tenant_id, subject_id, state, not_after, certificate_id);

CREATE INDEX certificates_expiry_lookup
  ON identity.certificates (tenant_id, state, not_after, certificate_id);

CREATE TABLE identity.certificate_lifecycle_events (
  tenant_id identity.tenant_id NOT NULL,
  event_id identity.event_id NOT NULL,
  certificate_id identity.certificate_id NOT NULL,
  event_type identity.certificate_lifecycle_event_type NOT NULL,
  certificate_state identity.certificate_state NOT NULL,
  subject_id identity.subject_id NOT NULL,
  issuer_id identity.issuer_id NOT NULL,
  serial_number identity.x509_serial_number NOT NULL,
  fingerprint_sha256 identity.sha256_digest NOT NULL,
  not_after timestamptz NOT NULL,
  request_id identity.request_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  causation_event_id identity.event_id,
  idempotency_key identity.idempotency_key NOT NULL,
  actor_subject_id identity.subject_id NOT NULL,
  reason_code text,
  occurred_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT certificate_lifecycle_events_pk PRIMARY KEY (tenant_id, event_id),
  CONSTRAINT certificate_lifecycle_events_id_global_unique UNIQUE (event_id),
  CONSTRAINT certificate_lifecycle_events_certificate_fk FOREIGN KEY (tenant_id, certificate_id)
    REFERENCES identity.certificates (tenant_id, certificate_id) ON DELETE RESTRICT,
  CONSTRAINT certificate_lifecycle_events_actor_fk FOREIGN KEY (tenant_id, actor_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT certificate_lifecycle_events_idempotency_unique UNIQUE (tenant_id, idempotency_key, event_type),
  CONSTRAINT certificate_lifecycle_events_reason_format CHECK (
    reason_code IS NULL OR reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT certificate_lifecycle_events_recorded_after_occurrence CHECK (recorded_at >= occurred_at),
  CONSTRAINT certificate_lifecycle_events_issued_shape CHECK (
    event_type <> 'issued'
    OR (
      certificate_state = 'active'
      AND causation_event_id IS NULL
      AND reason_code IS NULL
    )
  )
);

CREATE INDEX certificate_lifecycle_events_certificate_time
  ON identity.certificate_lifecycle_events (tenant_id, certificate_id, occurred_at, event_id);

CREATE INDEX certificate_lifecycle_events_subject_time
  ON identity.certificate_lifecycle_events (tenant_id, subject_id, occurred_at, event_id);

CREATE FUNCTION identity.prevent_certificate_identity_rewrite()
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
     OR NEW.public_key_algorithm IS DISTINCT FROM OLD.public_key_algorithm
     OR NEW.not_before IS DISTINCT FROM OLD.not_before
     OR NEW.not_after IS DISTINCT FROM OLD.not_after
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.requested_by_subject_id IS DISTINCT FROM OLD.requested_by_subject_id
     OR NEW.request_id IS DISTINCT FROM OLD.request_id
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.issued_event_id IS DISTINCT FROM OLD.issued_event_id
     OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'Certificate identity and issuance metadata are immutable.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER certificates_keep_identity
BEFORE UPDATE ON identity.certificates
FOR EACH ROW EXECUTE FUNCTION identity.prevent_certificate_identity_rewrite();

CREATE FUNCTION identity.reject_certificate_lifecycle_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, identity
AS $function$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '42501',
    MESSAGE = 'Certificate lifecycle events are append-only.';
END
$function$;

CREATE TRIGGER certificate_lifecycle_events_append_only
BEFORE UPDATE OR DELETE ON identity.certificate_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION identity.reject_certificate_lifecycle_event_mutation();

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
       OR existing.public_key_algorithm <> p_public_key_algorithm
       OR existing.not_before <> p_not_before
       OR existing.not_after <> p_not_after
       OR existing.issued_at <> p_issued_at THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Certificate idempotency key conflicts with another issuance.';
    END IF;

    RETURN QUERY SELECT existing.certificate_id, existing.issued_event_id, existing.state;
    RETURN;
  END IF;

  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after,
    issued_at, state_changed_at, requested_by_subject_id, request_id,
    idempotency_key, issued_event_id, last_event_id, correlation_id
  ) VALUES (
    identity.current_tenant_id(), p_certificate_id, p_subject_id, p_issuer_id,
    p_profile_id, p_serial_number, p_fingerprint_sha256, p_public_key_algorithm,
    'active', p_not_before, p_not_after, p_issued_at, p_issued_at, actor_id,
    p_request_id, p_idempotency_key, p_event_id, p_event_id, p_correlation_id
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

ALTER TABLE identity.certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY certificates_current_actor_select
  ON identity.certificates
  FOR SELECT
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
    AND (
      subject_id = identity.current_subject_id()
      OR identity.current_actor_is_tenant_admin()
    )
  );

ALTER TABLE identity.certificate_lifecycle_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.certificate_lifecycle_events FORCE ROW LEVEL SECURITY;
CREATE POLICY certificate_lifecycle_events_current_actor_select
  ON identity.certificate_lifecycle_events
  FOR SELECT
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
    AND (
      subject_id = identity.current_subject_id()
      OR identity.current_actor_is_tenant_admin()
    )
  );

REVOKE ALL ON FUNCTION identity.prevent_certificate_identity_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.reject_certificate_lifecycle_event_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.record_certificate_issuance(
  identity.certificate_id, identity.event_id, identity.correlation_id,
  identity.request_id, identity.subject_id, identity.issuer_id,
  identity.certificate_profile_id, identity.x509_serial_number,
  identity.sha256_digest, text, timestamptz, timestamptz, timestamptz,
  identity.idempotency_key
) FROM PUBLIC;

GRANT SELECT ON identity.certificates, identity.certificate_lifecycle_events TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION identity.record_certificate_issuance(
  identity.certificate_id, identity.event_id, identity.correlation_id,
  identity.request_id, identity.subject_id, identity.issuer_id,
  identity.certificate_profile_id, identity.x509_serial_number,
  identity.sha256_digest, text, timestamptz, timestamptz, timestamptz,
  identity.idempotency_key
) TO tenant_trust_app;

COMMENT ON DOMAIN identity.certificate_id IS 'Opaque certificate identifier matching the shared crt_UUID contract';
COMMENT ON DOMAIN identity.event_id IS 'Opaque lifecycle event identifier matching the shared evt_UUID contract';
COMMENT ON TABLE identity.certificates IS 'Authoritative tenant-qualified certificate inventory and current lifecycle state';
COMMENT ON TABLE identity.certificate_lifecycle_events IS 'Append-only tenant-qualified certificate lifecycle history';
COMMENT ON FUNCTION identity.record_certificate_issuance(
  identity.certificate_id, identity.event_id, identity.correlation_id,
  identity.request_id, identity.subject_id, identity.issuer_id,
  identity.certificate_profile_id, identity.x509_serial_number,
  identity.sha256_digest, text, timestamptz, timestamptz, timestamptz,
  identity.idempotency_key
) IS 'Atomically records a verified issued certificate and its initial lifecycle event for the bound tenant actor';
