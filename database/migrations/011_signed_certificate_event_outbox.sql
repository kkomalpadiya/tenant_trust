CREATE DOMAIN identity.certificate_event_claim_token AS text
  CHECK (VALUE ~ '^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TYPE identity.certificate_event_delivery_state AS ENUM ('pending', 'publishing', 'published');

DO $create_certificate_event_worker$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_certificate_event_worker') THEN
    CREATE ROLE tenant_trust_certificate_event_worker;
  END IF;
END
$create_certificate_event_worker$;

ALTER ROLE tenant_trust_certificate_event_worker
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS
  PASSWORD NULL;

ALTER TABLE identity.certificate_lifecycle_events
  ALTER COLUMN actor_subject_id DROP NOT NULL,
  ADD CONSTRAINT certificate_lifecycle_events_expired_shape CHECK (
    event_type <> 'expired'
    OR (
      certificate_state = 'expired'
      AND causation_event_id IS NOT NULL
      AND reason_code = 'CERTIFICATE_EXPIRED'
      AND issuer_confirmation_id IS NULL
    )
  );

CREATE UNIQUE INDEX certificate_expiration_event_unique
  ON identity.certificate_lifecycle_events (tenant_id, certificate_id)
  WHERE event_type = 'expired';

CREATE TABLE identity.certificate_event_outbox (
  tenant_id identity.tenant_id NOT NULL,
  event_id identity.event_id NOT NULL,
  status identity.certificate_event_delivery_state NOT NULL DEFAULT 'pending',
  claim_token identity.certificate_event_claim_token,
  claimed_by text,
  claimed_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_failure_code text,
  stream_sequence bigint,
  signed_event_sha256 identity.sha256_digest,
  published_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT certificate_event_outbox_pk PRIMARY KEY (tenant_id, event_id),
  CONSTRAINT certificate_event_outbox_event_fk FOREIGN KEY (tenant_id, event_id)
    REFERENCES identity.certificate_lifecycle_events (tenant_id, event_id) ON DELETE RESTRICT,
  CONSTRAINT certificate_event_outbox_attempt_positive CHECK (attempt_count >= 0),
  CONSTRAINT certificate_event_outbox_worker_format CHECK (
    claimed_by IS NULL OR claimed_by ~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
  ),
  CONSTRAINT certificate_event_outbox_failure_format CHECK (
    last_failure_code IS NULL OR last_failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT certificate_event_outbox_sequence_positive CHECK (
    stream_sequence IS NULL OR stream_sequence > 0
  ),
  CONSTRAINT certificate_event_outbox_state_shape CHECK (
    (
      status = 'pending'
      AND claim_token IS NULL
      AND claimed_by IS NULL
      AND claimed_at IS NULL
      AND stream_sequence IS NULL
      AND signed_event_sha256 IS NULL
      AND published_at IS NULL
    )
    OR (
      status = 'publishing'
      AND claim_token IS NOT NULL
      AND claimed_by IS NOT NULL
      AND claimed_at IS NOT NULL
      AND stream_sequence IS NULL
      AND signed_event_sha256 IS NULL
      AND published_at IS NULL
    )
    OR (
      status = 'published'
      AND claim_token IS NULL
      AND claimed_by IS NULL
      AND claimed_at IS NULL
      AND stream_sequence IS NOT NULL
      AND signed_event_sha256 IS NOT NULL
      AND published_at IS NOT NULL
    )
  ),
  CONSTRAINT certificate_event_outbox_time_order CHECK (
    updated_at >= created_at
    AND (claimed_at IS NULL OR claimed_at >= created_at)
    AND (published_at IS NULL OR published_at >= created_at)
  )
);

CREATE INDEX certificate_event_outbox_pending
  ON identity.certificate_event_outbox (tenant_id, next_attempt_at, created_at, event_id)
  WHERE status = 'pending';

CREATE FUNCTION identity.enqueue_certificate_lifecycle_event()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
BEGIN
  INSERT INTO identity.certificate_event_outbox (tenant_id, event_id, created_at, updated_at)
  VALUES (NEW.tenant_id, NEW.event_id, NEW.recorded_at, NEW.recorded_at)
  ON CONFLICT (tenant_id, event_id) DO NOTHING;
  RETURN NEW;
END
$function$;

CREATE TRIGGER certificate_lifecycle_event_enqueue
AFTER INSERT ON identity.certificate_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION identity.enqueue_certificate_lifecycle_event();

INSERT INTO identity.certificate_event_outbox (tenant_id, event_id, created_at, updated_at)
SELECT tenant_id, event_id, recorded_at, recorded_at
FROM identity.certificate_lifecycle_events
ON CONFLICT (tenant_id, event_id) DO NOTHING;

CREATE FUNCTION identity.record_due_certificate_expiration(
  p_tenant_id identity.tenant_id,
  p_certificate_id identity.certificate_id,
  p_event_id identity.event_id,
  p_correlation_id identity.correlation_id,
  p_expired_at timestamptz
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
  target identity.certificates%ROWTYPE;
  existing identity.certificate_lifecycle_events%ROWTYPE;
  expiration_key identity.idempotency_key := ('certificate-expiry:' || p_certificate_id)::identity.idempotency_key;
BEGIN
  SELECT * INTO target
  FROM identity.certificates AS certificate
  WHERE certificate.tenant_id = p_tenant_id
    AND certificate.certificate_id = p_certificate_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate expiration denied.';
  END IF;

  IF target.state = 'expired' THEN
    SELECT * INTO existing
    FROM identity.certificate_lifecycle_events AS event
    WHERE event.tenant_id = p_tenant_id
      AND event.certificate_id = p_certificate_id
      AND event.event_type = 'expired';
    IF NOT FOUND OR target.last_event_id <> existing.event_id THEN
      RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Certificate expiration durable state is inconsistent.';
    END IF;
    RETURN QUERY SELECT target.certificate_id, existing.event_id,
      existing.correlation_id, target.state, target.version;
    RETURN;
  END IF;

  IF target.state <> 'active'
     OR p_expired_at < target.not_after
     OR p_expired_at > clock_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate expiration denied.';
  END IF;

  UPDATE identity.certificates
  SET state = 'expired',
      state_changed_at = p_expired_at,
      last_event_id = p_event_id,
      version = version + 1,
      updated_at = GREATEST(clock_timestamp(), p_expired_at)
  WHERE tenant_id = p_tenant_id
    AND certificate_id = p_certificate_id;

  INSERT INTO identity.certificate_lifecycle_events (
    tenant_id, event_id, certificate_id, event_type, certificate_state,
    subject_id, issuer_id, serial_number, fingerprint_sha256, not_after,
    request_id, correlation_id, causation_event_id, idempotency_key,
    actor_subject_id, reason_code, occurred_at
  ) VALUES (
    p_tenant_id, p_event_id, target.certificate_id, 'expired', 'expired',
    target.subject_id, target.issuer_id, target.serial_number,
    target.fingerprint_sha256, target.not_after, target.request_id,
    p_correlation_id, target.last_event_id, expiration_key, NULL,
    'CERTIFICATE_EXPIRED', p_expired_at
  );

  RETURN QUERY SELECT target.certificate_id, p_event_id, p_correlation_id,
    'expired'::identity.certificate_state, target.version + 1;
END
$function$;

CREATE FUNCTION identity.claim_certificate_event_outbox(
  p_tenant_id identity.tenant_id,
  p_worker_id text,
  p_claim_token identity.certificate_event_claim_token,
  p_claimed_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  event_id identity.event_id,
  event_type identity.certificate_lifecycle_event_type,
  certificate_state identity.certificate_state,
  certificate_id identity.certificate_id,
  subject_id identity.subject_id,
  issuer_id identity.issuer_id,
  serial_number identity.x509_serial_number,
  fingerprint_sha256 identity.sha256_digest,
  not_before timestamptz,
  not_after timestamptz,
  supersedes_certificate_id identity.certificate_id,
  request_id identity.request_id,
  correlation_id identity.correlation_id,
  causation_event_id identity.event_id,
  idempotency_key identity.idempotency_key,
  actor_subject_id identity.subject_id,
  reason_code text,
  issuer_confirmation_id identity.issuer_confirmation_id,
  occurred_at timestamptz,
  recorded_at timestamptz,
  claim_token identity.certificate_event_claim_token,
  attempt_count integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
BEGIN
  IF p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
     OR p_claimed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate event outbox claim denied.';
  END IF;

  UPDATE identity.certificate_event_outbox AS outbox
  SET status = 'pending',
      claim_token = NULL,
      claimed_by = NULL,
      claimed_at = NULL,
      next_attempt_at = p_claimed_at,
      last_failure_code = 'STALE_CLAIM_RECOVERED',
      updated_at = GREATEST(clock_timestamp(), p_claimed_at)
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.status = 'publishing'
    AND outbox.claimed_at < p_claimed_at - interval '5 minutes';

  RETURN QUERY
  WITH candidate AS (
    SELECT outbox.tenant_id, outbox.event_id
    FROM identity.certificate_event_outbox AS outbox
    WHERE outbox.tenant_id = p_tenant_id
      AND outbox.status = 'pending'
      AND outbox.next_attempt_at <= p_claimed_at
    ORDER BY outbox.created_at, outbox.event_id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
  ), claimed AS (
    UPDATE identity.certificate_event_outbox AS outbox
    SET status = 'publishing',
        claim_token = p_claim_token,
        claimed_by = p_worker_id,
        claimed_at = p_claimed_at,
        attempt_count = outbox.attempt_count + 1,
        last_failure_code = NULL,
        updated_at = GREATEST(clock_timestamp(), p_claimed_at)
    FROM candidate
    WHERE outbox.tenant_id = candidate.tenant_id
      AND outbox.event_id = candidate.event_id
    RETURNING outbox.tenant_id, outbox.event_id, outbox.claim_token, outbox.attempt_count
  )
  SELECT event.tenant_id, event.event_id, event.event_type,
    event.certificate_state, event.certificate_id, event.subject_id,
    event.issuer_id, event.serial_number, event.fingerprint_sha256,
    certificate.not_before, event.not_after, certificate.supersedes_certificate_id,
    event.request_id, event.correlation_id, event.causation_event_id,
    event.idempotency_key, event.actor_subject_id, event.reason_code,
    event.issuer_confirmation_id, event.occurred_at, event.recorded_at,
    claimed.claim_token, claimed.attempt_count
  FROM claimed
  JOIN identity.certificate_lifecycle_events AS event
    ON event.tenant_id = claimed.tenant_id AND event.event_id = claimed.event_id
  JOIN identity.certificates AS certificate
    ON certificate.tenant_id = event.tenant_id AND certificate.certificate_id = event.certificate_id;
END
$function$;

CREATE FUNCTION identity.mark_certificate_event_published(
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_claim_token identity.certificate_event_claim_token,
  p_stream_sequence bigint,
  p_signed_event_sha256 identity.sha256_digest,
  p_published_at timestamptz
)
RETURNS TABLE (
  event_id identity.event_id,
  status identity.certificate_event_delivery_state,
  stream_sequence bigint,
  signed_event_sha256 identity.sha256_digest
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
DECLARE
  updated identity.certificate_event_outbox%ROWTYPE;
BEGIN
  IF p_stream_sequence < 1 OR p_published_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate event publish confirmation denied.';
  END IF;
  UPDATE identity.certificate_event_outbox AS outbox
  SET status = 'published', claim_token = NULL, claimed_by = NULL,
      claimed_at = NULL, stream_sequence = p_stream_sequence,
      signed_event_sha256 = p_signed_event_sha256, published_at = p_published_at,
      last_failure_code = NULL, updated_at = GREATEST(clock_timestamp(), p_published_at)
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.event_id = p_event_id
    AND outbox.status = 'publishing'
    AND outbox.claim_token = p_claim_token
  RETURNING outbox.* INTO updated;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate event publish confirmation denied.';
  END IF;
  RETURN QUERY SELECT updated.event_id, updated.status,
    updated.stream_sequence, updated.signed_event_sha256;
END
$function$;

CREATE FUNCTION identity.mark_certificate_event_publish_failed(
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_claim_token identity.certificate_event_claim_token,
  p_failure_code text,
  p_failed_at timestamptz,
  p_retry_delay_seconds integer
)
RETURNS TABLE (event_id identity.event_id, status identity.certificate_event_delivery_state)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
DECLARE
  updated identity.certificate_event_outbox%ROWTYPE;
BEGIN
  IF p_failure_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_retry_delay_seconds < 1 OR p_retry_delay_seconds > 600
     OR p_failed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate event publish failure update denied.';
  END IF;
  UPDATE identity.certificate_event_outbox AS outbox
  SET status = 'pending', claim_token = NULL, claimed_by = NULL,
      claimed_at = NULL, next_attempt_at = p_failed_at + make_interval(secs => p_retry_delay_seconds),
      last_failure_code = p_failure_code, updated_at = GREATEST(clock_timestamp(), p_failed_at)
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.event_id = p_event_id
    AND outbox.status = 'publishing'
    AND outbox.claim_token = p_claim_token
  RETURNING outbox.* INTO updated;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate event publish failure update denied.';
  END IF;
  RETURN QUERY SELECT updated.event_id, updated.status;
END
$function$;

REVOKE ALL ON TABLE identity.certificate_event_outbox FROM PUBLIC, tenant_trust_app, tenant_trust_certificate_event_worker;
REVOKE ALL ON FUNCTION identity.enqueue_certificate_lifecycle_event() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.record_due_certificate_expiration(identity.tenant_id, identity.certificate_id, identity.event_id, identity.correlation_id, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.claim_certificate_event_outbox(identity.tenant_id, text, identity.certificate_event_claim_token, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.mark_certificate_event_published(identity.tenant_id, identity.event_id, identity.certificate_event_claim_token, bigint, identity.sha256_digest, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.mark_certificate_event_publish_failed(identity.tenant_id, identity.event_id, identity.certificate_event_claim_token, text, timestamptz, integer) FROM PUBLIC;

GRANT USAGE ON SCHEMA identity TO tenant_trust_certificate_event_worker;
GRANT EXECUTE ON FUNCTION identity.record_due_certificate_expiration(identity.tenant_id, identity.certificate_id, identity.event_id, identity.correlation_id, timestamptz) TO tenant_trust_certificate_event_worker;
GRANT EXECUTE ON FUNCTION identity.claim_certificate_event_outbox(identity.tenant_id, text, identity.certificate_event_claim_token, timestamptz) TO tenant_trust_certificate_event_worker;
GRANT EXECUTE ON FUNCTION identity.mark_certificate_event_published(identity.tenant_id, identity.event_id, identity.certificate_event_claim_token, bigint, identity.sha256_digest, timestamptz) TO tenant_trust_certificate_event_worker;
GRANT EXECUTE ON FUNCTION identity.mark_certificate_event_publish_failed(identity.tenant_id, identity.event_id, identity.certificate_event_claim_token, text, timestamptz, integer) TO tenant_trust_certificate_event_worker;

COMMENT ON TABLE identity.certificate_event_outbox IS 'Transactional delivery state for source-authenticated certificate lifecycle events';
COMMENT ON ROLE tenant_trust_certificate_event_worker IS 'NOLOGIN privilege set for the cross-tenant certificate expiry and signed-event publisher worker';
COMMENT ON FUNCTION identity.record_due_certificate_expiration(identity.tenant_id, identity.certificate_id, identity.event_id, identity.correlation_id, timestamptz) IS 'Atomically expires one due active certificate and appends its causal lifecycle event';
COMMENT ON FUNCTION identity.claim_certificate_event_outbox(identity.tenant_id, text, identity.certificate_event_claim_token, timestamptz) IS 'Claims the oldest due certificate lifecycle event for one tenant without granting direct outbox access';
COMMENT ON FUNCTION identity.mark_certificate_event_published(identity.tenant_id, identity.event_id, identity.certificate_event_claim_token, bigint, identity.sha256_digest, timestamptz) IS 'Records the acknowledged JetStream sequence and signed-event digest for an exact active claim';
COMMENT ON FUNCTION identity.mark_certificate_event_publish_failed(identity.tenant_id, identity.event_id, identity.certificate_event_claim_token, text, timestamptz, integer) IS 'Returns an exact active claim to pending with a bounded reason code and retry delay';
