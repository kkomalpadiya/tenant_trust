CREATE DOMAIN trust.evidence_id AS text
  CHECK (VALUE ~ '^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN trust.evidence_event_claim_token AS text
  CHECK (VALUE ~ '^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TYPE trust.evidence_event_delivery_state AS ENUM ('pending', 'publishing', 'published');

DO $create_evidence_event_roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_evidence_event_worker') THEN
    CREATE ROLE tenant_trust_evidence_event_worker;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_evidence_event_consumer') THEN
    CREATE ROLE tenant_trust_evidence_event_consumer;
  END IF;
END
$create_evidence_event_roles$;

ALTER ROLE tenant_trust_evidence_event_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;
ALTER ROLE tenant_trust_evidence_event_consumer
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;

CREATE TABLE trust.evidence_event_outbox (
  tenant_id identity.tenant_id NOT NULL,
  source_event_id trust.evidence_event_id NOT NULL,
  delivery_event_id identity.event_id NOT NULL,
  evidence_id trust.evidence_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  status trust.evidence_event_delivery_state NOT NULL DEFAULT 'pending',
  claim_token trust.evidence_event_claim_token,
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
  CONSTRAINT evidence_event_outbox_pk PRIMARY KEY (tenant_id, source_event_id),
  CONSTRAINT evidence_event_outbox_receipt_fk FOREIGN KEY (tenant_id, source_event_id)
    REFERENCES trust.evidence_ingestion_receipts (tenant_id, event_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_event_outbox_delivery_unique UNIQUE (tenant_id, delivery_event_id),
  CONSTRAINT evidence_event_outbox_evidence_unique UNIQUE (tenant_id, evidence_id),
  CONSTRAINT evidence_event_outbox_attempt_positive CHECK (attempt_count >= 0),
  CONSTRAINT evidence_event_outbox_worker_format CHECK (
    claimed_by IS NULL OR claimed_by ~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
  ),
  CONSTRAINT evidence_event_outbox_failure_format CHECK (
    last_failure_code IS NULL OR last_failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT evidence_event_outbox_sequence_positive CHECK (
    stream_sequence IS NULL OR stream_sequence > 0
  ),
  CONSTRAINT evidence_event_outbox_state_shape CHECK (
    (
      status = 'pending'
      AND claim_token IS NULL AND claimed_by IS NULL AND claimed_at IS NULL
      AND stream_sequence IS NULL AND signed_event_sha256 IS NULL AND published_at IS NULL
    ) OR (
      status = 'publishing'
      AND claim_token IS NOT NULL AND claimed_by IS NOT NULL AND claimed_at IS NOT NULL
      AND stream_sequence IS NULL AND signed_event_sha256 IS NULL AND published_at IS NULL
    ) OR (
      status = 'published'
      AND claim_token IS NULL AND claimed_by IS NULL AND claimed_at IS NULL
      AND stream_sequence IS NOT NULL AND signed_event_sha256 IS NOT NULL AND published_at IS NOT NULL
    )
  ),
  CONSTRAINT evidence_event_outbox_time_order CHECK (
    updated_at >= created_at
    AND (claimed_at IS NULL OR claimed_at >= created_at)
    AND (published_at IS NULL OR published_at >= created_at)
  )
);

CREATE INDEX evidence_event_outbox_pending
  ON trust.evidence_event_outbox (tenant_id, next_attempt_at, created_at, delivery_event_id)
  WHERE status = 'pending';

CREATE TABLE trust.evidence_event_effects (
  consumer_name text NOT NULL,
  tenant_id identity.tenant_id NOT NULL,
  delivery_event_id identity.event_id NOT NULL,
  evidence_id trust.evidence_id NOT NULL,
  stream_sequence bigint NOT NULL,
  signed_event_sha256 identity.sha256_digest NOT NULL,
  processed_at timestamptz NOT NULL,
  CONSTRAINT evidence_event_effects_pk PRIMARY KEY (consumer_name, tenant_id, delivery_event_id),
  CONSTRAINT evidence_event_effects_outbox_fk FOREIGN KEY (tenant_id, delivery_event_id)
    REFERENCES trust.evidence_event_outbox (tenant_id, delivery_event_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_event_effects_consumer_format CHECK (
    consumer_name ~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
  ),
  CONSTRAINT evidence_event_effects_sequence_positive CHECK (stream_sequence > 0)
);

CREATE FUNCTION trust.enqueue_accepted_evidence_event()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, identity, trust
SET row_security = off
AS $function$
BEGIN
  INSERT INTO trust.evidence_event_outbox (
    tenant_id, source_event_id, delivery_event_id, evidence_id, correlation_id,
    created_at, updated_at, next_attempt_at
  ) VALUES (
    NEW.tenant_id,
    NEW.event_id,
    ('evt_' || public.gen_random_uuid()::text)::identity.event_id,
    ('evd_' || public.gen_random_uuid()::text)::trust.evidence_id,
    ('cor_' || public.gen_random_uuid()::text)::identity.correlation_id,
    NEW.accepted_at, NEW.accepted_at, NEW.accepted_at
  )
  ON CONFLICT (tenant_id, source_event_id) DO NOTHING;
  RETURN NEW;
END
$function$;

CREATE TRIGGER accepted_evidence_event_enqueue
AFTER INSERT ON trust.evidence_ingestion_receipts
FOR EACH ROW EXECUTE FUNCTION trust.enqueue_accepted_evidence_event();

INSERT INTO trust.evidence_event_outbox (
  tenant_id, source_event_id, delivery_event_id, evidence_id, correlation_id,
  created_at, updated_at, next_attempt_at
)
SELECT receipt.tenant_id,
       receipt.event_id,
       ('evt_' || public.gen_random_uuid()::text)::identity.event_id,
       ('evd_' || public.gen_random_uuid()::text)::trust.evidence_id,
       ('cor_' || public.gen_random_uuid()::text)::identity.correlation_id,
       receipt.accepted_at, receipt.accepted_at, receipt.accepted_at
FROM trust.evidence_ingestion_receipts AS receipt
ON CONFLICT (tenant_id, source_event_id) DO NOTHING;

CREATE FUNCTION trust.claim_evidence_event_outbox(
  p_tenant_id identity.tenant_id,
  p_worker_id text,
  p_claim_token trust.evidence_event_claim_token,
  p_claimed_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  event_id identity.event_id,
  source_event_id trust.evidence_event_id,
  evidence_id trust.evidence_id,
  correlation_id identity.correlation_id,
  subject_id identity.subject_id,
  source_id trust.source_id,
  evidence_type trust.evidence_type,
  source_sequence bigint,
  content_hash_sha256 identity.sha256_digest,
  synthetic boolean,
  observed_at timestamptz,
  expires_at timestamptz,
  accepted_at timestamptz,
  claim_token trust.evidence_event_claim_token,
  attempt_count integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
BEGIN
  IF p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
     OR p_claimed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence event outbox claim denied.';
  END IF;

  UPDATE trust.evidence_event_outbox AS outbox
  SET status = 'pending', claim_token = NULL, claimed_by = NULL, claimed_at = NULL,
      next_attempt_at = p_claimed_at, last_failure_code = 'STALE_CLAIM_RECOVERED',
      updated_at = GREATEST(clock_timestamp(), p_claimed_at)
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.status = 'publishing'
    AND outbox.claimed_at < p_claimed_at - interval '5 minutes';

  RETURN QUERY
  WITH candidate AS (
    SELECT outbox.tenant_id, outbox.source_event_id
    FROM trust.evidence_event_outbox AS outbox
    WHERE outbox.tenant_id = p_tenant_id
      AND outbox.status = 'pending'
      AND outbox.next_attempt_at <= p_claimed_at
    ORDER BY outbox.created_at, outbox.delivery_event_id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
  ), claimed AS (
    UPDATE trust.evidence_event_outbox AS outbox
    SET status = 'publishing', claim_token = p_claim_token, claimed_by = p_worker_id,
        claimed_at = p_claimed_at, attempt_count = outbox.attempt_count + 1,
        last_failure_code = NULL, updated_at = GREATEST(clock_timestamp(), p_claimed_at)
    FROM candidate
    WHERE outbox.tenant_id = candidate.tenant_id
      AND outbox.source_event_id = candidate.source_event_id
    RETURNING outbox.*
  )
  SELECT claimed.tenant_id, claimed.delivery_event_id, claimed.source_event_id,
         claimed.evidence_id, claimed.correlation_id, receipt.subject_id,
         receipt.source_id, receipt.evidence_type, receipt.source_sequence,
         receipt.content_hash_sha256::identity.sha256_digest, receipt.synthetic,
         receipt.observed_at, receipt.expires_at, receipt.accepted_at,
         claimed.claim_token, claimed.attempt_count
  FROM claimed
  JOIN trust.evidence_ingestion_receipts AS receipt
    ON receipt.tenant_id = claimed.tenant_id
   AND receipt.event_id = claimed.source_event_id
  JOIN trust.encrypted_evidence AS stored
    ON stored.tenant_id = receipt.tenant_id
   AND stored.event_id = receipt.event_id;
END
$function$;

CREATE FUNCTION trust.mark_evidence_event_published(
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_claim_token trust.evidence_event_claim_token,
  p_stream_sequence bigint,
  p_signed_event_sha256 identity.sha256_digest,
  p_published_at timestamptz
)
RETURNS TABLE (
  event_id identity.event_id,
  status trust.evidence_event_delivery_state,
  stream_sequence bigint,
  signed_event_sha256 identity.sha256_digest
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE updated trust.evidence_event_outbox%ROWTYPE;
BEGIN
  IF p_stream_sequence < 1 OR p_published_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence event publish confirmation denied.';
  END IF;
  UPDATE trust.evidence_event_outbox AS outbox
  SET status = 'published', claim_token = NULL, claimed_by = NULL, claimed_at = NULL,
      stream_sequence = p_stream_sequence, signed_event_sha256 = p_signed_event_sha256,
      published_at = p_published_at, last_failure_code = NULL,
      updated_at = GREATEST(clock_timestamp(), p_published_at)
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.delivery_event_id = p_event_id
    AND outbox.status = 'publishing'
    AND outbox.claim_token = p_claim_token
  RETURNING outbox.* INTO updated;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence event publish confirmation denied.';
  END IF;
  RETURN QUERY SELECT updated.delivery_event_id, updated.status,
    updated.stream_sequence, updated.signed_event_sha256;
END
$function$;

CREATE FUNCTION trust.mark_evidence_event_publish_failed(
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_claim_token trust.evidence_event_claim_token,
  p_failure_code text,
  p_failed_at timestamptz,
  p_retry_delay_seconds integer
)
RETURNS TABLE (event_id identity.event_id, status trust.evidence_event_delivery_state)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE updated trust.evidence_event_outbox%ROWTYPE;
BEGIN
  IF p_failure_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_retry_delay_seconds < 1 OR p_retry_delay_seconds > 600
     OR p_failed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence event publish failure update denied.';
  END IF;
  UPDATE trust.evidence_event_outbox AS outbox
  SET status = 'pending', claim_token = NULL, claimed_by = NULL, claimed_at = NULL,
      next_attempt_at = p_failed_at + make_interval(secs => p_retry_delay_seconds),
      last_failure_code = p_failure_code,
      updated_at = GREATEST(clock_timestamp(), p_failed_at)
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.delivery_event_id = p_event_id
    AND outbox.status = 'publishing'
    AND outbox.claim_token = p_claim_token
  RETURNING outbox.* INTO updated;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence event publish failure update denied.';
  END IF;
  RETURN QUERY SELECT updated.delivery_event_id, updated.status;
END
$function$;

CREATE FUNCTION trust.record_evidence_event_effect(
  p_consumer_name text,
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_evidence_id trust.evidence_id,
  p_stream_sequence bigint,
  p_signed_event_sha256 identity.sha256_digest,
  p_processed_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE published trust.evidence_event_outbox%ROWTYPE;
DECLARE existing trust.evidence_event_effects%ROWTYPE;
BEGIN
  IF p_consumer_name !~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
     OR p_stream_sequence < 1
     OR p_processed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence event effect denied.';
  END IF;

  SELECT * INTO published
  FROM trust.evidence_event_outbox AS outbox
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.delivery_event_id = p_event_id
    AND outbox.evidence_id = p_evidence_id
    AND outbox.status = 'published'
  FOR SHARE;
  IF NOT FOUND
     OR published.stream_sequence <> p_stream_sequence
     OR published.signed_event_sha256 <> p_signed_event_sha256 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence event effect denied.';
  END IF;

  INSERT INTO trust.evidence_event_effects (
    consumer_name, tenant_id, delivery_event_id, evidence_id,
    stream_sequence, signed_event_sha256, processed_at
  ) VALUES (
    p_consumer_name, p_tenant_id, p_event_id, p_evidence_id,
    p_stream_sequence, p_signed_event_sha256, p_processed_at
  )
  ON CONFLICT (consumer_name, tenant_id, delivery_event_id) DO NOTHING;
  IF FOUND THEN RETURN TRUE; END IF;

  SELECT * INTO STRICT existing
  FROM trust.evidence_event_effects AS effect
  WHERE effect.consumer_name = p_consumer_name
    AND effect.tenant_id = p_tenant_id
    AND effect.delivery_event_id = p_event_id;
  IF existing.evidence_id <> p_evidence_id
     OR existing.stream_sequence <> p_stream_sequence
     OR existing.signed_event_sha256 <> p_signed_event_sha256 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence event effect conflict.';
  END IF;
  RETURN FALSE;
END
$function$;

REVOKE ALL ON TABLE trust.evidence_event_outbox FROM PUBLIC, tenant_trust_app,
  tenant_trust_evidence_event_worker, tenant_trust_evidence_event_consumer;
REVOKE ALL ON TABLE trust.evidence_event_effects FROM PUBLIC, tenant_trust_app,
  tenant_trust_evidence_event_worker, tenant_trust_evidence_event_consumer;
REVOKE ALL ON FUNCTION trust.enqueue_accepted_evidence_event() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.claim_evidence_event_outbox(identity.tenant_id, text, trust.evidence_event_claim_token, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.mark_evidence_event_published(identity.tenant_id, identity.event_id, trust.evidence_event_claim_token, bigint, identity.sha256_digest, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.mark_evidence_event_publish_failed(identity.tenant_id, identity.event_id, trust.evidence_event_claim_token, text, timestamptz, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.record_evidence_event_effect(text, identity.tenant_id, identity.event_id, trust.evidence_id, bigint, identity.sha256_digest, timestamptz) FROM PUBLIC;

GRANT USAGE ON SCHEMA trust TO tenant_trust_evidence_event_worker, tenant_trust_evidence_event_consumer;
GRANT EXECUTE ON FUNCTION trust.claim_evidence_event_outbox(identity.tenant_id, text, trust.evidence_event_claim_token, timestamptz) TO tenant_trust_evidence_event_worker;
GRANT EXECUTE ON FUNCTION trust.mark_evidence_event_published(identity.tenant_id, identity.event_id, trust.evidence_event_claim_token, bigint, identity.sha256_digest, timestamptz) TO tenant_trust_evidence_event_worker;
GRANT EXECUTE ON FUNCTION trust.mark_evidence_event_publish_failed(identity.tenant_id, identity.event_id, trust.evidence_event_claim_token, text, timestamptz, integer) TO tenant_trust_evidence_event_worker;
GRANT EXECUTE ON FUNCTION trust.record_evidence_event_effect(text, identity.tenant_id, identity.event_id, trust.evidence_id, bigint, identity.sha256_digest, timestamptz) TO tenant_trust_evidence_event_consumer;

COMMENT ON TABLE trust.evidence_event_outbox IS
  'Transactional delivery state for source-authenticated accepted-evidence events; raw evidence is excluded';
COMMENT ON TABLE trust.evidence_event_effects IS
  'Durable per-consumer idempotency receipts that must commit in the same transaction as downstream effects';
COMMENT ON FUNCTION trust.claim_evidence_event_outbox(identity.tenant_id, text, trust.evidence_event_claim_token, timestamptz) IS
  'Claims the oldest due accepted-evidence event for one tenant and recovers stale worker claims';
COMMENT ON FUNCTION trust.record_evidence_event_effect(text, identity.tenant_id, identity.event_id, trust.evidence_id, bigint, identity.sha256_digest, timestamptz) IS
  'Records one exact published event per consumer; callers must apply their effect in the same transaction';
