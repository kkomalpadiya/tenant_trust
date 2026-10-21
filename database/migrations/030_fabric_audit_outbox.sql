CREATE DOMAIN audit.audit_outbox_claim_token AS text
  CHECK (VALUE ~ '^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TYPE audit.audit_outbox_state AS ENUM ('pending', 'submitting', 'submitted');

DO $create_audit_outbox_worker$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_audit_outbox_worker') THEN
    CREATE ROLE tenant_trust_audit_outbox_worker;
  END IF;
END
$create_audit_outbox_worker$;

ALTER ROLE tenant_trust_audit_outbox_worker
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS
  PASSWORD NULL;

CREATE TABLE audit.fabric_commitment_outbox (
  tenant_id identity.tenant_id NOT NULL,
  event_id identity.event_id NOT NULL,
  channel_name text NOT NULL,
  event_type text NOT NULL,
  record_type text NOT NULL,
  event_document jsonb NOT NULL,
  canonical_preimage_json text NOT NULL,
  ledger_key text NOT NULL,
  event_key_hash_sha256 identity.sha256_digest NOT NULL,
  commitment_hash_sha256 identity.sha256_digest NOT NULL,
  ledger_value jsonb NOT NULL,
  status audit.audit_outbox_state NOT NULL DEFAULT 'pending',
  claim_token audit.audit_outbox_claim_token,
  claimed_by text,
  claimed_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL,
  last_failure_code text,
  submission_status text,
  submitted_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT fabric_commitment_outbox_pk PRIMARY KEY (tenant_id, event_id),
  CONSTRAINT fabric_commitment_outbox_event_key_unique UNIQUE (tenant_id, event_key_hash_sha256),
  CONSTRAINT fabric_commitment_outbox_channel_format CHECK (
    channel_name ~ '^tt-audit-[a-z0-9-]+-v[1-9][0-9]*$'
  ),
  CONSTRAINT fabric_commitment_outbox_event_type_format CHECK (
    event_type ~ '^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.v[1-9][0-9]*$'
  ),
  CONSTRAINT fabric_commitment_outbox_record_type_allowed CHECK (
    record_type IN ('certificate-lifecycle', 'trust-transition', 'policy-change', 'access-decision', 'security-action')
  ),
  CONSTRAINT fabric_commitment_outbox_document_identity CHECK (
    event_document ->> 'tenantId' = tenant_id::text
    AND event_document ->> 'eventId' = event_id::text
    AND event_document ->> 'eventType' = event_type
  ),
  CONSTRAINT fabric_commitment_outbox_ledger_shape CHECK (
    jsonb_typeof(ledger_value) = 'object'
    AND ledger_value ?& ARRAY[
      'canonicalizationProfile', 'commitmentHashSha256', 'digestAlgorithm',
      'eventKeyHashSha256', 'recordType', 'schemaVersion'
    ]
    AND ledger_value
      - 'canonicalizationProfile'
      - 'commitmentHashSha256'
      - 'digestAlgorithm'
      - 'eventKeyHashSha256'
      - 'recordType'
      - 'schemaVersion' = '{}'::jsonb
    AND ledger_value ->> 'canonicalizationProfile' = 'tenant-trust-audit-commitment-json-v1'
    AND ledger_value ->> 'digestAlgorithm' = 'sha256'
    AND ledger_value ->> 'schemaVersion' = '1.0.0'
    AND ledger_value ->> 'recordType' = record_type
    AND ledger_value ->> 'eventKeyHashSha256' = event_key_hash_sha256::text
    AND ledger_value ->> 'commitmentHashSha256' = commitment_hash_sha256::text
  ),
  CONSTRAINT fabric_commitment_outbox_ledger_key_matches CHECK (
    ledger_key = 'audit~' || record_type || '~' || event_key_hash_sha256::text
  ),
  CONSTRAINT fabric_commitment_outbox_attempt_nonnegative CHECK (attempt_count >= 0),
  CONSTRAINT fabric_commitment_outbox_worker_format CHECK (
    claimed_by IS NULL OR claimed_by ~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
  ),
  CONSTRAINT fabric_commitment_outbox_failure_format CHECK (
    last_failure_code IS NULL OR last_failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT fabric_commitment_outbox_submission_status CHECK (
    submission_status IS NULL OR submission_status IN ('created', 'duplicate')
  ),
  CONSTRAINT fabric_commitment_outbox_state_shape CHECK (
    (
      status = 'pending'
      AND claim_token IS NULL
      AND claimed_by IS NULL
      AND claimed_at IS NULL
      AND submission_status IS NULL
      AND submitted_at IS NULL
    )
    OR (
      status = 'submitting'
      AND claim_token IS NOT NULL
      AND claimed_by IS NOT NULL
      AND claimed_at IS NOT NULL
      AND submission_status IS NULL
      AND submitted_at IS NULL
    )
    OR (
      status = 'submitted'
      AND claim_token IS NULL
      AND claimed_by IS NULL
      AND claimed_at IS NULL
      AND submission_status IS NOT NULL
      AND submitted_at IS NOT NULL
    )
  ),
  CONSTRAINT fabric_commitment_outbox_time_order CHECK (
    updated_at >= created_at
    AND next_attempt_at >= created_at
    AND (claimed_at IS NULL OR claimed_at >= created_at)
    AND (submitted_at IS NULL OR submitted_at >= created_at)
  )
);

CREATE INDEX fabric_commitment_outbox_due
  ON audit.fabric_commitment_outbox (next_attempt_at, created_at, tenant_id, event_id)
  WHERE status = 'pending';

CREATE FUNCTION audit.enqueue_fabric_commitment(
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_channel_name text,
  p_event_type text,
  p_record_type text,
  p_event_document jsonb,
  p_canonical_preimage_json text,
  p_ledger_key text,
  p_event_key_hash_sha256 identity.sha256_digest,
  p_commitment_hash_sha256 identity.sha256_digest,
  p_ledger_value jsonb,
  p_queued_at timestamptz
)
RETURNS TABLE (
  event_id identity.event_id,
  status audit.audit_outbox_state,
  event_key_hash_sha256 identity.sha256_digest,
  commitment_hash_sha256 identity.sha256_digest
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity
SET row_security = off
AS $function$
DECLARE
  existing audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  IF identity.current_tenant_id() IS DISTINCT FROM p_tenant_id
     OR p_queued_at > clock_timestamp() + interval '2 seconds'
     OR p_queued_at < clock_timestamp() - interval '10 minutes' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Audit commitment enqueue denied.';
  END IF;

  INSERT INTO audit.fabric_commitment_outbox (
    tenant_id, event_id, channel_name, event_type, record_type,
    event_document, canonical_preimage_json, ledger_key,
    event_key_hash_sha256, commitment_hash_sha256, ledger_value,
    next_attempt_at, created_at, updated_at
  ) VALUES (
    p_tenant_id, p_event_id, p_channel_name, p_event_type, p_record_type,
    p_event_document, p_canonical_preimage_json, p_ledger_key,
    p_event_key_hash_sha256, p_commitment_hash_sha256, p_ledger_value,
    p_queued_at, p_queued_at, p_queued_at
  )
  ON CONFLICT ON CONSTRAINT fabric_commitment_outbox_pk DO NOTHING;

  SELECT * INTO existing
  FROM audit.fabric_commitment_outbox AS outbox
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.event_id = p_event_id;

  IF existing.channel_name <> p_channel_name
     OR existing.event_type <> p_event_type
     OR existing.record_type <> p_record_type
     OR existing.event_document <> p_event_document
     OR existing.canonical_preimage_json <> p_canonical_preimage_json
     OR existing.ledger_key <> p_ledger_key
     OR existing.event_key_hash_sha256 <> p_event_key_hash_sha256
     OR existing.commitment_hash_sha256 <> p_commitment_hash_sha256
     OR existing.ledger_value <> p_ledger_value THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Audit commitment idempotency conflict.';
  END IF;

  RETURN QUERY SELECT existing.event_id, existing.status,
    existing.event_key_hash_sha256, existing.commitment_hash_sha256;
END
$function$;

CREATE FUNCTION audit.claim_fabric_commitment(
  p_worker_id text,
  p_claim_token audit.audit_outbox_claim_token,
  p_claimed_at timestamptz
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  event_id identity.event_id,
  channel_name text,
  event_document jsonb,
  canonical_preimage_json text,
  ledger_key text,
  ledger_value jsonb,
  claim_token audit.audit_outbox_claim_token,
  attempt_count integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity
SET row_security = off
AS $function$
BEGIN
  IF p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
     OR p_claimed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Audit commitment claim denied.';
  END IF;

  UPDATE audit.fabric_commitment_outbox AS outbox
  SET status = 'pending',
      claim_token = NULL,
      claimed_by = NULL,
      claimed_at = NULL,
      next_attempt_at = p_claimed_at,
      last_failure_code = 'STALE_CLAIM_RECOVERED',
      updated_at = GREATEST(clock_timestamp(), p_claimed_at)
  WHERE outbox.status = 'submitting'
    AND outbox.claimed_at < p_claimed_at - interval '5 minutes';

  RETURN QUERY
  WITH candidate AS (
    SELECT outbox.tenant_id, outbox.event_id
    FROM audit.fabric_commitment_outbox AS outbox
    WHERE outbox.status = 'pending'
      AND outbox.next_attempt_at <= p_claimed_at
    ORDER BY outbox.next_attempt_at, outbox.created_at, outbox.tenant_id, outbox.event_id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
  ), claimed AS (
    UPDATE audit.fabric_commitment_outbox AS outbox
    SET status = 'submitting',
        claim_token = p_claim_token,
        claimed_by = p_worker_id,
        claimed_at = p_claimed_at,
        attempt_count = outbox.attempt_count + 1,
        last_failure_code = NULL,
        updated_at = GREATEST(clock_timestamp(), p_claimed_at)
    FROM candidate
    WHERE outbox.tenant_id = candidate.tenant_id
      AND outbox.event_id = candidate.event_id
    RETURNING outbox.*
  )
  SELECT claimed.tenant_id, claimed.event_id, claimed.channel_name,
    claimed.event_document, claimed.canonical_preimage_json,
    claimed.ledger_key, claimed.ledger_value, claimed.claim_token,
    claimed.attempt_count
  FROM claimed;
END
$function$;

CREATE FUNCTION audit.mark_fabric_commitment_submitted(
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_claim_token audit.audit_outbox_claim_token,
  p_ledger_key text,
  p_submission_status text,
  p_submitted_at timestamptz
)
RETURNS TABLE (
  event_id identity.event_id,
  status audit.audit_outbox_state,
  submission_status text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity
SET row_security = off
AS $function$
DECLARE
  updated audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  IF p_submission_status NOT IN ('created', 'duplicate')
     OR p_submitted_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Audit commitment submission update denied.';
  END IF;

  UPDATE audit.fabric_commitment_outbox AS outbox
  SET status = 'submitted',
      claim_token = NULL,
      claimed_by = NULL,
      claimed_at = NULL,
      submission_status = p_submission_status,
      submitted_at = p_submitted_at,
      last_failure_code = NULL,
      updated_at = GREATEST(clock_timestamp(), p_submitted_at)
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.event_id = p_event_id
    AND outbox.status = 'submitting'
    AND outbox.claim_token = p_claim_token
    AND outbox.ledger_key = p_ledger_key
  RETURNING outbox.* INTO updated;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Audit commitment submission update denied.';
  END IF;

  RETURN QUERY SELECT updated.event_id, updated.status, updated.submission_status;
END
$function$;

CREATE FUNCTION audit.mark_fabric_commitment_failed(
  p_tenant_id identity.tenant_id,
  p_event_id identity.event_id,
  p_claim_token audit.audit_outbox_claim_token,
  p_failure_code text,
  p_failed_at timestamptz,
  p_retry_delay_seconds integer
)
RETURNS TABLE (
  event_id identity.event_id,
  status audit.audit_outbox_state,
  next_attempt_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity
SET row_security = off
AS $function$
DECLARE
  updated audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  IF p_failure_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_retry_delay_seconds < 1
     OR p_retry_delay_seconds > 600
     OR p_failed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Audit commitment failure update denied.';
  END IF;

  UPDATE audit.fabric_commitment_outbox AS outbox
  SET status = 'pending',
      claim_token = NULL,
      claimed_by = NULL,
      claimed_at = NULL,
      next_attempt_at = p_failed_at + make_interval(secs => p_retry_delay_seconds),
      last_failure_code = p_failure_code,
      updated_at = GREATEST(clock_timestamp(), p_failed_at)
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.event_id = p_event_id
    AND outbox.status = 'submitting'
    AND outbox.claim_token = p_claim_token
  RETURNING outbox.* INTO updated;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Audit commitment failure update denied.';
  END IF;

  RETURN QUERY SELECT updated.event_id, updated.status, updated.next_attempt_at;
END
$function$;

REVOKE ALL ON TABLE audit.fabric_commitment_outbox
  FROM PUBLIC, tenant_trust_app, tenant_trust_audit_outbox_worker;
REVOKE ALL ON FUNCTION audit.enqueue_fabric_commitment(
  identity.tenant_id, identity.event_id, text, text, text, jsonb, text, text,
  identity.sha256_digest, identity.sha256_digest, jsonb, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.claim_fabric_commitment(
  text, audit.audit_outbox_claim_token, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.mark_fabric_commitment_submitted(
  identity.tenant_id, identity.event_id, audit.audit_outbox_claim_token, text, text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.mark_fabric_commitment_failed(
  identity.tenant_id, identity.event_id, audit.audit_outbox_claim_token, text, timestamptz, integer
) FROM PUBLIC;

GRANT USAGE ON SCHEMA audit TO tenant_trust_app, tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.enqueue_fabric_commitment(
  identity.tenant_id, identity.event_id, text, text, text, jsonb, text, text,
  identity.sha256_digest, identity.sha256_digest, jsonb, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION audit.claim_fabric_commitment(
  text, audit.audit_outbox_claim_token, timestamptz
) TO tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.mark_fabric_commitment_submitted(
  identity.tenant_id, identity.event_id, audit.audit_outbox_claim_token, text, text, timestamptz
) TO tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.mark_fabric_commitment_failed(
  identity.tenant_id, identity.event_id, audit.audit_outbox_claim_token, text, timestamptz, integer
) TO tenant_trust_audit_outbox_worker;

COMMENT ON TABLE audit.fabric_commitment_outbox IS
  'Durable off-chain audit preimages and retry state for asynchronous minimal Fabric commitments';
COMMENT ON ROLE tenant_trust_audit_outbox_worker IS
  'NOLOGIN privilege set limited to claiming and updating Fabric audit outbox deliveries';
COMMENT ON FUNCTION audit.enqueue_fabric_commitment(
  identity.tenant_id, identity.event_id, text, text, text, jsonb, text, text,
  identity.sha256_digest, identity.sha256_digest, jsonb, timestamptz
) IS 'Idempotently enqueues a tenant-bound audit event without contacting Fabric';
COMMENT ON FUNCTION audit.claim_fabric_commitment(
  text, audit.audit_outbox_claim_token, timestamptz
) IS 'Claims one due Fabric commitment and recovers abandoned five-minute leases';
COMMENT ON FUNCTION audit.mark_fabric_commitment_submitted(
  identity.tenant_id, identity.event_id, audit.audit_outbox_claim_token, text, text, timestamptz
) IS 'Records a validated chaincode submission response for one exact active claim';
COMMENT ON FUNCTION audit.mark_fabric_commitment_failed(
  identity.tenant_id, identity.event_id, audit.audit_outbox_claim_token, text, timestamptz, integer
) IS 'Returns one exact active claim to pending with a bounded retry delay';
