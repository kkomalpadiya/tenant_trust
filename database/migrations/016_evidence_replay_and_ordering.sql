CREATE DOMAIN trust.evidence_event_id AS text
  CHECK (VALUE ~ '^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TYPE trust.evidence_ingestion_rejection_reason AS ENUM (
  'EVIDENCE_TIME_WINDOW_INVALID',
  'EVIDENCE_OBSERVED_IN_FUTURE',
  'EVIDENCE_STALE',
  'EVIDENCE_EXPIRED',
  'EVIDENCE_TTL_EXCEEDED',
  'EVIDENCE_EVENT_REPLAYED',
  'EVIDENCE_NONCE_REPLAYED',
  'EVIDENCE_SEQUENCE_REPLAYED',
  'EVIDENCE_SEQUENCE_REORDERED',
  'EVIDENCE_OBSERVATION_REORDERED'
);

CREATE TABLE trust.evidence_ingestion_state (
  tenant_id identity.tenant_id NOT NULL,
  source_id trust.source_id NOT NULL,
  key_id trust.evidence_source_key_id NOT NULL,
  highest_source_sequence bigint,
  latest_observed_at timestamptz,
  accepted_count bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT evidence_ingestion_state_pk PRIMARY KEY (tenant_id, source_id, key_id),
  CONSTRAINT evidence_ingestion_state_key_fk FOREIGN KEY (tenant_id, source_id, key_id)
    REFERENCES trust.evidence_source_keys (tenant_id, source_id, key_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_ingestion_state_sequence_range CHECK (
    highest_source_sequence IS NULL
    OR highest_source_sequence BETWEEN 0 AND 9007199254740991
  ),
  CONSTRAINT evidence_ingestion_state_shape CHECK (
    (highest_source_sequence IS NULL AND latest_observed_at IS NULL AND accepted_count = 0)
    OR (highest_source_sequence IS NOT NULL AND latest_observed_at IS NOT NULL AND accepted_count > 0)
  ),
  CONSTRAINT evidence_ingestion_state_time_order CHECK (created_at <= updated_at)
);

CREATE TABLE trust.evidence_ingestion_receipts (
  tenant_id identity.tenant_id NOT NULL,
  event_id trust.evidence_event_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  source_id trust.source_id NOT NULL,
  key_id trust.evidence_source_key_id NOT NULL,
  evidence_type trust.evidence_type NOT NULL,
  source_sequence bigint NOT NULL,
  nonce_sha256 text NOT NULL,
  content_hash_sha256 text NOT NULL,
  synthetic boolean NOT NULL,
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz NOT NULL,
  CONSTRAINT evidence_ingestion_receipts_pk PRIMARY KEY (tenant_id, event_id),
  CONSTRAINT evidence_ingestion_receipts_key_fk FOREIGN KEY (tenant_id, source_id, key_id)
    REFERENCES trust.evidence_source_keys (tenant_id, source_id, key_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_ingestion_receipts_subject_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_ingestion_receipts_sequence_unique
    UNIQUE (tenant_id, source_id, key_id, source_sequence),
  CONSTRAINT evidence_ingestion_receipts_nonce_unique
    UNIQUE (tenant_id, source_id, key_id, nonce_sha256),
  CONSTRAINT evidence_ingestion_receipts_sequence_range CHECK (
    source_sequence BETWEEN 0 AND 9007199254740991
  ),
  CONSTRAINT evidence_ingestion_receipts_nonce_hash CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evidence_ingestion_receipts_content_hash CHECK (content_hash_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evidence_ingestion_receipts_time_order CHECK (
    observed_at < expires_at
    AND observed_at <= accepted_at + interval '30 seconds'
    AND accepted_at < expires_at
  )
);

CREATE TABLE trust.evidence_ingestion_rejections (
  rejection_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id identity.tenant_id NOT NULL,
  source_id trust.source_id NOT NULL,
  key_id trust.evidence_source_key_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  reason_code trust.evidence_ingestion_rejection_reason NOT NULL,
  event_id_sha256 text NOT NULL,
  nonce_sha256 text NOT NULL,
  content_hash_sha256 text NOT NULL,
  source_sequence bigint NOT NULL,
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  rejected_at timestamptz NOT NULL,
  CONSTRAINT evidence_ingestion_rejections_key_fk FOREIGN KEY (tenant_id, source_id, key_id)
    REFERENCES trust.evidence_source_keys (tenant_id, source_id, key_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_ingestion_rejections_subject_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_ingestion_rejections_event_hash CHECK (event_id_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evidence_ingestion_rejections_nonce_hash CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evidence_ingestion_rejections_content_hash CHECK (content_hash_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evidence_ingestion_rejections_sequence_range CHECK (
    source_sequence BETWEEN 0 AND 9007199254740991
  )
);

CREATE INDEX evidence_ingestion_rejections_operational_lookup
  ON trust.evidence_ingestion_rejections (tenant_id, source_id, rejected_at DESC, reason_code);

CREATE FUNCTION trust.prevent_evidence_ingestion_history_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Evidence ingestion history is append-only.';
END
$function$;

CREATE TRIGGER evidence_ingestion_receipts_keep_history
BEFORE UPDATE OR DELETE ON trust.evidence_ingestion_receipts
FOR EACH ROW EXECUTE FUNCTION trust.prevent_evidence_ingestion_history_rewrite();

CREATE TRIGGER evidence_ingestion_rejections_keep_history
BEFORE UPDATE OR DELETE ON trust.evidence_ingestion_rejections
FOR EACH ROW EXECUTE FUNCTION trust.prevent_evidence_ingestion_history_rewrite();

CREATE FUNCTION trust.apply_evidence_replay_guard(
  p_tenant_id identity.tenant_id,
  p_subject_id identity.subject_id,
  p_source_id trust.source_id,
  p_key_id trust.evidence_source_key_id,
  p_evidence_type trust.evidence_type,
  p_event_id trust.evidence_event_id,
  p_source_sequence bigint,
  p_nonce text,
  p_observed_at timestamptz,
  p_expires_at timestamptz,
  p_content_hash_sha256 text,
  p_synthetic boolean
)
RETURNS TABLE (
  accepted boolean,
  reason_code text,
  accepted_at timestamptz,
  highest_source_sequence bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_maximum_age_seconds integer;
  v_reason trust.evidence_ingestion_rejection_reason;
  v_nonce_sha256 text;
  v_highest_source_sequence bigint;
  v_latest_observed_at timestamptz;
BEGIN
  IF p_source_sequence < 0
    OR p_source_sequence > 9007199254740991
    OR p_nonce !~ '^[A-Za-z0-9_-]{22,64}$'
    OR p_content_hash_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Invalid evidence replay-guard input.';
  END IF;

  SELECT source.maximum_age_seconds
  INTO v_maximum_age_seconds
  FROM identity.tenants AS tenant
  JOIN identity.tenant_memberships AS membership
    ON membership.tenant_id = tenant.tenant_id
   AND membership.subject_id = p_subject_id
  JOIN identity.subjects AS subject
    ON subject.subject_id = membership.subject_id
  JOIN trust.evidence_sources AS source
    ON source.tenant_id = tenant.tenant_id
   AND source.source_id = p_source_id
  JOIN trust.evidence_source_keys AS source_key
    ON source_key.tenant_id = source.tenant_id
   AND source_key.source_id = source.source_id
   AND source_key.key_id = p_key_id
  WHERE tenant.tenant_id = p_tenant_id
    AND tenant.state = 'active'
    AND subject.state = 'active'
    AND membership.state = 'active'
    AND source.state = 'active'
    AND source.evidence_type = p_evidence_type
    AND source.synthetic = p_synthetic
    AND source.verification_algorithm = 'ed25519'
    AND source.verification_key_sha256 = source_key.public_key_sha256
    AND source_key.state = 'active'
    AND source_key.algorithm = 'Ed25519'
  FOR SHARE OF tenant, membership, subject, source, source_key;

  IF NOT FOUND THEN
    RETURN QUERY SELECT FALSE, 'VERIFICATION_CONTEXT_NOT_FOUND'::text, NULL::timestamptz, NULL::bigint;
    RETURN;
  END IF;

  v_nonce_sha256 := encode(public.digest(p_nonce, 'sha256'), 'hex');

  IF p_observed_at >= p_expires_at THEN
    v_reason := 'EVIDENCE_TIME_WINDOW_INVALID';
  ELSIF p_observed_at > v_now + interval '30 seconds' THEN
    v_reason := 'EVIDENCE_OBSERVED_IN_FUTURE';
  ELSIF p_observed_at < v_now - make_interval(secs => v_maximum_age_seconds) THEN
    v_reason := 'EVIDENCE_STALE';
  ELSIF p_expires_at <= v_now THEN
    v_reason := 'EVIDENCE_EXPIRED';
  ELSIF p_expires_at > p_observed_at + make_interval(secs => v_maximum_age_seconds) THEN
    v_reason := 'EVIDENCE_TTL_EXCEEDED';
  END IF;

  IF v_reason IS NULL THEN
    INSERT INTO trust.evidence_ingestion_state (
      tenant_id, source_id, key_id, created_at, updated_at
    )
    VALUES (p_tenant_id, p_source_id, p_key_id, v_now, v_now)
    ON CONFLICT (tenant_id, source_id, key_id) DO NOTHING;

    SELECT state.highest_source_sequence, state.latest_observed_at
    INTO v_highest_source_sequence, v_latest_observed_at
    FROM trust.evidence_ingestion_state AS state
    WHERE state.tenant_id = p_tenant_id
      AND state.source_id = p_source_id
      AND state.key_id = p_key_id
    FOR UPDATE;

    PERFORM pg_advisory_xact_lock(
      hashtextextended(p_tenant_id::text || ':' || p_event_id::text, 0)
    );

    IF EXISTS (
      SELECT 1
      FROM trust.evidence_ingestion_receipts AS receipt
      WHERE receipt.tenant_id = p_tenant_id
        AND receipt.event_id = p_event_id
    ) THEN
      v_reason := 'EVIDENCE_EVENT_REPLAYED';
    ELSIF EXISTS (
      SELECT 1
      FROM trust.evidence_ingestion_receipts AS receipt
      WHERE receipt.tenant_id = p_tenant_id
        AND receipt.source_id = p_source_id
        AND receipt.key_id = p_key_id
        AND receipt.nonce_sha256 = v_nonce_sha256
    ) THEN
      v_reason := 'EVIDENCE_NONCE_REPLAYED';
    ELSIF p_source_sequence = v_highest_source_sequence THEN
      v_reason := 'EVIDENCE_SEQUENCE_REPLAYED';
    ELSIF p_source_sequence < v_highest_source_sequence THEN
      v_reason := 'EVIDENCE_SEQUENCE_REORDERED';
    ELSIF p_observed_at < v_latest_observed_at THEN
      v_reason := 'EVIDENCE_OBSERVATION_REORDERED';
    END IF;
  END IF;

  IF v_reason IS NOT NULL THEN
    INSERT INTO trust.evidence_ingestion_rejections (
      tenant_id, source_id, key_id, subject_id, reason_code,
      event_id_sha256, nonce_sha256, content_hash_sha256,
      source_sequence, observed_at, expires_at, rejected_at
    ) VALUES (
      p_tenant_id, p_source_id, p_key_id, p_subject_id, v_reason,
      encode(public.digest(p_event_id::text, 'sha256'), 'hex'),
      v_nonce_sha256,
      p_content_hash_sha256,
      p_source_sequence, p_observed_at, p_expires_at, v_now
    );
    RETURN QUERY SELECT FALSE, v_reason::text, NULL::timestamptz, v_highest_source_sequence;
    RETURN;
  END IF;

  INSERT INTO trust.evidence_ingestion_receipts (
    tenant_id, event_id, subject_id, source_id, key_id, evidence_type,
    source_sequence, nonce_sha256, content_hash_sha256, synthetic,
    observed_at, expires_at, accepted_at
  ) VALUES (
    p_tenant_id, p_event_id, p_subject_id, p_source_id, p_key_id, p_evidence_type,
    p_source_sequence, v_nonce_sha256, p_content_hash_sha256, p_synthetic,
    p_observed_at, p_expires_at, v_now
  );

  UPDATE trust.evidence_ingestion_state AS state
  SET highest_source_sequence = p_source_sequence,
      latest_observed_at = p_observed_at,
      accepted_count = state.accepted_count + 1,
      updated_at = v_now
  WHERE state.tenant_id = p_tenant_id
    AND state.source_id = p_source_id
    AND state.key_id = p_key_id;

  RETURN QUERY SELECT TRUE, NULL::text, v_now, p_source_sequence;
END
$function$;

REVOKE ALL ON TABLE trust.evidence_ingestion_state FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON TABLE trust.evidence_ingestion_receipts FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON TABLE trust.evidence_ingestion_rejections FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON SEQUENCE trust.evidence_ingestion_rejections_rejection_id_seq FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION trust.prevent_evidence_ingestion_history_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.apply_evidence_replay_guard(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id,
  trust.evidence_type, trust.evidence_event_id, bigint, text, timestamptz, timestamptz, text, boolean
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust.apply_evidence_replay_guard(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id,
  trust.evidence_type, trust.evidence_event_id, bigint, text, timestamptz, timestamptz, text, boolean
) TO tenant_trust_app;

COMMENT ON TABLE trust.evidence_ingestion_state IS
  'Mutable high-water mark for one tenant evidence source key epoch; only the replay-guard function may update it';
COMMENT ON TABLE trust.evidence_ingestion_receipts IS
  'Append-only accepted-evidence replay metadata; raw evidence payloads are deliberately excluded';
COMMENT ON TABLE trust.evidence_ingestion_rejections IS
  'Append-only observable freshness, replay and ordering rejections with event and nonce identifiers stored only as SHA-256 hashes';
COMMENT ON FUNCTION trust.apply_evidence_replay_guard(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id,
  trust.evidence_type, trust.evidence_event_id, bigint, text, timestamptz, timestamptz, text, boolean
) IS 'Atomically enforces trusted-time freshness, source TTL, duplicate event/nonce and monotonic sequence/observation ordering for a verified evidence envelope';
