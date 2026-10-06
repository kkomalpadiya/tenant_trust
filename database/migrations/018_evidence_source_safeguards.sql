ALTER TYPE trust.evidence_ingestion_rejection_reason ADD VALUE 'EVIDENCE_RATE_LIMITED';

ALTER TABLE trust.evidence_sources
  ADD COLUMN rate_limit_window_seconds integer NOT NULL DEFAULT 60,
  ADD COLUMN rate_limit_max_events integer NOT NULL DEFAULT 120,
  ADD COLUMN rate_limit_suspension_threshold integer NOT NULL DEFAULT 10,
  ADD COLUMN maximum_influence numeric(5,4) NOT NULL DEFAULT 0.2500,
  ADD CONSTRAINT evidence_sources_rate_window_range
    CHECK (rate_limit_window_seconds BETWEEN 1 AND 3600),
  ADD CONSTRAINT evidence_sources_rate_max_events_range
    CHECK (rate_limit_max_events BETWEEN 1 AND 100000),
  ADD CONSTRAINT evidence_sources_rate_suspension_threshold_range
    CHECK (rate_limit_suspension_threshold BETWEEN 1 AND 1000),
  ADD CONSTRAINT evidence_sources_maximum_influence_range
    CHECK (maximum_influence BETWEEN 0.0001 AND 1.0000);

ALTER TABLE trust.evidence_ingestion_receipts
  ADD COLUMN maximum_source_influence numeric(5,4);

ALTER TABLE trust.evidence_ingestion_receipts
  DISABLE TRIGGER evidence_ingestion_receipts_keep_history;
UPDATE trust.evidence_ingestion_receipts AS receipt
SET maximum_source_influence = LEAST(source.maximum_influence, configuration.maximum_source_influence)
FROM trust.evidence_sources AS source
JOIN trust.trust_configurations AS configuration
  ON configuration.tenant_id = source.tenant_id
 AND configuration.state = 'active'
WHERE source.tenant_id = receipt.tenant_id
  AND source.source_id = receipt.source_id;
ALTER TABLE trust.evidence_ingestion_receipts
  ENABLE TRIGGER evidence_ingestion_receipts_keep_history;

ALTER TABLE trust.evidence_ingestion_receipts
  ALTER COLUMN maximum_source_influence SET NOT NULL,
  ADD CONSTRAINT evidence_ingestion_receipts_influence_range
    CHECK (maximum_source_influence BETWEEN 0.0001 AND 1.0000);

CREATE OR REPLACE FUNCTION trust.prevent_evidence_source_registry_bypass()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  IF current_user = 'tenant_trust_app' THEN
    IF TG_OP = 'INSERT'
       AND (NEW.state <> 'planned' OR NEW.verification_key_sha256 IS NOT NULL) THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source enrollment must use the key registry.';
    END IF;

    IF TG_OP = 'UPDATE'
       AND (
         NEW.state IS DISTINCT FROM OLD.state
         OR NEW.verification_algorithm IS DISTINCT FROM OLD.verification_algorithm
         OR NEW.verification_key_sha256 IS DISTINCT FROM OLD.verification_key_sha256
         OR NEW.rate_limit_window_seconds IS DISTINCT FROM OLD.rate_limit_window_seconds
         OR NEW.rate_limit_max_events IS DISTINCT FROM OLD.rate_limit_max_events
         OR NEW.rate_limit_suspension_threshold IS DISTINCT FROM OLD.rate_limit_suspension_threshold
         OR NEW.maximum_influence IS DISTINCT FROM OLD.maximum_influence
       ) THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source lifecycle and safeguard changes must use governed registry functions.';
    END IF;

    IF TG_OP = 'DELETE' AND EXISTS (
      SELECT 1 FROM trust.evidence_source_keys AS source_key
      WHERE source_key.tenant_id = OLD.tenant_id AND source_key.source_id = OLD.source_id
    ) THEN
      RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Enrolled evidence source history is append-only.';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END
$function$;

CREATE TYPE trust.evidence_source_control_event_type AS ENUM (
  'configured', 'suspended', 'resumed', 'automatically_suspended'
);

CREATE TABLE trust.evidence_source_rate_state (
  tenant_id identity.tenant_id NOT NULL,
  source_id trust.source_id NOT NULL,
  window_started_at timestamptz NOT NULL,
  accepted_count integer NOT NULL DEFAULT 0,
  rate_limited_count integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT evidence_source_rate_state_pk PRIMARY KEY (tenant_id, source_id),
  CONSTRAINT evidence_source_rate_state_source_fk FOREIGN KEY (tenant_id, source_id)
    REFERENCES trust.evidence_sources (tenant_id, source_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_source_rate_state_counts_nonnegative CHECK (
    accepted_count >= 0 AND rate_limited_count >= 0
  ),
  CONSTRAINT evidence_source_rate_state_time_order CHECK (updated_at >= window_started_at)
);

CREATE TABLE trust.evidence_source_control_events (
  control_event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id identity.tenant_id NOT NULL,
  source_id trust.source_id NOT NULL,
  event_type trust.evidence_source_control_event_type NOT NULL,
  actor_subject_id identity.subject_id,
  reason_code text NOT NULL,
  rate_limit_window_seconds integer NOT NULL,
  rate_limit_max_events integer NOT NULL,
  rate_limit_suspension_threshold integer NOT NULL,
  maximum_influence numeric(5,4) NOT NULL,
  occurred_at timestamptz NOT NULL,
  CONSTRAINT evidence_source_control_events_source_fk FOREIGN KEY (tenant_id, source_id)
    REFERENCES trust.evidence_sources (tenant_id, source_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_source_control_events_actor_fk FOREIGN KEY (tenant_id, actor_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_source_control_events_reason_format CHECK (
    reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT evidence_source_control_events_actor_shape CHECK (
    (event_type = 'automatically_suspended' AND actor_subject_id IS NULL)
    OR (event_type <> 'automatically_suspended' AND actor_subject_id IS NOT NULL)
  )
);

CREATE INDEX evidence_source_control_events_lookup
  ON trust.evidence_source_control_events (tenant_id, source_id, occurred_at DESC);

CREATE FUNCTION trust.prevent_evidence_source_control_history_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Evidence source control history is append-only.';
END
$function$;

CREATE TRIGGER evidence_source_control_events_keep_history
BEFORE UPDATE OR DELETE ON trust.evidence_source_control_events
FOR EACH ROW EXECUTE FUNCTION trust.prevent_evidence_source_control_history_rewrite();

CREATE FUNCTION trust.snapshot_evidence_source_influence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, trust
SET row_security = off
AS $function$
BEGIN
  SELECT LEAST(source.maximum_influence, configuration.maximum_source_influence)
  INTO STRICT NEW.maximum_source_influence
  FROM trust.evidence_sources AS source
  JOIN trust.trust_configurations AS configuration
    ON configuration.tenant_id = source.tenant_id
   AND configuration.state = 'active'
  WHERE source.tenant_id = NEW.tenant_id
    AND source.source_id = NEW.source_id;
  RETURN NEW;
END
$function$;

CREATE TRIGGER evidence_ingestion_receipts_snapshot_influence
BEFORE INSERT ON trust.evidence_ingestion_receipts
FOR EACH ROW EXECUTE FUNCTION trust.snapshot_evidence_source_influence();

CREATE FUNCTION trust.configure_evidence_source_safeguards(
  p_source_id trust.source_id,
  p_rate_limit_window_seconds integer,
  p_rate_limit_max_events integer,
  p_rate_limit_suspension_threshold integer,
  p_maximum_influence numeric,
  p_occurred_at timestamptz
)
RETURNS TABLE (
  configured_source_id trust.source_id,
  configured_source_state trust.evidence_source_state,
  configured_source_version bigint,
  rate_limit_window_seconds integer,
  rate_limit_max_events integer,
  rate_limit_suspension_threshold integer,
  maximum_influence numeric(5,4)
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  actor_tenant identity.tenant_id := identity.current_tenant_id();
  actor_id identity.subject_id := identity.current_subject_id();
  source_record trust.evidence_sources%ROWTYPE;
BEGIN
  IF actor_tenant IS NULL OR actor_id IS NULL OR NOT identity.current_actor_is_tenant_admin()
    OR p_rate_limit_window_seconds NOT BETWEEN 1 AND 3600
    OR p_rate_limit_max_events NOT BETWEEN 1 AND 100000
    OR p_rate_limit_suspension_threshold NOT BETWEEN 1 AND 1000
    OR p_maximum_influence NOT BETWEEN 0.0001 AND 1.0000
    OR p_occurred_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source safeguard configuration denied.';
  END IF;

  SELECT * INTO source_record
  FROM trust.evidence_sources AS source
  WHERE source.tenant_id = actor_tenant AND source.source_id = p_source_id
  FOR UPDATE;
  IF NOT FOUND OR source_record.state = 'retired' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source safeguard configuration denied.';
  END IF;

  UPDATE trust.evidence_sources
  SET rate_limit_window_seconds = p_rate_limit_window_seconds,
      rate_limit_max_events = p_rate_limit_max_events,
      rate_limit_suspension_threshold = p_rate_limit_suspension_threshold,
      maximum_influence = p_maximum_influence,
      version = version + 1,
      updated_at = GREATEST(clock_timestamp(), p_occurred_at)
  WHERE tenant_id = actor_tenant AND source_id = p_source_id
  RETURNING * INTO source_record;

  DELETE FROM trust.evidence_source_rate_state
  WHERE tenant_id = actor_tenant AND source_id = p_source_id;

  INSERT INTO trust.evidence_source_control_events (
    tenant_id, source_id, event_type, actor_subject_id, reason_code,
    rate_limit_window_seconds, rate_limit_max_events,
    rate_limit_suspension_threshold, maximum_influence, occurred_at
  ) VALUES (
    actor_tenant, p_source_id, 'configured', actor_id, 'SAFEGUARDS_CONFIGURED',
    p_rate_limit_window_seconds, p_rate_limit_max_events,
    p_rate_limit_suspension_threshold, p_maximum_influence, p_occurred_at
  );

  RETURN QUERY SELECT source_record.source_id, source_record.state, source_record.version,
    source_record.rate_limit_window_seconds, source_record.rate_limit_max_events,
    source_record.rate_limit_suspension_threshold, source_record.maximum_influence;
END
$function$;

CREATE FUNCTION trust.set_evidence_source_suspension(
  p_source_id trust.source_id,
  p_suspended boolean,
  p_reason_code text,
  p_occurred_at timestamptz
)
RETURNS TABLE (
  controlled_source_id trust.source_id,
  controlled_source_state trust.evidence_source_state,
  controlled_source_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  actor_tenant identity.tenant_id := identity.current_tenant_id();
  actor_id identity.subject_id := identity.current_subject_id();
  source_record trust.evidence_sources%ROWTYPE;
  target_state trust.evidence_source_state;
BEGIN
  IF actor_tenant IS NULL OR actor_id IS NULL OR NOT identity.current_actor_is_tenant_admin()
    OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
    OR p_occurred_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source suspension change denied.';
  END IF;

  SELECT * INTO source_record
  FROM trust.evidence_sources AS source
  WHERE source.tenant_id = actor_tenant AND source.source_id = p_source_id
  FOR UPDATE;
  target_state := CASE WHEN p_suspended THEN 'suspended' ELSE 'active' END;
  IF NOT FOUND
    OR (p_suspended AND source_record.state <> 'active')
    OR (NOT p_suspended AND source_record.state <> 'suspended')
    OR (NOT p_suspended AND NOT EXISTS (
      SELECT 1 FROM trust.evidence_source_keys AS source_key
      WHERE source_key.tenant_id = actor_tenant
        AND source_key.source_id = p_source_id
        AND source_key.state = 'active'
        AND source_key.public_key_sha256 = source_record.verification_key_sha256
    )) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source suspension change denied.';
  END IF;

  UPDATE trust.evidence_sources
  SET state = target_state,
      version = version + 1,
      updated_at = GREATEST(clock_timestamp(), p_occurred_at)
  WHERE tenant_id = actor_tenant AND source_id = p_source_id
  RETURNING * INTO source_record;

  DELETE FROM trust.evidence_source_rate_state
  WHERE tenant_id = actor_tenant AND source_id = p_source_id;

  INSERT INTO trust.evidence_source_control_events (
    tenant_id, source_id, event_type, actor_subject_id, reason_code,
    rate_limit_window_seconds, rate_limit_max_events,
    rate_limit_suspension_threshold, maximum_influence, occurred_at
  ) VALUES (
    actor_tenant, p_source_id,
    (CASE WHEN p_suspended THEN 'suspended' ELSE 'resumed' END)::trust.evidence_source_control_event_type,
    actor_id, p_reason_code, source_record.rate_limit_window_seconds,
    source_record.rate_limit_max_events, source_record.rate_limit_suspension_threshold,
    source_record.maximum_influence, p_occurred_at
  );

  RETURN QUERY SELECT source_record.source_id, source_record.state, source_record.version;
END
$function$;

ALTER FUNCTION trust.apply_evidence_replay_guard(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id,
  trust.evidence_type, trust.evidence_event_id, bigint, text, timestamptz, timestamptz, text, boolean
) RENAME TO apply_evidence_replay_guard_without_flood_control;

REVOKE ALL ON FUNCTION trust.apply_evidence_replay_guard_without_flood_control(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id,
  trust.evidence_type, trust.evidence_event_id, bigint, text, timestamptz, timestamptz, text, boolean
) FROM PUBLIC, tenant_trust_app;

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
  source_record trust.evidence_sources%ROWTYPE;
  rate_record trust.evidence_source_rate_state%ROWTYPE;
  decision record;
BEGIN
  SELECT source.* INTO source_record
  FROM identity.tenants AS tenant
  JOIN identity.tenant_memberships AS membership
    ON membership.tenant_id = tenant.tenant_id AND membership.subject_id = p_subject_id
  JOIN identity.subjects AS subject ON subject.subject_id = membership.subject_id
  JOIN trust.evidence_sources AS source
    ON source.tenant_id = tenant.tenant_id AND source.source_id = p_source_id
  JOIN trust.evidence_source_keys AS source_key
    ON source_key.tenant_id = source.tenant_id
   AND source_key.source_id = source.source_id AND source_key.key_id = p_key_id
  WHERE tenant.tenant_id = p_tenant_id
    AND tenant.state = 'active' AND subject.state = 'active' AND membership.state = 'active'
    AND source.state = 'active' AND source.evidence_type = p_evidence_type
    AND source.synthetic = p_synthetic AND source.verification_algorithm = 'ed25519'
    AND source.verification_key_sha256 = source_key.public_key_sha256
    AND source_key.state = 'active' AND source_key.algorithm = 'Ed25519'
  FOR UPDATE OF source;

  IF NOT FOUND THEN
    RETURN QUERY SELECT * FROM trust.apply_evidence_replay_guard_without_flood_control(
      p_tenant_id, p_subject_id, p_source_id, p_key_id, p_evidence_type, p_event_id,
      p_source_sequence, p_nonce, p_observed_at, p_expires_at, p_content_hash_sha256, p_synthetic
    );
    RETURN;
  END IF;

  INSERT INTO trust.evidence_source_rate_state (
    tenant_id, source_id, window_started_at, updated_at
  ) VALUES (p_tenant_id, p_source_id, v_now, v_now)
  ON CONFLICT (tenant_id, source_id) DO NOTHING;

  SELECT * INTO rate_record
  FROM trust.evidence_source_rate_state AS rate_state
  WHERE rate_state.tenant_id = p_tenant_id AND rate_state.source_id = p_source_id
  FOR UPDATE;

  IF v_now >= rate_record.window_started_at
      + make_interval(secs => source_record.rate_limit_window_seconds) THEN
    UPDATE trust.evidence_source_rate_state
    SET window_started_at = v_now, accepted_count = 0, rate_limited_count = 0, updated_at = v_now
    WHERE tenant_id = p_tenant_id AND source_id = p_source_id
    RETURNING * INTO rate_record;
  END IF;

  IF rate_record.accepted_count >= source_record.rate_limit_max_events THEN
    UPDATE trust.evidence_source_rate_state
    SET rate_limited_count = rate_limited_count + 1, updated_at = v_now
    WHERE tenant_id = p_tenant_id AND source_id = p_source_id
    RETURNING * INTO rate_record;

    INSERT INTO trust.evidence_ingestion_rejections (
      tenant_id, source_id, key_id, subject_id, reason_code,
      event_id_sha256, nonce_sha256, content_hash_sha256,
      source_sequence, observed_at, expires_at, rejected_at
    ) VALUES (
      p_tenant_id, p_source_id, p_key_id, p_subject_id, 'EVIDENCE_RATE_LIMITED',
      encode(public.digest(p_event_id::text, 'sha256'), 'hex'),
      encode(public.digest(p_nonce, 'sha256'), 'hex'), p_content_hash_sha256,
      p_source_sequence, p_observed_at, p_expires_at, v_now
    );

    IF rate_record.rate_limited_count >= source_record.rate_limit_suspension_threshold THEN
      UPDATE trust.evidence_sources
      SET state = 'suspended', version = version + 1, updated_at = v_now
      WHERE tenant_id = p_tenant_id AND source_id = p_source_id;
      INSERT INTO trust.evidence_source_control_events (
        tenant_id, source_id, event_type, actor_subject_id, reason_code,
        rate_limit_window_seconds, rate_limit_max_events,
        rate_limit_suspension_threshold, maximum_influence, occurred_at
      ) VALUES (
        p_tenant_id, p_source_id, 'automatically_suspended', NULL, 'RATE_LIMIT_THRESHOLD_REACHED',
        source_record.rate_limit_window_seconds, source_record.rate_limit_max_events,
        source_record.rate_limit_suspension_threshold, source_record.maximum_influence, v_now
      );
    END IF;

    RETURN QUERY SELECT FALSE, 'EVIDENCE_RATE_LIMITED'::text, NULL::timestamptz,
      (SELECT max(receipt.source_sequence)
       FROM trust.evidence_ingestion_receipts AS receipt
       WHERE receipt.tenant_id = p_tenant_id
         AND receipt.source_id = p_source_id
         AND receipt.key_id = p_key_id);
    RETURN;
  END IF;

  SELECT * INTO decision
  FROM trust.apply_evidence_replay_guard_without_flood_control(
    p_tenant_id, p_subject_id, p_source_id, p_key_id, p_evidence_type, p_event_id,
    p_source_sequence, p_nonce, p_observed_at, p_expires_at, p_content_hash_sha256, p_synthetic
  );
  IF decision.accepted THEN
    UPDATE trust.evidence_source_rate_state
    SET accepted_count = accepted_count + 1, updated_at = v_now
    WHERE tenant_id = p_tenant_id AND source_id = p_source_id;
  END IF;
  RETURN QUERY SELECT decision.accepted, decision.reason_code,
    decision.accepted_at, decision.highest_source_sequence;
END
$function$;

REVOKE ALL ON TABLE trust.evidence_source_rate_state FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON TABLE trust.evidence_source_control_events FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON SEQUENCE trust.evidence_source_control_events_control_event_id_seq FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION trust.prevent_evidence_source_control_history_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.snapshot_evidence_source_influence() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.configure_evidence_source_safeguards(
  trust.source_id, integer, integer, integer, numeric, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.set_evidence_source_suspension(
  trust.source_id, boolean, text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.apply_evidence_replay_guard(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id,
  trust.evidence_type, trust.evidence_event_id, bigint, text, timestamptz, timestamptz, text, boolean
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust.configure_evidence_source_safeguards(
  trust.source_id, integer, integer, integer, numeric, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.set_evidence_source_suspension(
  trust.source_id, boolean, text, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.apply_evidence_replay_guard(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id,
  trust.evidence_type, trust.evidence_event_id, bigint, text, timestamptz, timestamptz, text, boolean
) TO tenant_trust_app;

COMMENT ON TABLE trust.evidence_source_rate_state IS
  'Transactionally locked fixed-window acceptance and rate-limit counters for one tenant evidence source';
COMMENT ON TABLE trust.evidence_source_control_events IS
  'Append-only tenant evidence-source safeguard configuration and suspension history';
COMMENT ON COLUMN trust.evidence_ingestion_receipts.maximum_source_influence IS
  'Accepted-time snapshot of the lesser source-specific and active tenant-wide influence caps';
COMMENT ON FUNCTION trust.configure_evidence_source_safeguards(
  trust.source_id, integer, integer, integer, numeric, timestamptz
) IS 'Tenant-admin boundary for per-source rate, automatic suspension and influence controls';
COMMENT ON FUNCTION trust.set_evidence_source_suspension(
  trust.source_id, boolean, text, timestamptz
) IS 'Tenant-admin boundary for suspending or resuming an evidence source with an active key';
COMMENT ON FUNCTION trust.apply_evidence_replay_guard(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id,
  trust.evidence_type, trust.evidence_event_id, bigint, text, timestamptz, timestamptz, text, boolean
) IS 'Atomically enforces per-source flood limits before applying freshness, replay and ordering checks';
