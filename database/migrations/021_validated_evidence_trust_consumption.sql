CREATE TABLE trust.subject_component_observations (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  evidence_type trust.evidence_type NOT NULL,
  component_score numeric(5,2) NOT NULL,
  delivery_event_id identity.event_id NOT NULL,
  evidence_id trust.evidence_id NOT NULL,
  source_event_id trust.evidence_event_id NOT NULL,
  source_id trust.source_id NOT NULL,
  source_sequence bigint NOT NULL,
  stream_sequence bigint NOT NULL,
  observed_at timestamptz NOT NULL,
  accepted_at timestamptz NOT NULL,
  processed_at timestamptz NOT NULL,
  CONSTRAINT subject_component_observations_pk
    PRIMARY KEY (tenant_id, subject_id, evidence_type),
  CONSTRAINT subject_component_observations_membership_fk
    FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT subject_component_observations_delivery_fk
    FOREIGN KEY (tenant_id, delivery_event_id)
    REFERENCES trust.evidence_event_outbox (tenant_id, delivery_event_id) ON DELETE RESTRICT,
  CONSTRAINT subject_component_observations_evidence_fk
    FOREIGN KEY (tenant_id, evidence_id)
    REFERENCES trust.evidence_event_outbox (tenant_id, evidence_id) ON DELETE RESTRICT,
  CONSTRAINT subject_component_observations_delivery_unique
    UNIQUE (tenant_id, delivery_event_id),
  CONSTRAINT subject_component_observations_score_range
    CHECK (component_score BETWEEN 0 AND 100),
  CONSTRAINT subject_component_observations_sequences_positive
    CHECK (source_sequence >= 0 AND stream_sequence > 0),
  CONSTRAINT subject_component_observations_times_ordered
    CHECK (observed_at <= accepted_at AND accepted_at <= processed_at + interval '2 seconds')
);

CREATE INDEX subject_component_observations_freshness
  ON trust.subject_component_observations (
    tenant_id, subject_id, observed_at DESC, stream_sequence DESC
  );

CREATE FUNCTION trust.consume_validated_evidence_component(
  p_consumer_name text,
  p_tenant_id identity.tenant_id,
  p_delivery_event_id identity.event_id,
  p_evidence_id trust.evidence_id,
  p_stream_sequence bigint,
  p_signed_event_sha256 identity.sha256_digest,
  p_component_score numeric,
  p_processed_at timestamptz
)
RETURNS TABLE (
  applied boolean,
  outcome_code text,
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  evidence_type trust.evidence_type,
  update_version bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_source_event_id trust.evidence_event_id;
  v_subject_id identity.subject_id;
  v_source_id trust.source_id;
  v_evidence_type trust.evidence_type;
  v_source_sequence bigint;
  v_observed_at timestamptz;
  v_accepted_at timestamptz;
  v_effect_recorded boolean;
  v_staged_count integer;
  v_changed_count integer;
  v_configuration_version integer;
  v_model_version text;
  v_expected_previous_version bigint;
  v_update_version bigint;
  v_snapshot_observed_at timestamptz;
  v_identity_score numeric;
  v_device_score numeric;
  v_behaviour_score numeric;
  v_certificate_score numeric;
  v_compliance_score numeric;
  v_evidence_references jsonb;
BEGIN
  IF p_component_score IS NULL
     OR p_component_score::text = 'NaN'
     OR p_component_score NOT BETWEEN 0 AND 100
     OR p_processed_at IS NULL
     OR p_processed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Validated evidence component input is invalid.';
  END IF;

  SELECT outbox.source_event_id,
         receipt.subject_id,
         receipt.source_id,
         receipt.evidence_type,
         receipt.source_sequence,
         receipt.observed_at,
         receipt.accepted_at
  INTO v_source_event_id,
       v_subject_id,
       v_source_id,
       v_evidence_type,
       v_source_sequence,
       v_observed_at,
       v_accepted_at
  FROM trust.evidence_event_outbox AS outbox
  JOIN trust.evidence_ingestion_receipts AS receipt
    ON receipt.tenant_id = outbox.tenant_id
   AND receipt.event_id = outbox.source_event_id
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.delivery_event_id = p_delivery_event_id
    AND outbox.evidence_id = p_evidence_id
    AND outbox.status = 'published'
    AND outbox.stream_sequence = p_stream_sequence
    AND outbox.signed_event_sha256 = p_signed_event_sha256
  FOR SHARE OF outbox, receipt;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Validated evidence delivery is not authoritative.';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(p_tenant_id::text || ':' || v_subject_id::text, 0)
  );

  SELECT trust.record_evidence_event_effect(
    p_consumer_name,
    p_tenant_id,
    p_delivery_event_id,
    p_evidence_id,
    p_stream_sequence,
    p_signed_event_sha256,
    p_processed_at
  ) INTO v_effect_recorded;

  IF NOT v_effect_recorded THEN
    SELECT current_state.update_version INTO v_update_version
    FROM trust.subject_trust_current AS current_state
    WHERE current_state.tenant_id = p_tenant_id
      AND current_state.subject_id = v_subject_id;

    RETURN QUERY SELECT false, 'duplicate'::text, p_tenant_id,
      v_subject_id, v_evidence_type, v_update_version;
    RETURN;
  END IF;

  INSERT INTO trust.subject_component_observations (
    tenant_id, subject_id, evidence_type, component_score,
    delivery_event_id, evidence_id, source_event_id, source_id,
    source_sequence, stream_sequence, observed_at, accepted_at, processed_at
  ) VALUES (
    p_tenant_id, v_subject_id, v_evidence_type, p_component_score,
    p_delivery_event_id, p_evidence_id, v_source_event_id, v_source_id,
    v_source_sequence, p_stream_sequence, v_observed_at, v_accepted_at, p_processed_at
  )
  ON CONFLICT ON CONSTRAINT subject_component_observations_pk DO UPDATE
  SET component_score = EXCLUDED.component_score,
      delivery_event_id = EXCLUDED.delivery_event_id,
      evidence_id = EXCLUDED.evidence_id,
      source_event_id = EXCLUDED.source_event_id,
      source_id = EXCLUDED.source_id,
      source_sequence = EXCLUDED.source_sequence,
      stream_sequence = EXCLUDED.stream_sequence,
      observed_at = EXCLUDED.observed_at,
      accepted_at = EXCLUDED.accepted_at,
      processed_at = EXCLUDED.processed_at
  WHERE (
    EXCLUDED.observed_at,
    EXCLUDED.stream_sequence,
    EXCLUDED.delivery_event_id::text
  ) > (
    subject_component_observations.observed_at,
    subject_component_observations.stream_sequence,
    subject_component_observations.delivery_event_id::text
  );
  GET DIAGNOSTICS v_changed_count = ROW_COUNT;

  IF v_changed_count = 0 THEN
    SELECT current_state.update_version INTO v_update_version
    FROM trust.subject_trust_current AS current_state
    WHERE current_state.tenant_id = p_tenant_id
      AND current_state.subject_id = v_subject_id;

    RETURN QUERY SELECT true, 'superseded'::text, p_tenant_id,
      v_subject_id, v_evidence_type, v_update_version;
    RETURN;
  END IF;

  SELECT count(*)::integer,
         max(observation.observed_at),
         max(observation.component_score) FILTER (WHERE observation.evidence_type = 'identity'),
         max(observation.component_score) FILTER (WHERE observation.evidence_type = 'device'),
         max(observation.component_score) FILTER (WHERE observation.evidence_type = 'behaviour'),
         max(observation.component_score) FILTER (WHERE observation.evidence_type = 'certificate'),
         max(observation.component_score) FILTER (WHERE observation.evidence_type = 'compliance'),
         jsonb_agg(
           jsonb_build_object(
             'evidenceId', observation.evidence_id,
             'sourceEventId', observation.source_event_id,
             'evidenceType', observation.evidence_type
           ) ORDER BY observation.evidence_type
         )
  INTO v_staged_count,
       v_snapshot_observed_at,
       v_identity_score,
       v_device_score,
       v_behaviour_score,
       v_certificate_score,
       v_compliance_score,
       v_evidence_references
  FROM trust.subject_component_observations AS observation
  WHERE observation.tenant_id = p_tenant_id
    AND observation.subject_id = v_subject_id;

  IF v_staged_count < 5 THEN
    RETURN QUERY SELECT true, 'staged'::text, p_tenant_id,
      v_subject_id, v_evidence_type, NULL::bigint;
    RETURN;
  END IF;

  SELECT configuration.configuration_version, configuration.model_version
  INTO v_configuration_version, v_model_version
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = p_tenant_id
    AND configuration.state = 'active'
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Active trust configuration is unavailable.';
  END IF;

  SELECT current_state.update_version INTO v_expected_previous_version
  FROM trust.subject_trust_current AS current_state
  WHERE current_state.tenant_id = p_tenant_id
    AND current_state.subject_id = v_subject_id
  FOR UPDATE;
  IF NOT FOUND THEN v_expected_previous_version := 0; END IF;

  SELECT stored.update_version INTO STRICT v_update_version
  FROM trust.store_subject_trust_state(
    p_tenant_id,
    v_subject_id,
    v_expected_previous_version,
    v_model_version,
    v_configuration_version,
    v_identity_score,
    v_device_score,
    v_behaviour_score,
    v_certificate_score,
    v_compliance_score,
    v_snapshot_observed_at,
    v_evidence_references
  ) AS stored;

  RETURN QUERY SELECT true, 'state_updated'::text, p_tenant_id,
    v_subject_id, v_evidence_type, v_update_version;
END
$function$;

ALTER TABLE trust.subject_component_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_component_observations FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE trust.subject_component_observations
  FROM PUBLIC, tenant_trust_app, tenant_trust_trust_engine, tenant_trust_evidence_event_consumer;
REVOKE ALL ON FUNCTION trust.consume_validated_evidence_component(
  text, identity.tenant_id, identity.event_id, trust.evidence_id,
  bigint, identity.sha256_digest, numeric, timestamptz
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust.consume_validated_evidence_component(
  text, identity.tenant_id, identity.event_id, trust.evidence_id,
  bigint, identity.sha256_digest, numeric, timestamptz
) TO tenant_trust_evidence_event_consumer;

COMMENT ON TABLE trust.subject_component_observations IS
  'Latest ordered validated evidence component per tenant and subject; complete sets become append-only trust-state versions';
COMMENT ON FUNCTION trust.consume_validated_evidence_component(
  text, identity.tenant_id, identity.event_id, trust.evidence_id,
  bigint, identity.sha256_digest, numeric, timestamptz
) IS
  'Atomically records consume-once delivery, serializes one subject, stages only newer component evidence and appends a complete trust-state version';
