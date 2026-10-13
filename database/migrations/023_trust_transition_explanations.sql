CREATE DOMAIN trust.transition_id AS text
  CHECK (VALUE ~ '^trn_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

ALTER TABLE trust.subject_trust_state_evidence
  ADD CONSTRAINT subject_trust_state_evidence_exact_reference_unique
  UNIQUE (
    tenant_id, subject_id, update_version, evidence_type, evidence_id, source_event_id
  );

CREATE TABLE trust.subject_trust_transitions (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  transition_id trust.transition_id NOT NULL,
  event_id identity.event_id NOT NULL,
  update_version bigint NOT NULL,
  previous_transition_id trust.transition_id,
  previous_score numeric(5,2) NOT NULL,
  previous_band text NOT NULL,
  previous_recovery_streak smallint NOT NULL,
  new_score numeric(5,2) NOT NULL,
  new_band text NOT NULL,
  new_recovery_streak smallint NOT NULL,
  weighted_score numeric(5,2) NOT NULL,
  smoothed_score numeric(5,2) NOT NULL,
  transition_kind text NOT NULL,
  model_version text NOT NULL,
  configuration_version integer NOT NULL,
  observed_at timestamptz NOT NULL,
  evaluated_at timestamptz NOT NULL,
  explanation_json text NOT NULL,
  explanation_hash_sha256 identity.sha256_digest NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT subject_trust_transitions_pk PRIMARY KEY (tenant_id, transition_id),
  CONSTRAINT subject_trust_transitions_event_unique UNIQUE (event_id),
  CONSTRAINT subject_trust_transitions_state_unique
    UNIQUE (tenant_id, subject_id, update_version),
  CONSTRAINT subject_trust_transitions_state_fk
    FOREIGN KEY (tenant_id, subject_id, update_version)
    REFERENCES trust.subject_trust_state_versions (tenant_id, subject_id, update_version)
    ON DELETE RESTRICT,
  CONSTRAINT subject_trust_transitions_configuration_fk
    FOREIGN KEY (tenant_id, configuration_version)
    REFERENCES trust.trust_configurations (tenant_id, configuration_version)
    ON DELETE RESTRICT,
  CONSTRAINT subject_trust_transitions_previous_fk
    FOREIGN KEY (tenant_id, previous_transition_id)
    REFERENCES trust.subject_trust_transitions (tenant_id, transition_id)
    ON DELETE RESTRICT,
  CONSTRAINT subject_trust_transitions_score_ranges CHECK (
    previous_score BETWEEN 0 AND 100
    AND new_score BETWEEN 0 AND 100
    AND weighted_score BETWEEN 0 AND 100
    AND smoothed_score BETWEEN 0 AND 100
  ),
  CONSTRAINT subject_trust_transitions_band_values CHECK (
    previous_band IN ('uninitialized', 'low', 'medium', 'high')
    AND new_band IN ('low', 'medium', 'high')
  ),
  CONSTRAINT subject_trust_transitions_previous_shape CHECK (
    (previous_transition_id IS NULL
      AND previous_band = 'uninitialized'
      AND previous_recovery_streak = 0)
    OR
    (previous_transition_id IS NOT NULL
      AND previous_band IN ('low', 'medium', 'high'))
  ),
  CONSTRAINT subject_trust_transitions_recovery_ranges CHECK (
    previous_recovery_streak BETWEEN 0 AND 1
    AND new_recovery_streak BETWEEN 0 AND 1
  ),
  CONSTRAINT subject_trust_transitions_kind_values CHECK (
    transition_kind IN ('held', 'deteriorated', 'recovered', 'critical-override')
  ),
  CONSTRAINT subject_trust_transitions_model_format CHECK (
    model_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
  ),
  CONSTRAINT subject_trust_transitions_time_order CHECK (
    observed_at <= evaluated_at AND evaluated_at <= recorded_at + interval '2 seconds'
  ),
  CONSTRAINT subject_trust_transitions_explanation_json CHECK (
    jsonb_typeof(explanation_json::jsonb) = 'object'
  )
);

CREATE INDEX subject_trust_transitions_history_lookup
  ON trust.subject_trust_transitions (
    tenant_id, subject_id, evaluated_at DESC, update_version DESC
  );

CREATE TABLE trust.subject_trust_transition_contributions (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  transition_id trust.transition_id NOT NULL,
  update_version bigint NOT NULL,
  component_id trust.evidence_type NOT NULL,
  normalized_value numeric(5,2) NOT NULL,
  weight numeric(7,6) NOT NULL,
  weighted_contribution numeric(9,6) NOT NULL,
  evidence_id trust.evidence_id NOT NULL,
  source_event_id trust.evidence_event_id NOT NULL,
  CONSTRAINT subject_trust_transition_contributions_pk
    PRIMARY KEY (tenant_id, transition_id, component_id),
  CONSTRAINT subject_trust_transition_contributions_transition_fk
    FOREIGN KEY (tenant_id, transition_id)
    REFERENCES trust.subject_trust_transitions (tenant_id, transition_id)
    ON DELETE RESTRICT,
  CONSTRAINT subject_trust_transition_contributions_state_evidence_fk
    FOREIGN KEY (
      tenant_id, subject_id, update_version, component_id, evidence_id, source_event_id
    ) REFERENCES trust.subject_trust_state_evidence (
      tenant_id, subject_id, update_version, evidence_type, evidence_id, source_event_id
    ) ON DELETE RESTRICT,
  CONSTRAINT subject_trust_transition_contributions_value_ranges CHECK (
    normalized_value BETWEEN 0 AND 100
    AND weight BETWEEN 0 AND 1
    AND weighted_contribution BETWEEN 0 AND 100
  )
);

CREATE TABLE trust.subject_trust_transition_current (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  transition_id trust.transition_id NOT NULL,
  update_version bigint NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT subject_trust_transition_current_pk PRIMARY KEY (tenant_id, subject_id),
  CONSTRAINT subject_trust_transition_current_transition_fk
    FOREIGN KEY (tenant_id, transition_id)
    REFERENCES trust.subject_trust_transitions (tenant_id, transition_id)
    ON DELETE RESTRICT,
  CONSTRAINT subject_trust_transition_current_state_fk
    FOREIGN KEY (tenant_id, subject_id, update_version)
    REFERENCES trust.subject_trust_state_versions (tenant_id, subject_id, update_version)
    ON DELETE RESTRICT
);

CREATE TABLE trust.trust_transition_events (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  event_id identity.event_id NOT NULL,
  transition_id trust.transition_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  causation_event_id identity.event_id NOT NULL,
  event_json text NOT NULL,
  event_sha256 identity.sha256_digest NOT NULL,
  recorded_at timestamptz NOT NULL,
  CONSTRAINT trust_transition_events_pk PRIMARY KEY (tenant_id, event_id),
  CONSTRAINT trust_transition_events_id_global_unique UNIQUE (event_id),
  CONSTRAINT trust_transition_events_transition_unique UNIQUE (tenant_id, transition_id),
  CONSTRAINT trust_transition_events_transition_fk
    FOREIGN KEY (tenant_id, transition_id)
    REFERENCES trust.subject_trust_transitions (tenant_id, transition_id)
    ON DELETE RESTRICT,
  CONSTRAINT trust_transition_events_json_object CHECK (
    jsonb_typeof(event_json::jsonb) = 'object'
  )
);

CREATE TRIGGER subject_trust_transitions_keep_history
BEFORE UPDATE OR DELETE ON trust.subject_trust_transitions
FOR EACH ROW EXECUTE FUNCTION trust.prevent_subject_trust_history_rewrite();

CREATE TRIGGER subject_trust_transition_contributions_keep_history
BEFORE UPDATE OR DELETE ON trust.subject_trust_transition_contributions
FOR EACH ROW EXECUTE FUNCTION trust.prevent_subject_trust_history_rewrite();

CREATE TRIGGER trust_transition_events_keep_history
BEFORE UPDATE OR DELETE ON trust.trust_transition_events
FOR EACH ROW EXECUTE FUNCTION trust.prevent_subject_trust_history_rewrite();

CREATE FUNCTION trust.record_subject_trust_transition(
  p_tenant_id identity.tenant_id,
  p_subject_id identity.subject_id,
  p_transition_id trust.transition_id,
  p_event_id identity.event_id,
  p_correlation_id identity.correlation_id,
  p_causation_event_id identity.event_id,
  p_update_version bigint,
  p_previous_transition_id trust.transition_id,
  p_previous_score numeric,
  p_previous_band text,
  p_previous_recovery_streak integer,
  p_new_score numeric,
  p_new_band text,
  p_new_recovery_streak integer,
  p_weighted_score numeric,
  p_smoothed_score numeric,
  p_transition_kind text,
  p_observed_at timestamptz,
  p_evaluated_at timestamptz,
  p_model_version text,
  p_configuration_version integer,
  p_contributions jsonb,
  p_explanation_json text,
  p_explanation_hash_sha256 identity.sha256_digest,
  p_event_json text,
  p_event_sha256 identity.sha256_digest
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  transition_id trust.transition_id,
  event_id identity.event_id,
  update_version bigint,
  explanation_hash_sha256 identity.sha256_digest,
  event_sha256 identity.sha256_digest,
  recorded_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_recorded_at timestamptz := clock_timestamp();
  v_state trust.subject_trust_state_versions%ROWTYPE;
  v_configuration trust.trust_configurations%ROWTYPE;
  v_current trust.subject_trust_transition_current%ROWTYPE;
  v_previous trust.subject_trust_transitions%ROWTYPE;
  v_existing trust.subject_trust_transitions%ROWTYPE;
  v_explanation jsonb;
  v_event jsonb;
  v_matched_contributions integer;
  v_contribution_total numeric;
  v_previous_rank integer;
  v_new_rank integer;
BEGIN
  IF p_update_version < 1
     OR p_previous_score NOT BETWEEN 0 AND 100
     OR p_new_score NOT BETWEEN 0 AND 100
     OR p_weighted_score NOT BETWEEN 0 AND 100
     OR p_smoothed_score NOT BETWEEN 0 AND 100
     OR p_previous_band NOT IN ('uninitialized', 'low', 'medium', 'high')
     OR p_new_band NOT IN ('low', 'medium', 'high')
     OR p_previous_recovery_streak NOT BETWEEN 0 AND 1
     OR p_new_recovery_streak NOT BETWEEN 0 AND 1
     OR p_transition_kind NOT IN ('held', 'deteriorated', 'recovered', 'critical-override')
     OR p_model_version !~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
     OR p_configuration_version < 1
     OR p_observed_at > p_evaluated_at
     OR p_evaluated_at > v_recorded_at + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust transition input is invalid.';
  END IF;

  IF p_contributions IS NULL
     OR jsonb_typeof(p_contributions) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_contributions) <> 5
     OR EXISTS (
       SELECT 1
       FROM jsonb_array_elements(p_contributions) AS entry(item)
       WHERE jsonb_typeof(entry.item) IS DISTINCT FROM 'object'
          OR entry.item - ARRAY[
            'componentId', 'normalizedValue', 'weight', 'weightedContribution',
            'evidenceId', 'sourceEventId'
          ]::text[] <> '{}'::jsonb
          OR NOT (
            entry.item ? 'componentId'
            AND entry.item ? 'normalizedValue'
            AND entry.item ? 'weight'
            AND entry.item ? 'weightedContribution'
            AND entry.item ? 'evidenceId'
            AND entry.item ? 'sourceEventId'
          )
          OR entry.item->>'componentId' NOT IN (
            'identity', 'device', 'behaviour', 'certificate', 'compliance'
          )
          OR jsonb_typeof(entry.item->'normalizedValue') IS DISTINCT FROM 'number'
          OR jsonb_typeof(entry.item->'weight') IS DISTINCT FROM 'number'
          OR jsonb_typeof(entry.item->'weightedContribution') IS DISTINCT FROM 'number'
          OR entry.item->>'evidenceId' !~ '^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
          OR entry.item->>'sourceEventId' !~ '^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     )
     OR (
       SELECT count(DISTINCT entry.item->>'componentId')
       FROM jsonb_array_elements(p_contributions) AS entry(item)
     ) <> 5
     OR (
       SELECT count(DISTINCT entry.item->>'evidenceId')
       FROM jsonb_array_elements(p_contributions) AS entry(item)
     ) <> 5
     OR (
       SELECT count(DISTINCT entry.item->>'sourceEventId')
       FROM jsonb_array_elements(p_contributions) AS entry(item)
     ) <> 5 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust transition contributions are invalid.';
  END IF;

  BEGIN
    v_explanation := p_explanation_json::jsonb;
    v_event := p_event_json::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust transition JSON is invalid.';
  END;
  IF jsonb_typeof(v_explanation) IS DISTINCT FROM 'object'
     OR jsonb_typeof(v_event) IS DISTINCT FROM 'object'
     OR encode(public.digest(convert_to(p_explanation_json, 'UTF8'), 'sha256'), 'hex')
        <> p_explanation_hash_sha256::text
     OR encode(public.digest(convert_to(p_event_json, 'UTF8'), 'sha256'), 'hex')
        <> p_event_sha256::text THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust transition digests are invalid.';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(p_tenant_id::text || ':' || p_subject_id::text, 0)
  );

  SELECT transition.* INTO v_existing
  FROM trust.subject_trust_transitions AS transition
  WHERE transition.tenant_id = p_tenant_id
    AND transition.transition_id = p_transition_id;
  IF FOUND THEN
    IF v_existing.subject_id <> p_subject_id
       OR v_existing.event_id <> p_event_id
       OR v_existing.update_version <> p_update_version
       OR v_existing.explanation_hash_sha256 <> p_explanation_hash_sha256
       OR NOT EXISTS (
         SELECT 1 FROM trust.trust_transition_events AS event
         WHERE event.tenant_id = p_tenant_id
           AND event.transition_id = p_transition_id
           AND event.event_sha256 = p_event_sha256
       ) THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Trust transition identity conflict.';
    END IF;
    RETURN QUERY SELECT v_existing.tenant_id, v_existing.subject_id,
      v_existing.transition_id, v_existing.event_id, v_existing.update_version,
      v_existing.explanation_hash_sha256, p_event_sha256, v_existing.recorded_at;
    RETURN;
  END IF;

  SELECT version.* INTO v_state
  FROM trust.subject_trust_state_versions AS version
  JOIN trust.subject_trust_current AS current_state
    ON current_state.tenant_id = version.tenant_id
   AND current_state.subject_id = version.subject_id
   AND current_state.update_version = version.update_version
  WHERE version.tenant_id = p_tenant_id
    AND version.subject_id = p_subject_id
    AND version.update_version = p_update_version
  FOR SHARE OF version, current_state;
  IF NOT FOUND
     OR v_state.model_version <> p_model_version
     OR v_state.configuration_version <> p_configuration_version
     OR v_state.observed_at <> p_observed_at THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Current trust state does not match the transition.';
  END IF;

  SELECT configuration.* INTO v_configuration
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = p_tenant_id
    AND configuration.configuration_version = p_configuration_version
    AND configuration.model_version = p_model_version
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust configuration does not match the transition.';
  END IF;

  WITH supplied AS (
    SELECT entry.item->>'componentId' AS component_id,
           (entry.item->>'normalizedValue')::numeric AS normalized_value,
           (entry.item->>'weight')::numeric AS weight,
           (entry.item->>'weightedContribution')::numeric AS weighted_contribution,
           (entry.item->>'evidenceId')::trust.evidence_id AS evidence_id,
           (entry.item->>'sourceEventId')::trust.evidence_event_id AS source_event_id
    FROM jsonb_array_elements(p_contributions) AS entry(item)
  )
  SELECT count(*), sum(supplied.weighted_contribution)
  INTO v_matched_contributions, v_contribution_total
  FROM supplied
  JOIN trust.subject_trust_state_evidence AS evidence
    ON evidence.tenant_id = p_tenant_id
   AND evidence.subject_id = p_subject_id
   AND evidence.update_version = p_update_version
   AND evidence.evidence_type::text = supplied.component_id
   AND evidence.evidence_id = supplied.evidence_id
   AND evidence.source_event_id = supplied.source_event_id
  WHERE supplied.normalized_value = CASE supplied.component_id
          WHEN 'identity' THEN v_state.identity_component
          WHEN 'device' THEN v_state.device_component
          WHEN 'behaviour' THEN v_state.behaviour_component
          WHEN 'certificate' THEN v_state.certificate_component
          WHEN 'compliance' THEN v_state.compliance_component
        END
    AND supplied.weight = CASE supplied.component_id
          WHEN 'identity' THEN v_configuration.identity_weight
          WHEN 'device' THEN v_configuration.device_weight
          WHEN 'behaviour' THEN v_configuration.behaviour_weight
          WHEN 'certificate' THEN v_configuration.certificate_weight
          WHEN 'compliance' THEN v_configuration.compliance_weight
        END
    AND supplied.weighted_contribution = round(supplied.normalized_value * supplied.weight, 6);
  IF v_matched_contributions <> 5 OR round(v_contribution_total, 2) <> p_weighted_score THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust transition contributions do not match durable state.';
  END IF;

  SELECT current_transition.* INTO v_current
  FROM trust.subject_trust_transition_current AS current_transition
  WHERE current_transition.tenant_id = p_tenant_id
    AND current_transition.subject_id = p_subject_id
  FOR UPDATE;
  IF NOT FOUND THEN
    IF p_previous_transition_id IS NOT NULL
       OR p_previous_band <> 'uninitialized'
       OR p_previous_score <> v_configuration.initial_score
       OR p_previous_recovery_streak <> 0 THEN
      RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Trust transition previous state conflict.';
    END IF;
  ELSE
    IF p_previous_transition_id IS DISTINCT FROM v_current.transition_id
       OR v_current.update_version >= p_update_version THEN
      RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Trust transition ordering conflict.';
    END IF;
    SELECT transition.* INTO STRICT v_previous
    FROM trust.subject_trust_transitions AS transition
    WHERE transition.tenant_id = p_tenant_id
      AND transition.transition_id = v_current.transition_id;
    IF v_previous.new_score <> p_previous_score
       OR v_previous.new_band <> p_previous_band
       OR v_previous.new_recovery_streak <> p_previous_recovery_streak THEN
      RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Trust transition previous state conflict.';
    END IF;
  END IF;

  v_previous_rank := CASE p_previous_band
    WHEN 'uninitialized' THEN 0 WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 END;
  v_new_rank := CASE p_new_band WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 END;
  IF (p_previous_band <> 'uninitialized' AND (
       (p_transition_kind = 'held' AND v_new_rank <> v_previous_rank)
       OR (p_transition_kind = 'deteriorated' AND v_new_rank >= v_previous_rank)
       OR (p_transition_kind = 'recovered' AND v_new_rank <> v_previous_rank + 1)
     ))
     OR (p_transition_kind = 'critical-override'
       AND (p_new_band <> 'low' OR p_new_score > p_previous_score)) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust transition state change is inconsistent.';
  END IF;

  IF v_explanation->>'transitionId' IS DISTINCT FROM p_transition_id::text
     OR v_explanation->>'tenantId' IS DISTINCT FROM p_tenant_id::text
     OR v_explanation->>'subjectId' IS DISTINCT FROM p_subject_id::text
     OR (v_explanation->>'updateVersion')::bigint IS DISTINCT FROM p_update_version
     OR v_explanation->>'modelVersion' IS DISTINCT FROM p_model_version
     OR (v_explanation->>'configurationVersion')::integer IS DISTINCT FROM p_configuration_version
     OR (v_explanation#>>'{previousState,score}')::numeric IS DISTINCT FROM p_previous_score
     OR v_explanation#>>'{previousState,band}' IS DISTINCT FROM p_previous_band
     OR (v_explanation#>>'{previousState,recoveryStreak}')::integer
        IS DISTINCT FROM p_previous_recovery_streak
     OR (v_explanation#>>'{newState,score}')::numeric IS DISTINCT FROM p_new_score
     OR v_explanation#>>'{newState,band}' IS DISTINCT FROM p_new_band
     OR (v_explanation#>>'{newState,recoveryStreak}')::integer
        IS DISTINCT FROM p_new_recovery_streak
     OR (v_explanation#>>'{weightedCalculation,score}')::numeric
        IS DISTINCT FROM p_weighted_score
     OR (v_explanation#>>'{temporalCalculation,score}')::numeric
        IS DISTINCT FROM p_smoothed_score
     OR v_explanation#>>'{transitionControl,transition}' IS DISTINCT FROM p_transition_kind
     OR v_explanation#>'{weightedCalculation,contributions}' IS DISTINCT FROM p_contributions
     OR jsonb_typeof(v_explanation->'evidenceReferences') IS DISTINCT FROM 'array'
     OR jsonb_array_length(v_explanation->'evidenceReferences') <> 5
     OR EXISTS (
       (SELECT reference.item->>'evidenceType', reference.item->>'evidenceId',
               reference.item->>'sourceEventId'
        FROM jsonb_array_elements(v_explanation->'evidenceReferences') AS reference(item))
       EXCEPT
       (SELECT entry.item->>'componentId', entry.item->>'evidenceId',
               entry.item->>'sourceEventId'
        FROM jsonb_array_elements(p_contributions) AS entry(item))
     )
     OR EXISTS (
       (SELECT entry.item->>'componentId', entry.item->>'evidenceId',
               entry.item->>'sourceEventId'
        FROM jsonb_array_elements(p_contributions) AS entry(item))
       EXCEPT
       (SELECT reference.item->>'evidenceType', reference.item->>'evidenceId',
               reference.item->>'sourceEventId'
        FROM jsonb_array_elements(v_explanation->'evidenceReferences') AS reference(item))
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust explanation does not match transition fields.';
  END IF;

  IF v_event->>'schemaVersion' IS DISTINCT FROM '1.0.0'
     OR v_event->>'eventType' IS DISTINCT FROM 'trust.updated.v1'
     OR v_event->>'eventId' IS DISTINCT FROM p_event_id::text
     OR v_event->>'tenantId' IS DISTINCT FROM p_tenant_id::text
     OR v_event->>'subjectId' IS DISTINCT FROM p_subject_id::text
     OR v_event->>'aggregateId' IS DISTINCT FROM p_transition_id::text
     OR v_event->>'correlationId' IS DISTINCT FROM p_correlation_id::text
     OR v_event->>'causationId' IS DISTINCT FROM p_causation_event_id::text
     OR v_event#>>'{payload,transitionId}' IS DISTINCT FROM p_transition_id::text
     OR (v_event#>>'{payload,previousScore}')::numeric IS DISTINCT FROM p_previous_score
     OR (v_event#>>'{payload,newScore}')::numeric IS DISTINCT FROM p_new_score
     OR (v_event#>>'{payload,previousBand}') IS DISTINCT FROM (CASE p_previous_band
          WHEN 'uninitialized' THEN 'uninitialized' WHEN 'low' THEN 'restricted'
          WHEN 'medium' THEN 'conditional' WHEN 'high' THEN 'trusted' END)
     OR (v_event#>>'{payload,newBand}') IS DISTINCT FROM (CASE p_new_band
          WHEN 'low' THEN 'restricted' WHEN 'medium' THEN 'conditional'
          WHEN 'high' THEN 'trusted' END)
     OR v_event#>>'{payload,modelVersion}' IS DISTINCT FROM p_model_version
     OR (v_event#>>'{payload,configurationVersion}')::integer IS DISTINCT FROM p_configuration_version
     OR v_event#>>'{payload,explanationHashSha256}' IS DISTINCT FROM p_explanation_hash_sha256::text
     OR jsonb_typeof(v_event#>'{payload,evidenceIds}') IS DISTINCT FROM 'array'
     OR jsonb_array_length(v_event#>'{payload,evidenceIds}') <> 5
     OR EXISTS (
       (SELECT jsonb_array_elements_text(v_event#>'{payload,evidenceIds}'))
       EXCEPT
       (SELECT entry.item->>'evidenceId'
        FROM jsonb_array_elements(p_contributions) AS entry(item))
     )
     OR EXISTS (
       (SELECT entry.item->>'evidenceId'
        FROM jsonb_array_elements(p_contributions) AS entry(item))
       EXCEPT
       (SELECT jsonb_array_elements_text(v_event#>'{payload,evidenceIds}'))
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust event does not match transition fields.';
  END IF;

  INSERT INTO trust.subject_trust_transitions (
    tenant_id, subject_id, transition_id, event_id, update_version,
    previous_transition_id, previous_score, previous_band, previous_recovery_streak,
    new_score, new_band, new_recovery_streak, weighted_score, smoothed_score,
    transition_kind, model_version, configuration_version, observed_at, evaluated_at,
    explanation_json, explanation_hash_sha256, recorded_at
  ) VALUES (
    p_tenant_id, p_subject_id, p_transition_id, p_event_id, p_update_version,
    p_previous_transition_id, p_previous_score, p_previous_band, p_previous_recovery_streak,
    p_new_score, p_new_band, p_new_recovery_streak, p_weighted_score, p_smoothed_score,
    p_transition_kind, p_model_version, p_configuration_version, p_observed_at, p_evaluated_at,
    p_explanation_json, p_explanation_hash_sha256, v_recorded_at
  );

  INSERT INTO trust.subject_trust_transition_contributions (
    tenant_id, subject_id, transition_id, update_version, component_id,
    normalized_value, weight, weighted_contribution, evidence_id, source_event_id
  )
  SELECT p_tenant_id, p_subject_id, p_transition_id, p_update_version,
         (entry.item->>'componentId')::trust.evidence_type,
         (entry.item->>'normalizedValue')::numeric,
         (entry.item->>'weight')::numeric,
         (entry.item->>'weightedContribution')::numeric,
         (entry.item->>'evidenceId')::trust.evidence_id,
         (entry.item->>'sourceEventId')::trust.evidence_event_id
  FROM jsonb_array_elements(p_contributions) AS entry(item);

  INSERT INTO trust.trust_transition_events (
    tenant_id, subject_id, event_id, transition_id, correlation_id,
    causation_event_id, event_json, event_sha256, recorded_at
  ) VALUES (
    p_tenant_id, p_subject_id, p_event_id, p_transition_id, p_correlation_id,
    p_causation_event_id, p_event_json, p_event_sha256, v_recorded_at
  );

  INSERT INTO trust.subject_trust_transition_current (
    tenant_id, subject_id, transition_id, update_version, updated_at
  ) VALUES (
    p_tenant_id, p_subject_id, p_transition_id, p_update_version, v_recorded_at
  )
  ON CONFLICT ON CONSTRAINT subject_trust_transition_current_pk DO UPDATE
  SET transition_id = EXCLUDED.transition_id,
      update_version = EXCLUDED.update_version,
      updated_at = EXCLUDED.updated_at;

  RETURN QUERY SELECT p_tenant_id, p_subject_id, p_transition_id, p_event_id,
    p_update_version, p_explanation_hash_sha256, p_event_sha256, v_recorded_at;
END
$function$;

ALTER TABLE trust.subject_trust_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_transitions FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_transition_contributions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_transition_contributions FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_transition_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_transition_current FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.trust_transition_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.trust_transition_events FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE trust.subject_trust_transitions
  FROM PUBLIC, tenant_trust_app, tenant_trust_trust_engine;
REVOKE ALL ON TABLE trust.subject_trust_transition_contributions
  FROM PUBLIC, tenant_trust_app, tenant_trust_trust_engine;
REVOKE ALL ON TABLE trust.subject_trust_transition_current
  FROM PUBLIC, tenant_trust_app, tenant_trust_trust_engine;
REVOKE ALL ON TABLE trust.trust_transition_events
  FROM PUBLIC, tenant_trust_app, tenant_trust_trust_engine;
REVOKE ALL ON FUNCTION trust.record_subject_trust_transition(
  identity.tenant_id, identity.subject_id, trust.transition_id, identity.event_id,
  identity.correlation_id, identity.event_id, bigint, trust.transition_id,
  numeric, text, integer, numeric, text, integer, numeric, numeric, text,
  timestamptz, timestamptz, text, integer, jsonb, text, identity.sha256_digest,
  text, identity.sha256_digest
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust.record_subject_trust_transition(
  identity.tenant_id, identity.subject_id, trust.transition_id, identity.event_id,
  identity.correlation_id, identity.event_id, bigint, trust.transition_id,
  numeric, text, integer, numeric, text, integer, numeric, numeric, text,
  timestamptz, timestamptz, text, integer, jsonb, text, identity.sha256_digest,
  text, identity.sha256_digest
) TO tenant_trust_trust_engine;

COMMENT ON DOMAIN trust.transition_id IS
  'Opaque trn_UUID identity for one immutable trust transition';
COMMENT ON TABLE trust.subject_trust_transitions IS
  'Append-only prior/new trust state and canonical explanation for one state version';
COMMENT ON TABLE trust.subject_trust_transition_contributions IS
  'Five evidence-bound weighted component contributions for one trust transition';
COMMENT ON TABLE trust.subject_trust_transition_current IS
  'Current durable trust transition pointer per tenant and subject';
COMMENT ON TABLE trust.trust_transition_events IS
  'Append-only canonical trust.updated.v1 event bytes linked to a durable transition';
COMMENT ON FUNCTION trust.record_subject_trust_transition(
  identity.tenant_id, identity.subject_id, trust.transition_id, identity.event_id,
  identity.correlation_id, identity.event_id, bigint, trust.transition_id,
  numeric, text, integer, numeric, text, integer, numeric, numeric, text,
  timestamptz, timestamptz, text, integer, jsonb, text, identity.sha256_digest,
  text, identity.sha256_digest
) IS
  'Atomically validates and records one ordered trust explanation, its five evidence contributions, event and current pointer';
