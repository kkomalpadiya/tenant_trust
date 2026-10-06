DO $create_trust_engine_role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_trust_engine') THEN
    CREATE ROLE tenant_trust_trust_engine;
  END IF;
END
$create_trust_engine_role$;

ALTER ROLE tenant_trust_trust_engine
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;

CREATE TABLE trust.subject_trust_state_versions (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  update_version bigint NOT NULL,
  model_version text NOT NULL,
  configuration_version integer NOT NULL,
  identity_component numeric(5,2) NOT NULL,
  device_component numeric(5,2) NOT NULL,
  behaviour_component numeric(5,2) NOT NULL,
  certificate_component numeric(5,2) NOT NULL,
  compliance_component numeric(5,2) NOT NULL,
  observed_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT subject_trust_state_versions_pk
    PRIMARY KEY (tenant_id, subject_id, update_version),
  CONSTRAINT subject_trust_state_versions_membership_fk
    FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT subject_trust_state_versions_configuration_fk
    FOREIGN KEY (tenant_id, configuration_version)
    REFERENCES trust.trust_configurations (tenant_id, configuration_version) ON DELETE RESTRICT,
  CONSTRAINT subject_trust_state_versions_update_positive CHECK (update_version > 0),
  CONSTRAINT subject_trust_state_versions_model_format CHECK (
    model_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
  ),
  CONSTRAINT subject_trust_state_versions_component_ranges CHECK (
    identity_component BETWEEN 0 AND 100
    AND device_component BETWEEN 0 AND 100
    AND behaviour_component BETWEEN 0 AND 100
    AND certificate_component BETWEEN 0 AND 100
    AND compliance_component BETWEEN 0 AND 100
  ),
  CONSTRAINT subject_trust_state_versions_time_order CHECK (observed_at <= recorded_at)
);

CREATE INDEX subject_trust_state_versions_observation_lookup
  ON trust.subject_trust_state_versions (tenant_id, subject_id, observed_at DESC, update_version DESC);

CREATE TABLE trust.subject_trust_state_evidence (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  update_version bigint NOT NULL,
  evidence_type trust.evidence_type NOT NULL,
  evidence_id trust.evidence_id NOT NULL,
  source_event_id trust.evidence_event_id NOT NULL,
  CONSTRAINT subject_trust_state_evidence_pk
    PRIMARY KEY (tenant_id, subject_id, update_version, evidence_type),
  CONSTRAINT subject_trust_state_evidence_version_fk
    FOREIGN KEY (tenant_id, subject_id, update_version)
    REFERENCES trust.subject_trust_state_versions (tenant_id, subject_id, update_version)
    ON DELETE RESTRICT,
  CONSTRAINT subject_trust_state_evidence_outbox_event_fk
    FOREIGN KEY (tenant_id, source_event_id)
    REFERENCES trust.evidence_event_outbox (tenant_id, source_event_id) ON DELETE RESTRICT,
  CONSTRAINT subject_trust_state_evidence_outbox_evidence_fk
    FOREIGN KEY (tenant_id, evidence_id)
    REFERENCES trust.evidence_event_outbox (tenant_id, evidence_id) ON DELETE RESTRICT,
  CONSTRAINT subject_trust_state_evidence_id_unique
    UNIQUE (tenant_id, subject_id, update_version, evidence_id),
  CONSTRAINT subject_trust_state_source_event_unique
    UNIQUE (tenant_id, subject_id, update_version, source_event_id)
);

CREATE INDEX subject_trust_state_evidence_reverse_lookup
  ON trust.subject_trust_state_evidence (tenant_id, evidence_id, subject_id, update_version);

CREATE TABLE trust.subject_trust_current (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  update_version bigint NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT subject_trust_current_pk PRIMARY KEY (tenant_id, subject_id),
  CONSTRAINT subject_trust_current_membership_fk
    FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT subject_trust_current_version_fk
    FOREIGN KEY (tenant_id, subject_id, update_version)
    REFERENCES trust.subject_trust_state_versions (tenant_id, subject_id, update_version)
    ON DELETE RESTRICT,
  CONSTRAINT subject_trust_current_update_positive CHECK (update_version > 0)
);

CREATE FUNCTION trust.prevent_subject_trust_history_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Subject trust-state history is append-only.';
END
$function$;

CREATE TRIGGER subject_trust_state_versions_keep_history
BEFORE UPDATE OR DELETE ON trust.subject_trust_state_versions
FOR EACH ROW EXECUTE FUNCTION trust.prevent_subject_trust_history_rewrite();

CREATE TRIGGER subject_trust_state_evidence_keep_history
BEFORE UPDATE OR DELETE ON trust.subject_trust_state_evidence
FOR EACH ROW EXECUTE FUNCTION trust.prevent_subject_trust_history_rewrite();

CREATE FUNCTION trust.validate_subject_trust_evidence_reference()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM trust.evidence_event_outbox AS outbox
    JOIN trust.evidence_ingestion_receipts AS receipt
      ON receipt.tenant_id = outbox.tenant_id
     AND receipt.event_id = outbox.source_event_id
    WHERE outbox.tenant_id = NEW.tenant_id
      AND outbox.source_event_id = NEW.source_event_id
      AND outbox.evidence_id = NEW.evidence_id
      AND receipt.subject_id = NEW.subject_id
      AND receipt.evidence_type = NEW.evidence_type
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Trust-state evidence reference is not tenant and subject bound.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER subject_trust_state_evidence_validate_reference
BEFORE INSERT ON trust.subject_trust_state_evidence
FOR EACH ROW EXECUTE FUNCTION trust.validate_subject_trust_evidence_reference();

CREATE FUNCTION trust.store_subject_trust_state(
  p_tenant_id identity.tenant_id,
  p_subject_id identity.subject_id,
  p_expected_previous_version bigint,
  p_model_version text,
  p_configuration_version integer,
  p_identity_component numeric,
  p_device_component numeric,
  p_behaviour_component numeric,
  p_certificate_component numeric,
  p_compliance_component numeric,
  p_observed_at timestamptz,
  p_evidence_references jsonb
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  update_version bigint,
  model_version text,
  configuration_version integer,
  observed_at timestamptz,
  recorded_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_current_version bigint;
  v_next_version bigint;
  v_recorded_at timestamptz := clock_timestamp();
  v_matched_references integer;
BEGIN
  IF p_expected_previous_version < 0
     OR p_configuration_version < 1
     OR p_model_version !~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
     OR p_identity_component NOT BETWEEN 0 AND 100
     OR p_device_component NOT BETWEEN 0 AND 100
     OR p_behaviour_component NOT BETWEEN 0 AND 100
     OR p_certificate_component NOT BETWEEN 0 AND 100
     OR p_compliance_component NOT BETWEEN 0 AND 100
     OR p_observed_at > v_recorded_at + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Subject trust-state input is invalid.';
  END IF;

  IF p_evidence_references IS NULL
     OR jsonb_typeof(p_evidence_references) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Subject trust-state evidence references are invalid.';
  END IF;
  IF jsonb_array_length(p_evidence_references) <> 5 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Subject trust-state evidence references are incomplete.';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(p_evidence_references) AS entry(item)
    WHERE jsonb_typeof(entry.item) IS DISTINCT FROM 'object'
       OR NOT (entry.item ? 'evidenceId' AND entry.item ? 'sourceEventId' AND entry.item ? 'evidenceType')
       OR entry.item - ARRAY['evidenceId', 'sourceEventId', 'evidenceType']::text[] <> '{}'::jsonb
       OR entry.item->>'evidenceId' !~ '^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR entry.item->>'sourceEventId' !~ '^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR entry.item->>'evidenceType' NOT IN ('identity', 'device', 'behaviour', 'certificate', 'compliance')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Subject trust-state evidence references are invalid.';
  END IF;
  IF (
    SELECT count(DISTINCT entry.item->>'evidenceType')
    FROM jsonb_array_elements(p_evidence_references) AS entry(item)
  ) <> 5 OR (
    SELECT count(DISTINCT entry.item->>'evidenceId')
    FROM jsonb_array_elements(p_evidence_references) AS entry(item)
  ) <> 5 OR (
    SELECT count(DISTINCT entry.item->>'sourceEventId')
    FROM jsonb_array_elements(p_evidence_references) AS entry(item)
  ) <> 5 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Subject trust-state evidence references must be unique by component.';
  END IF;

  PERFORM 1
  FROM identity.tenants AS tenant
  JOIN identity.tenant_memberships AS membership
    ON membership.tenant_id = tenant.tenant_id
   AND membership.subject_id = p_subject_id
  JOIN identity.subjects AS subject ON subject.subject_id = membership.subject_id
  JOIN trust.trust_configurations AS configuration
    ON configuration.tenant_id = tenant.tenant_id
   AND configuration.configuration_version = p_configuration_version
  WHERE tenant.tenant_id = p_tenant_id
    AND tenant.state = 'active'
    AND subject.state = 'active'
    AND membership.state = 'active'
    AND configuration.state = 'active'
    AND configuration.model_version = p_model_version
  FOR SHARE OF tenant, membership, subject, configuration;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Subject trust-state authority is unavailable.';
  END IF;

  WITH supplied AS (
    SELECT entry.item->>'evidenceId' AS evidence_id,
           entry.item->>'sourceEventId' AS source_event_id,
           entry.item->>'evidenceType' AS evidence_type
    FROM jsonb_array_elements(p_evidence_references) AS entry(item)
  )
  SELECT count(*) INTO v_matched_references
  FROM supplied
  JOIN trust.evidence_event_outbox AS outbox
    ON outbox.tenant_id = p_tenant_id
   AND outbox.evidence_id = supplied.evidence_id::trust.evidence_id
   AND outbox.source_event_id = supplied.source_event_id::trust.evidence_event_id
  JOIN trust.evidence_ingestion_receipts AS receipt
    ON receipt.tenant_id = outbox.tenant_id
   AND receipt.event_id = outbox.source_event_id
   AND receipt.subject_id = p_subject_id
   AND receipt.evidence_type::text = supplied.evidence_type;

  IF v_matched_references <> 5 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Subject trust-state evidence is not tenant and subject bound.';
  END IF;

  SELECT current_state.update_version INTO v_current_version
  FROM trust.subject_trust_current AS current_state
  WHERE current_state.tenant_id = p_tenant_id
    AND current_state.subject_id = p_subject_id
  FOR UPDATE;

  IF NOT FOUND THEN
    IF p_expected_previous_version <> 0 THEN
      RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Subject trust-state version conflict.';
    END IF;
    v_next_version := 1;
  ELSE
    IF v_current_version <> p_expected_previous_version THEN
      RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Subject trust-state version conflict.';
    END IF;
    v_next_version := v_current_version + 1;
  END IF;

  INSERT INTO trust.subject_trust_state_versions (
    tenant_id, subject_id, update_version, model_version, configuration_version,
    identity_component, device_component, behaviour_component,
    certificate_component, compliance_component, observed_at, recorded_at
  ) VALUES (
    p_tenant_id, p_subject_id, v_next_version, p_model_version, p_configuration_version,
    p_identity_component, p_device_component, p_behaviour_component,
    p_certificate_component, p_compliance_component, p_observed_at, v_recorded_at
  );

  INSERT INTO trust.subject_trust_state_evidence (
    tenant_id, subject_id, update_version, evidence_type, evidence_id, source_event_id
  )
  SELECT p_tenant_id, p_subject_id, v_next_version,
         (entry.item->>'evidenceType')::trust.evidence_type,
         (entry.item->>'evidenceId')::trust.evidence_id,
         (entry.item->>'sourceEventId')::trust.evidence_event_id
  FROM jsonb_array_elements(p_evidence_references) AS entry(item);

  INSERT INTO trust.subject_trust_current (
    tenant_id, subject_id, update_version, updated_at
  ) VALUES (
    p_tenant_id, p_subject_id, v_next_version, v_recorded_at
  )
  ON CONFLICT ON CONSTRAINT subject_trust_current_pk DO UPDATE
  SET update_version = EXCLUDED.update_version,
      updated_at = EXCLUDED.updated_at;

  RETURN QUERY SELECT p_tenant_id, p_subject_id, v_next_version,
    p_model_version, p_configuration_version, p_observed_at, v_recorded_at;
END
$function$;

CREATE FUNCTION trust.get_subject_trust_state_version(
  p_tenant_id identity.tenant_id,
  p_subject_id identity.subject_id,
  p_update_version bigint
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  update_version bigint,
  model_version text,
  configuration_version integer,
  identity_component numeric,
  device_component numeric,
  behaviour_component numeric,
  certificate_component numeric,
  compliance_component numeric,
  observed_at timestamptz,
  recorded_at timestamptz,
  evidence_references jsonb
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
  SELECT version.tenant_id, version.subject_id, version.update_version,
         version.model_version, version.configuration_version,
         version.identity_component, version.device_component,
         version.behaviour_component, version.certificate_component,
         version.compliance_component, version.observed_at, version.recorded_at,
         jsonb_agg(
           jsonb_build_object(
             'evidenceId', evidence.evidence_id,
             'sourceEventId', evidence.source_event_id,
             'evidenceType', evidence.evidence_type
           ) ORDER BY evidence.evidence_type
         ) AS evidence_references
  FROM trust.subject_trust_state_versions AS version
  JOIN trust.subject_trust_state_evidence AS evidence
    ON evidence.tenant_id = version.tenant_id
   AND evidence.subject_id = version.subject_id
   AND evidence.update_version = version.update_version
  WHERE version.tenant_id = p_tenant_id
    AND version.subject_id = p_subject_id
    AND version.update_version = p_update_version
  GROUP BY version.tenant_id, version.subject_id, version.update_version;
$function$;

CREATE FUNCTION trust.get_current_subject_trust_state(
  p_tenant_id identity.tenant_id,
  p_subject_id identity.subject_id
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  update_version bigint,
  model_version text,
  configuration_version integer,
  identity_component numeric,
  device_component numeric,
  behaviour_component numeric,
  certificate_component numeric,
  compliance_component numeric,
  observed_at timestamptz,
  recorded_at timestamptz,
  evidence_references jsonb
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
  SELECT stored.*
  FROM trust.subject_trust_current AS current_state
  CROSS JOIN LATERAL trust.get_subject_trust_state_version(
    current_state.tenant_id, current_state.subject_id, current_state.update_version
  ) AS stored
  WHERE current_state.tenant_id = p_tenant_id
    AND current_state.subject_id = p_subject_id;
$function$;

ALTER TABLE trust.subject_trust_state_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_state_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_state_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_state_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.subject_trust_current FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE trust.subject_trust_state_versions FROM PUBLIC, tenant_trust_app, tenant_trust_trust_engine;
REVOKE ALL ON TABLE trust.subject_trust_state_evidence FROM PUBLIC, tenant_trust_app, tenant_trust_trust_engine;
REVOKE ALL ON TABLE trust.subject_trust_current FROM PUBLIC, tenant_trust_app, tenant_trust_trust_engine;
REVOKE ALL ON FUNCTION trust.prevent_subject_trust_history_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.validate_subject_trust_evidence_reference() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.store_subject_trust_state(
  identity.tenant_id, identity.subject_id, bigint, text, integer,
  numeric, numeric, numeric, numeric, numeric, timestamptz, jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.get_subject_trust_state_version(
  identity.tenant_id, identity.subject_id, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.get_current_subject_trust_state(
  identity.tenant_id, identity.subject_id
) FROM PUBLIC;

GRANT USAGE ON SCHEMA trust TO tenant_trust_trust_engine;
GRANT EXECUTE ON FUNCTION trust.store_subject_trust_state(
  identity.tenant_id, identity.subject_id, bigint, text, integer,
  numeric, numeric, numeric, numeric, numeric, timestamptz, jsonb
) TO tenant_trust_trust_engine;
GRANT EXECUTE ON FUNCTION trust.get_subject_trust_state_version(
  identity.tenant_id, identity.subject_id, bigint
) TO tenant_trust_trust_engine;
GRANT EXECUTE ON FUNCTION trust.get_current_subject_trust_state(
  identity.tenant_id, identity.subject_id
) TO tenant_trust_trust_engine;

COMMENT ON TABLE trust.subject_trust_state_versions IS
  'Append-only tenant and subject scoped normalized trust-component snapshots';
COMMENT ON TABLE trust.subject_trust_state_evidence IS
  'One accepted same-subject evidence reference for each component in a trust-state version';
COMMENT ON TABLE trust.subject_trust_current IS
  'Current trust-state version pointer per tenant and subject; values remain in append-only history';
COMMENT ON FUNCTION trust.store_subject_trust_state(
  identity.tenant_id, identity.subject_id, bigint, text, integer,
  numeric, numeric, numeric, numeric, numeric, timestamptz, jsonb
) IS 'Atomically appends one complete normalized trust-state version and advances its current pointer';
