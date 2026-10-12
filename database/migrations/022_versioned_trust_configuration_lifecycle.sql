CREATE TYPE trust.configuration_event_type AS ENUM (
  'draft_created',
  'activated',
  'rollback_activated'
);

ALTER TABLE trust.trust_configurations
  DROP CONSTRAINT trust_configurations_model_version_format,
  DROP CONSTRAINT trust_configurations_smoothing_range,
  DROP CONSTRAINT trust_configurations_source_influence_range,
  ADD CONSTRAINT trust_configurations_model_version_format CHECK (
    model_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
  ),
  ADD CONSTRAINT trust_configurations_smoothing_range CHECK (
    smoothing_alpha > 0 AND smoothing_alpha <= 1
  ),
  ADD CONSTRAINT trust_configurations_source_influence_range CHECK (
    maximum_source_influence > 0 AND maximum_source_influence <= 1
  );

CREATE TABLE trust.trust_configuration_events (
  tenant_id identity.tenant_id NOT NULL,
  event_sequence bigint GENERATED ALWAYS AS IDENTITY,
  event_type trust.configuration_event_type NOT NULL,
  configuration_version integer NOT NULL,
  previous_active_configuration_version integer,
  rollback_target_configuration_version integer,
  actor_subject_id identity.subject_id NOT NULL,
  reason_code text NOT NULL,
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT trust_configuration_events_pk PRIMARY KEY (tenant_id, event_sequence),
  CONSTRAINT trust_configuration_events_configuration_fk
    FOREIGN KEY (tenant_id, configuration_version)
    REFERENCES trust.trust_configurations (tenant_id, configuration_version) ON DELETE RESTRICT,
  CONSTRAINT trust_configuration_events_previous_fk
    FOREIGN KEY (tenant_id, previous_active_configuration_version)
    REFERENCES trust.trust_configurations (tenant_id, configuration_version) ON DELETE RESTRICT,
  CONSTRAINT trust_configuration_events_rollback_target_fk
    FOREIGN KEY (tenant_id, rollback_target_configuration_version)
    REFERENCES trust.trust_configurations (tenant_id, configuration_version) ON DELETE RESTRICT,
  CONSTRAINT trust_configuration_events_actor_fk
    FOREIGN KEY (tenant_id, actor_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT trust_configuration_events_reason_format CHECK (
    reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT trust_configuration_events_version_positive CHECK (
    configuration_version > 0
    AND (
      previous_active_configuration_version IS NULL
      OR previous_active_configuration_version > 0
    )
    AND (
      rollback_target_configuration_version IS NULL
      OR rollback_target_configuration_version > 0
    )
  ),
  CONSTRAINT trust_configuration_events_shape CHECK (
    (
      event_type = 'draft_created'
      AND rollback_target_configuration_version IS NULL
    )
    OR (
      event_type = 'activated'
      AND rollback_target_configuration_version IS NULL
    )
    OR (
      event_type = 'rollback_activated'
      AND previous_active_configuration_version IS NOT NULL
      AND rollback_target_configuration_version IS NOT NULL
      AND rollback_target_configuration_version <> configuration_version
    )
  )
);

CREATE INDEX trust_configuration_events_history_lookup
  ON trust.trust_configuration_events (tenant_id, configuration_version, event_sequence DESC);

CREATE FUNCTION trust.prevent_trust_configuration_history_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '23514',
    MESSAGE = 'Trust configuration history is append-only.';
END
$function$;

CREATE TRIGGER trust_configurations_prevent_delete
BEFORE DELETE ON trust.trust_configurations
FOR EACH ROW EXECUTE FUNCTION trust.prevent_trust_configuration_history_rewrite();

CREATE TRIGGER trust_configuration_events_keep_history
BEFORE UPDATE OR DELETE ON trust.trust_configuration_events
FOR EACH ROW EXECUTE FUNCTION trust.prevent_trust_configuration_history_rewrite();

ALTER TABLE trust.trust_configuration_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.trust_configuration_events FORCE ROW LEVEL SECURITY;

CREATE POLICY trust_configuration_events_current_actor_select
  ON trust.trust_configuration_events FOR SELECT TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_active());

CREATE FUNCTION trust.create_trust_configuration_draft(
  p_model_version text,
  p_initial_score numeric,
  p_smoothing_alpha numeric,
  p_maximum_source_influence numeric,
  p_stale_after_seconds integer,
  p_identity_weight numeric,
  p_device_weight numeric,
  p_behaviour_weight numeric,
  p_certificate_weight numeric,
  p_compliance_weight numeric,
  p_reason_code text,
  p_occurred_at timestamptz
)
RETURNS trust.trust_configurations
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_actor_subject_id identity.subject_id := identity.current_subject_id();
  v_now timestamptz := clock_timestamp();
  v_configuration trust.trust_configurations%ROWTYPE;
  v_previous_active_version integer;
  v_next_version integer;
BEGIN
  IF v_tenant_id IS NULL
     OR v_actor_subject_id IS NULL
     OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust configuration change denied.';
  END IF;
  IF p_occurred_at IS NULL
     OR p_occurred_at > v_now + interval '2 seconds'
     OR p_occurred_at < v_now - interval '5 minutes'
     OR p_reason_code IS NULL
     OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_model_version IS NULL
     OR p_model_version !~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
     OR p_initial_score IS NULL OR p_initial_score NOT BETWEEN 0 AND 100
     OR p_smoothing_alpha IS NULL OR p_smoothing_alpha <= 0 OR p_smoothing_alpha > 1
     OR p_maximum_source_influence IS NULL
     OR p_maximum_source_influence <= 0 OR p_maximum_source_influence > 1
     OR p_stale_after_seconds IS NULL OR p_stale_after_seconds NOT BETWEEN 1 AND 2592000
     OR p_identity_weight IS NULL OR p_identity_weight NOT BETWEEN 0 AND 1
     OR p_device_weight IS NULL OR p_device_weight NOT BETWEEN 0 AND 1
     OR p_behaviour_weight IS NULL OR p_behaviour_weight NOT BETWEEN 0 AND 1
     OR p_certificate_weight IS NULL OR p_certificate_weight NOT BETWEEN 0 AND 1
     OR p_compliance_weight IS NULL OR p_compliance_weight NOT BETWEEN 0 AND 1
     OR p_identity_weight + p_device_weight + p_behaviour_weight
       + p_certificate_weight + p_compliance_weight <> 1.0000 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust configuration input is invalid.';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 0));
  PERFORM 1 FROM identity.tenants AS tenant
  WHERE tenant.tenant_id = v_tenant_id AND tenant.state = 'active'
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust configuration change denied.';
  END IF;

  SELECT configuration.configuration_version
  INTO v_previous_active_version
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = v_tenant_id AND configuration.state = 'active'
  FOR SHARE;

  SELECT COALESCE(MAX(configuration.configuration_version), 0) + 1
  INTO v_next_version
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = v_tenant_id;

  INSERT INTO trust.trust_configurations (
    tenant_id, configuration_version, model_version, state, initial_score,
    smoothing_alpha, maximum_source_influence, stale_after_seconds,
    identity_weight, device_weight, behaviour_weight, certificate_weight,
    compliance_weight, created_by_subject_id, created_at, updated_at
  ) VALUES (
    v_tenant_id, v_next_version, p_model_version, 'draft', p_initial_score,
    p_smoothing_alpha, p_maximum_source_influence, p_stale_after_seconds,
    p_identity_weight, p_device_weight, p_behaviour_weight, p_certificate_weight,
    p_compliance_weight, v_actor_subject_id, p_occurred_at, GREATEST(v_now, p_occurred_at)
  )
  RETURNING * INTO v_configuration;

  INSERT INTO trust.trust_configuration_events (
    tenant_id, event_type, configuration_version,
    previous_active_configuration_version, actor_subject_id,
    reason_code, occurred_at
  ) VALUES (
    v_tenant_id, 'draft_created', v_next_version,
    v_previous_active_version, v_actor_subject_id,
    p_reason_code, p_occurred_at
  );

  RETURN v_configuration;
END
$function$;

CREATE FUNCTION trust.activate_trust_configuration(
  p_configuration_version integer,
  p_reason_code text,
  p_occurred_at timestamptz
)
RETURNS trust.trust_configurations
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_actor_subject_id identity.subject_id := identity.current_subject_id();
  v_now timestamptz := clock_timestamp();
  v_target trust.trust_configurations%ROWTYPE;
  v_previous trust.trust_configurations%ROWTYPE;
BEGIN
  IF v_tenant_id IS NULL
     OR v_actor_subject_id IS NULL
     OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust configuration activation denied.';
  END IF;
  IF p_configuration_version IS NULL OR p_configuration_version < 1
     OR p_occurred_at IS NULL
     OR p_occurred_at > v_now + interval '2 seconds'
     OR p_occurred_at < v_now - interval '5 minutes'
     OR p_reason_code IS NULL
     OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust configuration activation input is invalid.';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 0));
  SELECT * INTO v_target
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = v_tenant_id
    AND configuration.configuration_version = p_configuration_version
  FOR UPDATE;

  IF NOT FOUND OR v_target.state <> 'draft' OR p_occurred_at < v_target.created_at THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust configuration activation denied.';
  END IF;

  SELECT * INTO v_previous
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = v_tenant_id AND configuration.state = 'active'
  FOR UPDATE;

  IF v_previous.configuration_version IS NOT NULL THEN
    IF p_occurred_at < v_previous.activated_at THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust configuration activation time is invalid.';
    END IF;
    UPDATE trust.trust_configurations
    SET state = 'superseded',
        superseded_at = p_occurred_at,
        updated_at = GREATEST(v_now, p_occurred_at)
    WHERE tenant_id = v_tenant_id
      AND configuration_version = v_previous.configuration_version;
  END IF;

  UPDATE trust.trust_configurations
  SET state = 'active',
      activated_at = p_occurred_at,
      superseded_at = NULL,
      updated_at = GREATEST(v_now, p_occurred_at)
  WHERE tenant_id = v_tenant_id AND configuration_version = p_configuration_version
  RETURNING * INTO v_target;

  INSERT INTO trust.trust_configuration_events (
    tenant_id, event_type, configuration_version,
    previous_active_configuration_version, actor_subject_id,
    reason_code, occurred_at
  ) VALUES (
    v_tenant_id, 'activated', p_configuration_version,
    v_previous.configuration_version, v_actor_subject_id,
    p_reason_code, p_occurred_at
  );

  RETURN v_target;
END
$function$;

CREATE FUNCTION trust.rollback_trust_configuration(
  p_target_configuration_version integer,
  p_reason_code text,
  p_occurred_at timestamptz
)
RETURNS trust.trust_configurations
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_actor_subject_id identity.subject_id := identity.current_subject_id();
  v_now timestamptz := clock_timestamp();
  v_target trust.trust_configurations%ROWTYPE;
  v_previous trust.trust_configurations%ROWTYPE;
  v_restored trust.trust_configurations%ROWTYPE;
  v_next_version integer;
BEGIN
  IF v_tenant_id IS NULL
     OR v_actor_subject_id IS NULL
     OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust configuration rollback denied.';
  END IF;
  IF p_target_configuration_version IS NULL OR p_target_configuration_version < 1
     OR p_occurred_at IS NULL
     OR p_occurred_at > v_now + interval '2 seconds'
     OR p_occurred_at < v_now - interval '5 minutes'
     OR p_reason_code IS NULL
     OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Trust configuration rollback input is invalid.';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 0));
  SELECT * INTO v_target
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = v_tenant_id
    AND configuration.configuration_version = p_target_configuration_version
  FOR SHARE;

  SELECT * INTO v_previous
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = v_tenant_id AND configuration.state = 'active'
  FOR UPDATE;

  IF v_target.configuration_version IS NULL
     OR v_target.state <> 'superseded'
     OR v_previous.configuration_version IS NULL
     OR p_occurred_at < v_previous.activated_at THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust configuration rollback denied.';
  END IF;

  SELECT COALESCE(MAX(configuration.configuration_version), 0) + 1
  INTO v_next_version
  FROM trust.trust_configurations AS configuration
  WHERE configuration.tenant_id = v_tenant_id;

  UPDATE trust.trust_configurations
  SET state = 'superseded',
      superseded_at = p_occurred_at,
      updated_at = GREATEST(v_now, p_occurred_at)
  WHERE tenant_id = v_tenant_id
    AND configuration_version = v_previous.configuration_version;

  INSERT INTO trust.trust_configurations (
    tenant_id, configuration_version, model_version, state, initial_score,
    smoothing_alpha, maximum_source_influence, stale_after_seconds,
    identity_weight, device_weight, behaviour_weight, certificate_weight,
    compliance_weight, created_by_subject_id, activated_at, created_at, updated_at
  ) VALUES (
    v_tenant_id, v_next_version, v_target.model_version, 'active', v_target.initial_score,
    v_target.smoothing_alpha, v_target.maximum_source_influence, v_target.stale_after_seconds,
    v_target.identity_weight, v_target.device_weight, v_target.behaviour_weight,
    v_target.certificate_weight, v_target.compliance_weight, v_actor_subject_id,
    p_occurred_at, p_occurred_at, GREATEST(v_now, p_occurred_at)
  )
  RETURNING * INTO v_restored;

  INSERT INTO trust.trust_configuration_events (
    tenant_id, event_type, configuration_version,
    previous_active_configuration_version, rollback_target_configuration_version,
    actor_subject_id, reason_code, occurred_at
  ) VALUES (
    v_tenant_id, 'rollback_activated', v_next_version,
    v_previous.configuration_version, p_target_configuration_version,
    v_actor_subject_id, p_reason_code, p_occurred_at
  );

  RETURN v_restored;
END
$function$;

CREATE FUNCTION trust.list_trust_configuration_history()
RETURNS TABLE (
  tenant_id identity.tenant_id,
  configuration_version integer,
  model_version text,
  state trust.configuration_state,
  initial_score numeric,
  smoothing_alpha numeric,
  maximum_source_influence numeric,
  stale_after_seconds integer,
  identity_weight numeric,
  device_weight numeric,
  behaviour_weight numeric,
  certificate_weight numeric,
  compliance_weight numeric,
  created_by_subject_id identity.subject_id,
  activated_at timestamptz,
  superseded_at timestamptz,
  created_at timestamptz,
  updated_at timestamptz,
  latest_event_type trust.configuration_event_type,
  latest_reason_code text,
  latest_actor_subject_id identity.subject_id,
  previous_active_configuration_version integer,
  rollback_target_configuration_version integer,
  latest_event_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
BEGIN
  IF v_tenant_id IS NULL OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust configuration history denied.';
  END IF;

  RETURN QUERY
  SELECT configuration.tenant_id, configuration.configuration_version,
    configuration.model_version, configuration.state, configuration.initial_score,
    configuration.smoothing_alpha, configuration.maximum_source_influence,
    configuration.stale_after_seconds, configuration.identity_weight,
    configuration.device_weight, configuration.behaviour_weight,
    configuration.certificate_weight, configuration.compliance_weight,
    configuration.created_by_subject_id, configuration.activated_at,
    configuration.superseded_at, configuration.created_at, configuration.updated_at,
    latest.event_type, latest.reason_code, latest.actor_subject_id,
    latest.previous_active_configuration_version,
    latest.rollback_target_configuration_version, latest.occurred_at
  FROM trust.trust_configurations AS configuration
  LEFT JOIN LATERAL (
    SELECT event.event_type, event.reason_code, event.actor_subject_id,
      event.previous_active_configuration_version,
      event.rollback_target_configuration_version, event.occurred_at
    FROM trust.trust_configuration_events AS event
    WHERE event.tenant_id = configuration.tenant_id
      AND event.configuration_version = configuration.configuration_version
    ORDER BY event.event_sequence DESC
    LIMIT 1
  ) AS latest ON true
  WHERE configuration.tenant_id = v_tenant_id
  ORDER BY configuration.configuration_version DESC;
END
$function$;

REVOKE INSERT, UPDATE, DELETE ON trust.trust_configurations FROM tenant_trust_app;
REVOKE ALL ON trust.trust_configuration_events FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION trust.prevent_trust_configuration_history_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.create_trust_configuration_draft(
  text, numeric, numeric, numeric, integer,
  numeric, numeric, numeric, numeric, numeric, text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.activate_trust_configuration(integer, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.rollback_trust_configuration(integer, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.list_trust_configuration_history() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust.create_trust_configuration_draft(
  text, numeric, numeric, numeric, integer,
  numeric, numeric, numeric, numeric, numeric, text, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.activate_trust_configuration(integer, text, timestamptz)
  TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.rollback_trust_configuration(integer, text, timestamptz)
  TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.list_trust_configuration_history()
  TO tenant_trust_app;

COMMENT ON TABLE trust.trust_configuration_events IS
  'Append-only tenant-admin trust-configuration draft, activation and rollback history';
COMMENT ON FUNCTION trust.create_trust_configuration_draft(
  text, numeric, numeric, numeric, integer,
  numeric, numeric, numeric, numeric, numeric, text, timestamptz
) IS 'Creates the next immutable tenant trust-configuration draft after full range and weight validation';
COMMENT ON FUNCTION trust.activate_trust_configuration(integer, text, timestamptz) IS
  'Atomically activates one tenant draft and supersedes the prior active trust configuration';
COMMENT ON FUNCTION trust.rollback_trust_configuration(integer, text, timestamptz) IS
  'Restores a superseded configuration by copying it into a new active version without rewriting history';
COMMENT ON FUNCTION trust.list_trust_configuration_history() IS
  'Returns tenant trust-configuration versions with their latest lifecycle event to tenant administrators';
