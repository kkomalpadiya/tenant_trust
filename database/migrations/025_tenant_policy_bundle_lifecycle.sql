ALTER TABLE trust.policy_versions
  ADD COLUMN bundle_document jsonb,
  ADD COLUMN bundle_canonical_json text,
  ADD COLUMN validation_engine text,
  ADD COLUMN validation_engine_version text,
  ADD COLUMN rego_version text,
  ADD COLUMN validated_at timestamptz,
  ADD CONSTRAINT policy_versions_validated_bundle_shape CHECK (
    (
      bundle_document IS NULL
      AND bundle_canonical_json IS NULL
      AND validation_engine IS NULL
      AND validation_engine_version IS NULL
      AND rego_version IS NULL
      AND validated_at IS NULL
    )
    OR (
      jsonb_typeof(bundle_document) = 'object'
      AND bundle_canonical_json IS NOT NULL
      AND length(bundle_canonical_json) BETWEEN 2 AND 1048576
      AND validation_engine = 'opa'
      AND validation_engine_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
      AND rego_version = 'v1'
      AND validated_at IS NOT NULL
    )
  ),
  ADD CONSTRAINT policy_versions_active_requires_validated_bundle CHECK (
    state <> 'active' OR bundle_document IS NOT NULL
  );

CREATE TYPE trust.policy_bundle_event_type AS ENUM ('published', 'activated', 'superseded');

CREATE TABLE trust.policy_bundle_events (
  tenant_id identity.tenant_id NOT NULL,
  event_sequence bigint GENERATED ALWAYS AS IDENTITY,
  event_type trust.policy_bundle_event_type NOT NULL,
  policy_version_id trust.policy_version_id NOT NULL,
  previous_active_policy_version_id trust.policy_version_id,
  actor_subject_id identity.subject_id NOT NULL,
  reason_code text NOT NULL,
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT policy_bundle_events_pk PRIMARY KEY (tenant_id, event_sequence),
  CONSTRAINT policy_bundle_events_policy_fk
    FOREIGN KEY (tenant_id, policy_version_id)
    REFERENCES trust.policy_versions (tenant_id, policy_version_id) ON DELETE RESTRICT,
  CONSTRAINT policy_bundle_events_previous_fk
    FOREIGN KEY (tenant_id, previous_active_policy_version_id)
    REFERENCES trust.policy_versions (tenant_id, policy_version_id) ON DELETE RESTRICT,
  CONSTRAINT policy_bundle_events_actor_fk
    FOREIGN KEY (tenant_id, actor_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT policy_bundle_events_reason_format CHECK (
    reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT policy_bundle_events_shape CHECK (
    (event_type = 'published' AND previous_active_policy_version_id IS NULL)
    OR event_type IN ('activated', 'superseded')
  )
);

CREATE INDEX policy_bundle_events_history_lookup
  ON trust.policy_bundle_events (tenant_id, policy_version_id, event_sequence DESC);

CREATE FUNCTION trust.prevent_policy_bundle_history_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '23514',
    MESSAGE = 'Policy bundle history is append-only.';
END
$function$;

CREATE TRIGGER policy_versions_prevent_delete
BEFORE DELETE ON trust.policy_versions
FOR EACH ROW EXECUTE FUNCTION trust.prevent_policy_bundle_history_rewrite();

CREATE TRIGGER policy_bundle_events_keep_history
BEFORE UPDATE OR DELETE ON trust.policy_bundle_events
FOR EACH ROW EXECUTE FUNCTION trust.prevent_policy_bundle_history_rewrite();

ALTER TABLE trust.policy_bundle_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.policy_bundle_events FORCE ROW LEVEL SECURITY;

CREATE POLICY policy_bundle_events_current_actor_select
  ON trust.policy_bundle_events FOR SELECT TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_active());

CREATE FUNCTION trust.publish_policy_bundle(
  p_policy_version_id trust.policy_version_id,
  p_policy_name text,
  p_bundle_version integer,
  p_bundle_hash_sha256 text,
  p_entrypoint text,
  p_bundle_canonical_json text,
  p_validation_engine_version text,
  p_rego_version text,
  p_reason_code text,
  p_occurred_at timestamptz
)
RETURNS trust.policy_versions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_actor_subject_id identity.subject_id := identity.current_subject_id();
  v_now timestamptz := clock_timestamp();
  v_document jsonb;
  v_previous_policy_version_id trust.policy_version_id;
  v_next_bundle_version integer;
  v_bundle trust.policy_versions%ROWTYPE;
BEGIN
  IF v_tenant_id IS NULL
     OR v_actor_subject_id IS NULL
     OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy bundle publication denied.';
  END IF;
  IF p_occurred_at IS NULL
     OR p_occurred_at > v_now + interval '2 seconds'
     OR p_occurred_at < v_now - interval '5 minutes'
     OR p_policy_name IS NULL
     OR p_policy_name <> lower(p_policy_name)
     OR p_policy_name !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
     OR length(p_policy_name) NOT BETWEEN 1 AND 63
     OR p_bundle_version IS NULL OR p_bundle_version < 1
     OR p_bundle_hash_sha256 IS NULL OR p_bundle_hash_sha256 !~ '^[0-9a-f]{64}$'
     OR p_entrypoint <> 'tenant_trust/authorization/decision'
     OR p_bundle_canonical_json IS NULL
     OR length(p_bundle_canonical_json) NOT BETWEEN 2 AND 1048576
     OR p_validation_engine_version IS NULL
     OR p_validation_engine_version !~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
     OR p_rego_version <> 'v1'
     OR p_reason_code IS NULL
     OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Policy bundle publication input is invalid.';
  END IF;

  BEGIN
    v_document := p_bundle_canonical_json::jsonb;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Policy bundle document is invalid.';
  END;

  IF jsonb_typeof(v_document) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(v_document)) <> 9
     OR v_document->>'schemaVersion' <> '1.0.0'
     OR v_document->>'tenantId' <> v_tenant_id::text
     OR v_document->>'policyVersionId' <> p_policy_version_id::text
     OR v_document->>'policyName' <> p_policy_name
     OR (v_document->>'bundleVersion')::integer <> p_bundle_version
     OR v_document->>'entrypoint' <> p_entrypoint
     OR jsonb_typeof(v_document->'modules') <> 'array'
     OR jsonb_array_length(v_document->'modules') NOT BETWEEN 1 AND 32
     OR jsonb_typeof(v_document->'data') <> 'object'
     OR jsonb_typeof(v_document->'validation') <> 'object'
     OR v_document#>>'{validation,engine}' <> 'opa'
     OR v_document#>>'{validation,engineVersion}' <> p_validation_engine_version
     OR v_document#>>'{validation,regoVersion}' <> p_rego_version
     OR (v_document#>>'{validation,checkedAt}')::timestamptz <> p_occurred_at
     OR encode(public.digest(convert_to(p_bundle_canonical_json, 'UTF8'), 'sha256'), 'hex')
       <> p_bundle_hash_sha256 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Policy bundle document is invalid.';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(v_tenant_id::text || ':' || p_policy_name, 0));
  PERFORM 1 FROM identity.tenants AS tenant
  WHERE tenant.tenant_id = v_tenant_id AND tenant.state = 'active'
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy bundle publication denied.';
  END IF;

  SELECT bundle.policy_version_id, bundle.bundle_version + 1
  INTO v_previous_policy_version_id, v_next_bundle_version
  FROM trust.policy_versions AS bundle
  WHERE bundle.tenant_id = v_tenant_id
    AND bundle.policy_name = p_policy_name
  ORDER BY bundle.bundle_version DESC
  LIMIT 1
  FOR SHARE;
  v_next_bundle_version := COALESCE(v_next_bundle_version, 1);
  IF p_bundle_version <> v_next_bundle_version THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Policy bundle version is not the next tenant version.';
  END IF;

  INSERT INTO trust.policy_versions (
    tenant_id, policy_version_id, policy_name, bundle_version,
    bundle_hash_sha256, entrypoint, state, replaces_policy_version_id,
    published_by_subject_id, bundle_document, bundle_canonical_json,
    validation_engine, validation_engine_version, rego_version, validated_at,
    created_at, updated_at
  ) VALUES (
    v_tenant_id, p_policy_version_id, p_policy_name, p_bundle_version,
    p_bundle_hash_sha256, p_entrypoint, 'published', v_previous_policy_version_id,
    v_actor_subject_id, v_document, p_bundle_canonical_json,
    'opa', p_validation_engine_version, p_rego_version, p_occurred_at,
    p_occurred_at, GREATEST(v_now, p_occurred_at)
  )
  RETURNING * INTO v_bundle;

  INSERT INTO trust.policy_bundle_events (
    tenant_id, event_type, policy_version_id, actor_subject_id,
    reason_code, occurred_at
  ) VALUES (
    v_tenant_id, 'published', p_policy_version_id, v_actor_subject_id,
    p_reason_code, p_occurred_at
  );

  RETURN v_bundle;
END
$function$;

CREATE FUNCTION trust.activate_policy_bundle(
  p_policy_version_id trust.policy_version_id,
  p_reason_code text,
  p_occurred_at timestamptz
)
RETURNS trust.policy_versions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_actor_subject_id identity.subject_id := identity.current_subject_id();
  v_now timestamptz := clock_timestamp();
  v_target trust.policy_versions%ROWTYPE;
  v_previous trust.policy_versions%ROWTYPE;
BEGIN
  IF v_tenant_id IS NULL
     OR v_actor_subject_id IS NULL
     OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy bundle activation denied.';
  END IF;
  IF p_occurred_at IS NULL
     OR p_occurred_at > v_now + interval '2 seconds'
     OR p_occurred_at < v_now - interval '5 minutes'
     OR p_reason_code IS NULL
     OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Policy bundle activation input is invalid.';
  END IF;

  SELECT * INTO v_target
  FROM trust.policy_versions AS bundle
  WHERE bundle.tenant_id = v_tenant_id
    AND bundle.policy_version_id = p_policy_version_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy bundle activation denied.';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(v_tenant_id::text || ':' || v_target.policy_name, 0));
  SELECT * INTO v_target
  FROM trust.policy_versions AS bundle
  WHERE bundle.tenant_id = v_tenant_id
    AND bundle.policy_version_id = p_policy_version_id
  FOR UPDATE;
  IF v_target.state <> 'published'
     OR v_target.bundle_document IS NULL
     OR p_occurred_at < v_target.created_at THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy bundle activation denied.';
  END IF;

  SELECT * INTO v_previous
  FROM trust.policy_versions AS bundle
  WHERE bundle.tenant_id = v_tenant_id
    AND bundle.policy_name = v_target.policy_name
    AND bundle.state = 'active'
  FOR UPDATE;

  IF v_previous.policy_version_id IS NOT NULL THEN
    IF p_occurred_at < v_previous.activated_at THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Policy bundle activation time is invalid.';
    END IF;
    UPDATE trust.policy_versions
    SET state = 'superseded',
        superseded_at = p_occurred_at,
        updated_at = GREATEST(v_now, p_occurred_at)
    WHERE tenant_id = v_tenant_id
      AND policy_version_id = v_previous.policy_version_id;

    INSERT INTO trust.policy_bundle_events (
      tenant_id, event_type, policy_version_id,
      previous_active_policy_version_id, actor_subject_id,
      reason_code, occurred_at
    ) VALUES (
      v_tenant_id, 'superseded', v_previous.policy_version_id,
      v_previous.policy_version_id, v_actor_subject_id,
      p_reason_code, p_occurred_at
    );
  END IF;

  UPDATE trust.policy_versions
  SET state = 'active',
      activated_at = p_occurred_at,
      superseded_at = NULL,
      updated_at = GREATEST(v_now, p_occurred_at)
  WHERE tenant_id = v_tenant_id AND policy_version_id = p_policy_version_id
  RETURNING * INTO v_target;

  INSERT INTO trust.policy_bundle_events (
    tenant_id, event_type, policy_version_id,
    previous_active_policy_version_id, actor_subject_id,
    reason_code, occurred_at
  ) VALUES (
    v_tenant_id, 'activated', p_policy_version_id,
    v_previous.policy_version_id, v_actor_subject_id,
    p_reason_code, p_occurred_at
  );

  RETURN v_target;
END
$function$;

CREATE FUNCTION trust.list_policy_bundle_history(p_policy_name text)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  policy_version_id trust.policy_version_id,
  policy_name text,
  bundle_version integer,
  bundle_hash_sha256 text,
  entrypoint text,
  state trust.policy_version_state,
  replaces_policy_version_id trust.policy_version_id,
  published_by_subject_id identity.subject_id,
  bundle_document jsonb,
  bundle_canonical_json text,
  validation_engine text,
  validation_engine_version text,
  rego_version text,
  validated_at timestamptz,
  activated_at timestamptz,
  superseded_at timestamptz,
  created_at timestamptz,
  updated_at timestamptz,
  latest_event_type trust.policy_bundle_event_type,
  latest_reason_code text
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
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy bundle history denied.';
  END IF;

  RETURN QUERY
  SELECT bundle.tenant_id, bundle.policy_version_id, bundle.policy_name,
    bundle.bundle_version, bundle.bundle_hash_sha256, bundle.entrypoint,
    bundle.state, bundle.replaces_policy_version_id, bundle.published_by_subject_id,
    bundle.bundle_document, bundle.bundle_canonical_json,
    bundle.validation_engine, bundle.validation_engine_version, bundle.rego_version,
    bundle.validated_at, bundle.activated_at, bundle.superseded_at,
    bundle.created_at, bundle.updated_at,
    latest.event_type, latest.reason_code
  FROM trust.policy_versions AS bundle
  LEFT JOIN LATERAL (
    SELECT event.event_type, event.reason_code
    FROM trust.policy_bundle_events AS event
    WHERE event.tenant_id = bundle.tenant_id
      AND event.policy_version_id = bundle.policy_version_id
    ORDER BY event.event_sequence DESC
    LIMIT 1
  ) AS latest ON true
  WHERE bundle.tenant_id = v_tenant_id
    AND bundle.policy_name = p_policy_name
    AND bundle.bundle_document IS NOT NULL
  ORDER BY bundle.bundle_version DESC;
END
$function$;

CREATE FUNCTION trust.get_active_policy_bundle(p_policy_name text)
RETURNS SETOF trust.policy_versions
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
BEGIN
  IF v_tenant_id IS NULL OR NOT identity.current_actor_is_active() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Active policy bundle lookup denied.';
  END IF;
  RETURN QUERY
  SELECT bundle.*
  FROM trust.policy_versions AS bundle
  WHERE bundle.tenant_id = v_tenant_id
    AND bundle.policy_name = p_policy_name
    AND bundle.state = 'active';
END
$function$;

REVOKE INSERT, UPDATE, DELETE ON trust.policy_versions FROM tenant_trust_app;
REVOKE ALL ON trust.policy_bundle_events FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION trust.prevent_policy_bundle_history_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.publish_policy_bundle(
  trust.policy_version_id, text, integer, text, text, text, text, text, text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.activate_policy_bundle(
  trust.policy_version_id, text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.list_policy_bundle_history(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.get_active_policy_bundle(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust.publish_policy_bundle(
  trust.policy_version_id, text, integer, text, text, text, text, text, text, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.activate_policy_bundle(
  trust.policy_version_id, text, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.list_policy_bundle_history(text) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.get_active_policy_bundle(text) TO tenant_trust_app;

COMMENT ON TABLE trust.policy_bundle_events IS
  'Append-only tenant policy publication, activation and supersession history';
COMMENT ON FUNCTION trust.publish_policy_bundle(
  trust.policy_version_id, text, integer, text, text, text, text, text, text, timestamptz
) IS 'Publishes the next immutable, content-addressed and OPA-validated tenant policy bundle';
COMMENT ON FUNCTION trust.activate_policy_bundle(trust.policy_version_id, text, timestamptz) IS
  'Atomically activates one tenant policy bundle and supersedes the prior active version';
COMMENT ON FUNCTION trust.get_active_policy_bundle(text) IS
  'Returns only the current actor tenant active policy bundle for decision provenance verification';
