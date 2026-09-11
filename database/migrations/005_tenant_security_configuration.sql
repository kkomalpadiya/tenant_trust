CREATE DOMAIN identity.issuer_id AS text
  CHECK (VALUE ~ '^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN trust.source_id AS text
  CHECK (VALUE ~ '^src_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN trust.policy_version_id AS text
  CHECK (VALUE ~ '^pol_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TYPE identity.issuer_mapping_state AS ENUM ('planned', 'active', 'suspended', 'retired');
CREATE TYPE trust.evidence_source_state AS ENUM ('planned', 'active', 'suspended', 'retired');
CREATE TYPE trust.evidence_type AS ENUM ('identity', 'device', 'behaviour', 'certificate', 'compliance');
CREATE TYPE trust.configuration_state AS ENUM ('draft', 'active', 'superseded');
CREATE TYPE trust.policy_version_state AS ENUM ('published', 'active', 'superseded');

CREATE TABLE identity.tenant_issuer_mappings (
  tenant_id identity.tenant_id NOT NULL,
  issuer_id identity.issuer_id NOT NULL,
  issuer_name text NOT NULL,
  authority_url text NOT NULL,
  state identity.issuer_mapping_state NOT NULL DEFAULT 'planned',
  root_certificate_sha256 text,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenant_issuer_mappings_pk PRIMARY KEY (tenant_id, issuer_id),
  CONSTRAINT tenant_issuer_mappings_tenant_fk FOREIGN KEY (tenant_id)
    REFERENCES identity.tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT tenant_issuer_mappings_name_unique UNIQUE (tenant_id, issuer_name),
  CONSTRAINT tenant_issuer_mappings_name_format CHECK (
    issuer_name = lower(issuer_name)
    AND issuer_name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    AND length(issuer_name) BETWEEN 1 AND 63
  ),
  CONSTRAINT tenant_issuer_mappings_url_format CHECK (
    authority_url = btrim(authority_url)
    AND authority_url ~ '^https://[^[:space:]]+$'
    AND length(authority_url) BETWEEN 9 AND 2048
  ),
  CONSTRAINT tenant_issuer_mappings_fingerprint_format CHECK (
    root_certificate_sha256 IS NULL
    OR root_certificate_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT tenant_issuer_mappings_active_fingerprint CHECK (
    state <> 'active' OR root_certificate_sha256 IS NOT NULL
  ),
  CONSTRAINT tenant_issuer_mappings_version_positive CHECK (version > 0),
  CONSTRAINT tenant_issuer_mappings_timestamps_ordered CHECK (updated_at >= created_at)
);

CREATE TABLE trust.evidence_sources (
  tenant_id identity.tenant_id NOT NULL,
  source_id trust.source_id NOT NULL,
  issuer_id identity.issuer_id,
  source_name text NOT NULL,
  evidence_type trust.evidence_type NOT NULL,
  state trust.evidence_source_state NOT NULL DEFAULT 'planned',
  verification_algorithm text NOT NULL,
  verification_key_sha256 text,
  maximum_age_seconds integer NOT NULL,
  synthetic boolean NOT NULL DEFAULT false,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT evidence_sources_pk PRIMARY KEY (tenant_id, source_id),
  CONSTRAINT evidence_sources_tenant_fk FOREIGN KEY (tenant_id)
    REFERENCES identity.tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_sources_issuer_fk FOREIGN KEY (tenant_id, issuer_id)
    REFERENCES identity.tenant_issuer_mappings (tenant_id, issuer_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_sources_name_unique UNIQUE (tenant_id, source_name),
  CONSTRAINT evidence_sources_name_format CHECK (
    source_name = lower(source_name)
    AND source_name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    AND length(source_name) BETWEEN 1 AND 63
  ),
  CONSTRAINT evidence_sources_algorithm_allowed CHECK (
    verification_algorithm IN ('ed25519', 'ecdsa-p256', 'rsa-pss-sha256')
  ),
  CONSTRAINT evidence_sources_key_fingerprint_format CHECK (
    verification_key_sha256 IS NULL
    OR verification_key_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT evidence_sources_active_key CHECK (
    state <> 'active' OR verification_key_sha256 IS NOT NULL
  ),
  CONSTRAINT evidence_sources_maximum_age CHECK (maximum_age_seconds BETWEEN 1 AND 86400),
  CONSTRAINT evidence_sources_version_positive CHECK (version > 0),
  CONSTRAINT evidence_sources_timestamps_ordered CHECK (updated_at >= created_at)
);

CREATE INDEX evidence_sources_type_lookup
  ON trust.evidence_sources (tenant_id, evidence_type, state, source_id);

CREATE TABLE trust.trust_configurations (
  tenant_id identity.tenant_id NOT NULL,
  configuration_version integer NOT NULL,
  model_version text NOT NULL,
  state trust.configuration_state NOT NULL DEFAULT 'draft',
  initial_score numeric(5,2) NOT NULL,
  smoothing_alpha numeric(5,4) NOT NULL,
  maximum_source_influence numeric(5,4) NOT NULL,
  stale_after_seconds integer NOT NULL,
  identity_weight numeric(5,4) NOT NULL,
  device_weight numeric(5,4) NOT NULL,
  behaviour_weight numeric(5,4) NOT NULL,
  certificate_weight numeric(5,4) NOT NULL,
  compliance_weight numeric(5,4) NOT NULL,
  created_by_subject_id identity.subject_id NOT NULL,
  activated_at timestamptz,
  superseded_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT trust_configurations_pk PRIMARY KEY (tenant_id, configuration_version),
  CONSTRAINT trust_configurations_tenant_fk FOREIGN KEY (tenant_id)
    REFERENCES identity.tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT trust_configurations_creator_membership_fk FOREIGN KEY (tenant_id, created_by_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT trust_configurations_version_positive CHECK (configuration_version > 0),
  CONSTRAINT trust_configurations_model_version_format CHECK (
    model_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'
  ),
  CONSTRAINT trust_configurations_initial_score_range CHECK (initial_score BETWEEN 0 AND 100),
  CONSTRAINT trust_configurations_smoothing_range CHECK (smoothing_alpha BETWEEN 0 AND 1),
  CONSTRAINT trust_configurations_source_influence_range CHECK (maximum_source_influence BETWEEN 0 AND 1),
  CONSTRAINT trust_configurations_stale_after_range CHECK (stale_after_seconds BETWEEN 1 AND 2592000),
  CONSTRAINT trust_configurations_weight_ranges CHECK (
    identity_weight BETWEEN 0 AND 1
    AND device_weight BETWEEN 0 AND 1
    AND behaviour_weight BETWEEN 0 AND 1
    AND certificate_weight BETWEEN 0 AND 1
    AND compliance_weight BETWEEN 0 AND 1
  ),
  CONSTRAINT trust_configurations_weight_total CHECK (
    identity_weight + device_weight + behaviour_weight + certificate_weight + compliance_weight = 1.0000
  ),
  CONSTRAINT trust_configurations_lifecycle CHECK (
    (state = 'draft' AND activated_at IS NULL AND superseded_at IS NULL)
    OR (state = 'active' AND activated_at IS NOT NULL AND superseded_at IS NULL)
    OR (
      state = 'superseded'
      AND activated_at IS NOT NULL
      AND superseded_at IS NOT NULL
      AND superseded_at >= activated_at
    )
  ),
  CONSTRAINT trust_configurations_timestamps_ordered CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX trust_configurations_one_active_per_tenant
  ON trust.trust_configurations (tenant_id)
  WHERE state = 'active';

CREATE TABLE trust.policy_versions (
  tenant_id identity.tenant_id NOT NULL,
  policy_version_id trust.policy_version_id NOT NULL,
  policy_name text NOT NULL,
  bundle_version integer NOT NULL,
  bundle_hash_sha256 text NOT NULL,
  entrypoint text NOT NULL,
  state trust.policy_version_state NOT NULL DEFAULT 'published',
  replaces_policy_version_id trust.policy_version_id,
  published_by_subject_id identity.subject_id NOT NULL,
  activated_at timestamptz,
  superseded_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT policy_versions_pk PRIMARY KEY (tenant_id, policy_version_id),
  CONSTRAINT policy_versions_tenant_fk FOREIGN KEY (tenant_id)
    REFERENCES identity.tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT policy_versions_publisher_membership_fk FOREIGN KEY (tenant_id, published_by_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT policy_versions_replaces_fk FOREIGN KEY (tenant_id, replaces_policy_version_id)
    REFERENCES trust.policy_versions (tenant_id, policy_version_id) ON DELETE RESTRICT,
  CONSTRAINT policy_versions_name_bundle_unique UNIQUE (tenant_id, policy_name, bundle_version),
  CONSTRAINT policy_versions_name_format CHECK (
    policy_name = lower(policy_name)
    AND policy_name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    AND length(policy_name) BETWEEN 1 AND 63
  ),
  CONSTRAINT policy_versions_bundle_version_positive CHECK (bundle_version > 0),
  CONSTRAINT policy_versions_bundle_hash_format CHECK (bundle_hash_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT policy_versions_entrypoint_format CHECK (
    entrypoint = btrim(entrypoint)
    AND entrypoint ~ '^[a-z][a-z0-9_]*(/[a-z][a-z0-9_]*)+$'
    AND length(entrypoint) BETWEEN 3 AND 255
  ),
  CONSTRAINT policy_versions_not_self_replacing CHECK (
    replaces_policy_version_id IS NULL OR replaces_policy_version_id <> policy_version_id
  ),
  CONSTRAINT policy_versions_lifecycle CHECK (
    (state = 'published' AND activated_at IS NULL AND superseded_at IS NULL)
    OR (state = 'active' AND activated_at IS NOT NULL AND superseded_at IS NULL)
    OR (
      state = 'superseded'
      AND activated_at IS NOT NULL
      AND superseded_at IS NOT NULL
      AND superseded_at >= activated_at
    )
  ),
  CONSTRAINT policy_versions_timestamps_ordered CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX policy_versions_one_active_name_per_tenant
  ON trust.policy_versions (tenant_id, policy_name)
  WHERE state = 'active';

CREATE FUNCTION identity.prevent_issuer_mapping_reassignment()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, identity
AS $function$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.issuer_id IS DISTINCT FROM OLD.issuer_id THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'Issuer mapping identity is immutable.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER tenant_issuer_mappings_keep_identity
BEFORE UPDATE OF tenant_id, issuer_id
ON identity.tenant_issuer_mappings
FOR EACH ROW EXECUTE FUNCTION identity.prevent_issuer_mapping_reassignment();

CREATE FUNCTION trust.prevent_evidence_source_reassignment()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.source_id IS DISTINCT FROM OLD.source_id THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'Evidence source identity is immutable.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER evidence_sources_keep_identity
BEFORE UPDATE OF tenant_id, source_id
ON trust.evidence_sources
FOR EACH ROW EXECUTE FUNCTION trust.prevent_evidence_source_reassignment();

CREATE FUNCTION trust.prevent_versioned_configuration_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  IF (
    to_jsonb(NEW) - ARRAY['state', 'activated_at', 'superseded_at', 'updated_at']
  ) IS DISTINCT FROM (
    to_jsonb(OLD) - ARRAY['state', 'activated_at', 'superseded_at', 'updated_at']
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'Versioned security configuration content is immutable.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER trust_configurations_keep_version_content
BEFORE UPDATE ON trust.trust_configurations
FOR EACH ROW EXECUTE FUNCTION trust.prevent_versioned_configuration_rewrite();

CREATE TRIGGER policy_versions_keep_version_content
BEFORE UPDATE ON trust.policy_versions
FOR EACH ROW EXECUTE FUNCTION trust.prevent_versioned_configuration_rewrite();

ALTER TABLE identity.tenant_issuer_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.tenant_issuer_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY issuer_mappings_current_actor_select
  ON identity.tenant_issuer_mappings FOR SELECT TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_active());
CREATE POLICY issuer_mappings_tenant_admin_insert
  ON identity.tenant_issuer_mappings FOR INSERT TO tenant_trust_app
  WITH CHECK (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());
CREATE POLICY issuer_mappings_tenant_admin_update
  ON identity.tenant_issuer_mappings FOR UPDATE TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin())
  WITH CHECK (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());
CREATE POLICY issuer_mappings_tenant_admin_delete
  ON identity.tenant_issuer_mappings FOR DELETE TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());

ALTER TABLE trust.evidence_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.evidence_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_sources_current_actor_select
  ON trust.evidence_sources FOR SELECT TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_active());
CREATE POLICY evidence_sources_tenant_admin_insert
  ON trust.evidence_sources FOR INSERT TO tenant_trust_app
  WITH CHECK (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());
CREATE POLICY evidence_sources_tenant_admin_update
  ON trust.evidence_sources FOR UPDATE TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin())
  WITH CHECK (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());
CREATE POLICY evidence_sources_tenant_admin_delete
  ON trust.evidence_sources FOR DELETE TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());

ALTER TABLE trust.trust_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.trust_configurations FORCE ROW LEVEL SECURITY;
CREATE POLICY trust_configurations_current_actor_select
  ON trust.trust_configurations FOR SELECT TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_active());
CREATE POLICY trust_configurations_tenant_admin_insert
  ON trust.trust_configurations FOR INSERT TO tenant_trust_app
  WITH CHECK (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());
CREATE POLICY trust_configurations_tenant_admin_update
  ON trust.trust_configurations FOR UPDATE TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin())
  WITH CHECK (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());
CREATE POLICY trust_configurations_tenant_admin_delete
  ON trust.trust_configurations FOR DELETE TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());

ALTER TABLE trust.policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.policy_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_versions_current_actor_select
  ON trust.policy_versions FOR SELECT TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_active());
CREATE POLICY policy_versions_tenant_admin_insert
  ON trust.policy_versions FOR INSERT TO tenant_trust_app
  WITH CHECK (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());
CREATE POLICY policy_versions_tenant_admin_update
  ON trust.policy_versions FOR UPDATE TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin())
  WITH CHECK (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());
CREATE POLICY policy_versions_tenant_admin_delete
  ON trust.policy_versions FOR DELETE TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_tenant_admin());

REVOKE ALL ON FUNCTION identity.prevent_issuer_mapping_reassignment() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.prevent_evidence_source_reassignment() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.prevent_versioned_configuration_rewrite() FROM PUBLIC;

GRANT USAGE ON SCHEMA trust TO tenant_trust_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity.tenant_issuer_mappings TO tenant_trust_app;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON trust.evidence_sources, trust.trust_configurations, trust.policy_versions
  TO tenant_trust_app;

COMMENT ON DOMAIN identity.issuer_id IS 'Opaque tenant issuer identifier matching the shared iss_UUID contract';
COMMENT ON DOMAIN trust.source_id IS 'Opaque evidence source identifier matching the shared src_UUID contract';
COMMENT ON DOMAIN trust.policy_version_id IS 'Opaque policy version identifier matching the shared pol_UUID contract';
COMMENT ON TABLE identity.tenant_issuer_mappings IS 'Tenant-owned issuer routing metadata; planned mappings do not imply an operational tenant CA';
COMMENT ON TABLE trust.evidence_sources IS 'Tenant-owned evidence source enrollment metadata and freshness limits';
COMMENT ON TABLE trust.trust_configurations IS 'Immutable versioned tenant trust-model inputs and evidence weights';
COMMENT ON TABLE trust.policy_versions IS 'Immutable tenant policy bundle identities and lifecycle metadata';
