DO $create_platform_admin_role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_platform_admin') THEN
    CREATE ROLE tenant_trust_platform_admin;
  END IF;
END
$create_platform_admin_role$;

ALTER ROLE tenant_trust_platform_admin
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS
  PASSWORD NULL;

ALTER TABLE identity.tenants
  ADD COLUMN retired_at timestamptz,
  ADD CONSTRAINT tenants_retirement_requires_suspension CHECK (
    retired_at IS NULL OR state = 'suspended'
  ),
  ADD CONSTRAINT tenants_retirement_after_creation CHECK (
    retired_at IS NULL OR retired_at >= created_at
  );

CREATE TABLE audit.tenant_lifecycle_events (
  lifecycle_event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id identity.tenant_id NOT NULL,
  tenant_slug text NOT NULL,
  tenant_display_name text NOT NULL,
  action text NOT NULL,
  previous_state identity.tenant_state NOT NULL,
  new_state identity.tenant_state NOT NULL,
  tenant_version bigint NOT NULL,
  reason_code text NOT NULL,
  requested_by_subject_id identity.subject_id NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT tenant_lifecycle_events_tenant_fk FOREIGN KEY (tenant_id)
    REFERENCES identity.tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT tenant_lifecycle_events_actor_fk FOREIGN KEY (requested_by_subject_id)
    REFERENCES identity.subjects (subject_id) ON DELETE RESTRICT,
  CONSTRAINT tenant_lifecycle_events_action_allowed CHECK (
    action IN ('suspended', 'reactivated', 'teardown_completed')
  ),
  CONSTRAINT tenant_lifecycle_events_reason_format CHECK (
    reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT tenant_lifecycle_events_version_positive CHECK (tenant_version > 0),
  CONSTRAINT tenant_lifecycle_events_details_object CHECK (jsonb_typeof(details) = 'object'),
  CONSTRAINT tenant_lifecycle_events_version_unique UNIQUE (tenant_id, tenant_version)
);

CREATE INDEX tenant_lifecycle_events_tenant_time
  ON audit.tenant_lifecycle_events (tenant_id, recorded_at, lifecycle_event_id);

CREATE FUNCTION identity.current_platform_subject_id()
RETURNS identity.subject_id
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, identity
AS $function$
  SELECT NULLIF(current_setting('tenant_trust.platform_subject_id', true), '')::identity.subject_id
$function$;

CREATE FUNCTION identity.current_platform_actor_is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM identity.subjects AS subject
    JOIN identity.platform_role_assignments AS role_assignment
      ON role_assignment.subject_id = subject.subject_id
    WHERE subject.subject_id = identity.current_platform_subject_id()
      AND subject.state = 'active'
      AND role_assignment.role_name = 'platform-admin'
  )
$function$;

CREATE FUNCTION identity.set_platform_actor_context(p_subject_id identity.subject_id)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM identity.subjects AS subject
    JOIN identity.platform_role_assignments AS role_assignment
      ON role_assignment.subject_id = subject.subject_id
    WHERE subject.subject_id = p_subject_id
      AND subject.state = 'active'
      AND role_assignment.role_name = 'platform-admin'
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = 'Platform actor context denied.';
  END IF;

  PERFORM set_config('tenant_trust.platform_subject_id', p_subject_id::text, true);
END
$function$;

CREATE FUNCTION audit.reject_lifecycle_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, audit
AS $function$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '42501',
    MESSAGE = 'Tenant lifecycle audit events are append-only.';
END
$function$;

CREATE TRIGGER tenant_lifecycle_events_append_only
BEFORE UPDATE OR DELETE ON audit.tenant_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION audit.reject_lifecycle_event_mutation();

CREATE FUNCTION identity.reject_tenant_physical_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, identity
AS $function$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '42501',
    MESSAGE = 'Tenants use audited lifecycle teardown and cannot be physically deleted.';
END
$function$;

CREATE TRIGGER tenants_require_lifecycle_teardown
BEFORE DELETE ON identity.tenants
FOR EACH ROW EXECUTE FUNCTION identity.reject_tenant_physical_delete();

CREATE OR REPLACE FUNCTION identity.prevent_last_active_tenant_admin_loss()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
DECLARE
  affected_tenant identity.tenant_id;
  removed_active_admin boolean := false;
BEGIN
  affected_tenant := OLD.tenant_id;

  IF TG_TABLE_NAME = 'tenant_role_assignments' THEN
    removed_active_admin := OLD.role_name = 'tenant-admin'
      AND (
        TG_OP = 'DELETE'
        OR NEW.role_name <> 'tenant-admin'
        OR NEW.tenant_id <> OLD.tenant_id
        OR NEW.subject_id <> OLD.subject_id
      );
  ELSIF TG_TABLE_NAME = 'tenant_memberships' THEN
    removed_active_admin := OLD.state = 'active'
      AND (TG_OP = 'DELETE' OR NEW.state <> 'active')
      AND EXISTS (
        SELECT 1
        FROM identity.tenant_role_assignments
        WHERE tenant_id = OLD.tenant_id
          AND subject_id = OLD.subject_id
          AND role_name = 'tenant-admin'
      );
  END IF;

  IF removed_active_admin
     AND EXISTS (
       SELECT 1 FROM identity.tenants
       WHERE tenant_id = affected_tenant
         AND state = 'active'
     )
     AND NOT EXISTS (
       SELECT 1
       FROM identity.tenant_memberships AS membership
       JOIN identity.tenant_role_assignments AS role_assignment
         ON role_assignment.tenant_id = membership.tenant_id
        AND role_assignment.subject_id = membership.subject_id
       WHERE membership.tenant_id = affected_tenant
         AND membership.state = 'active'
         AND role_assignment.role_name = 'tenant-admin'
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'Tenant must retain an active administrator.';
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END
$function$;

CREATE FUNCTION identity.suspend_tenant(
  p_tenant_id identity.tenant_id,
  p_reason_code text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, audit
SET row_security = off
AS $function$
DECLARE
  actor_id identity.subject_id := identity.current_platform_subject_id();
  tenant_record identity.tenants%ROWTYPE;
  next_version bigint;
BEGIN
  IF NOT identity.current_platform_actor_is_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Tenant lifecycle change denied.';
  END IF;
  IF p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Tenant lifecycle reason code is invalid.';
  END IF;

  SELECT * INTO tenant_record
  FROM identity.tenants
  WHERE tenant_id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Tenant lifecycle change denied.';
  END IF;
  IF tenant_record.retired_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Retired tenant cannot change lifecycle state.';
  END IF;
  IF tenant_record.state = 'suspended' THEN
    RETURN tenant_record.version;
  END IF;

  next_version := tenant_record.version + 1;
  UPDATE identity.tenants
  SET state = 'suspended', version = next_version, updated_at = clock_timestamp()
  WHERE tenant_id = p_tenant_id;

  INSERT INTO audit.tenant_lifecycle_events (
    tenant_id, tenant_slug, tenant_display_name, action, previous_state, new_state,
    tenant_version, reason_code, requested_by_subject_id
  ) VALUES (
    tenant_record.tenant_id, tenant_record.tenant_slug, tenant_record.display_name,
    'suspended', tenant_record.state, 'suspended', next_version, p_reason_code, actor_id
  );

  RETURN next_version;
END
$function$;

CREATE FUNCTION identity.reactivate_tenant(
  p_tenant_id identity.tenant_id,
  p_reason_code text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, audit
SET row_security = off
AS $function$
DECLARE
  actor_id identity.subject_id := identity.current_platform_subject_id();
  tenant_record identity.tenants%ROWTYPE;
  next_version bigint;
BEGIN
  IF NOT identity.current_platform_actor_is_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Tenant lifecycle change denied.';
  END IF;
  IF p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Tenant lifecycle reason code is invalid.';
  END IF;

  SELECT * INTO tenant_record
  FROM identity.tenants
  WHERE tenant_id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Tenant lifecycle change denied.';
  END IF;
  IF tenant_record.retired_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Retired tenant cannot change lifecycle state.';
  END IF;
  IF tenant_record.state = 'active' THEN
    RETURN tenant_record.version;
  END IF;

  next_version := tenant_record.version + 1;
  UPDATE identity.tenants
  SET state = 'active', version = next_version, updated_at = clock_timestamp()
  WHERE tenant_id = p_tenant_id;

  INSERT INTO audit.tenant_lifecycle_events (
    tenant_id, tenant_slug, tenant_display_name, action, previous_state, new_state,
    tenant_version, reason_code, requested_by_subject_id
  ) VALUES (
    tenant_record.tenant_id, tenant_record.tenant_slug, tenant_record.display_name,
    'reactivated', tenant_record.state, 'active', next_version, p_reason_code, actor_id
  );

  RETURN next_version;
END
$function$;

CREATE FUNCTION identity.teardown_tenant(
  p_tenant_id identity.tenant_id,
  p_reason_code text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, app, trust, audit
SET row_security = off
AS $function$
DECLARE
  actor_id identity.subject_id := identity.current_platform_subject_id();
  tenant_record identity.tenants%ROWTYPE;
  next_version bigint;
  membership_count integer;
  role_count integer;
  resource_count integer;
  issuer_count integer;
  source_count integer;
  trust_configuration_count integer;
  policy_version_count integer;
BEGIN
  IF NOT identity.current_platform_actor_is_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Tenant lifecycle change denied.';
  END IF;
  IF p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Tenant lifecycle reason code is invalid.';
  END IF;

  SELECT * INTO tenant_record
  FROM identity.tenants
  WHERE tenant_id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Tenant lifecycle change denied.';
  END IF;
  IF tenant_record.retired_at IS NOT NULL THEN
    RETURN tenant_record.version;
  END IF;
  IF tenant_record.state <> 'suspended' THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Tenant must be suspended before teardown.';
  END IF;

  SELECT count(*) INTO membership_count FROM identity.tenant_memberships WHERE tenant_id = p_tenant_id;
  SELECT count(*) INTO role_count FROM identity.tenant_role_assignments WHERE tenant_id = p_tenant_id;
  SELECT count(*) INTO resource_count FROM app.resources WHERE tenant_id = p_tenant_id;
  SELECT count(*) INTO issuer_count FROM identity.tenant_issuer_mappings WHERE tenant_id = p_tenant_id;
  SELECT count(*) INTO source_count FROM trust.evidence_sources WHERE tenant_id = p_tenant_id;
  SELECT count(*) INTO trust_configuration_count FROM trust.trust_configurations WHERE tenant_id = p_tenant_id;
  SELECT count(*) INTO policy_version_count FROM trust.policy_versions WHERE tenant_id = p_tenant_id;

  DELETE FROM identity.tenant_role_assignments WHERE tenant_id = p_tenant_id;
  UPDATE identity.tenant_memberships
  SET state = 'suspended', version = version + 1, updated_at = clock_timestamp()
  WHERE tenant_id = p_tenant_id AND state <> 'suspended';
  UPDATE identity.tenant_issuer_mappings
  SET state = 'retired', version = version + 1, updated_at = clock_timestamp()
  WHERE tenant_id = p_tenant_id AND state <> 'retired';
  UPDATE trust.evidence_sources
  SET state = 'retired', version = version + 1, updated_at = clock_timestamp()
  WHERE tenant_id = p_tenant_id AND state <> 'retired';
  UPDATE trust.trust_configurations
  SET state = 'superseded', superseded_at = clock_timestamp(), updated_at = clock_timestamp()
  WHERE tenant_id = p_tenant_id AND state = 'active';
  UPDATE trust.policy_versions
  SET state = 'superseded', superseded_at = clock_timestamp(), updated_at = clock_timestamp()
  WHERE tenant_id = p_tenant_id AND state = 'active';

  next_version := tenant_record.version + 1;
  UPDATE identity.tenants
  SET retired_at = clock_timestamp(), version = next_version, updated_at = clock_timestamp()
  WHERE tenant_id = p_tenant_id;

  INSERT INTO audit.tenant_lifecycle_events (
    tenant_id, tenant_slug, tenant_display_name, action, previous_state, new_state,
    tenant_version, reason_code, requested_by_subject_id, details
  ) VALUES (
    tenant_record.tenant_id, tenant_record.tenant_slug, tenant_record.display_name,
    'teardown_completed', tenant_record.state, 'suspended', next_version,
    p_reason_code, actor_id,
    jsonb_build_object(
      'membershipsRetained', membership_count,
      'rolesRemoved', role_count,
      'resourcesRetained', resource_count,
      'issuersRetired', issuer_count,
      'evidenceSourcesRetired', source_count,
      'trustConfigurationsRetained', trust_configuration_count,
      'policyVersionsRetained', policy_version_count
    )
  );

  RETURN next_version;
END
$function$;

REVOKE UPDATE ON identity.tenants FROM tenant_trust_app;
GRANT UPDATE (tenant_slug, display_name, version, updated_at)
  ON identity.tenants TO tenant_trust_app;

REVOKE ALL ON FUNCTION identity.current_platform_subject_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.current_platform_actor_is_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.set_platform_actor_context(identity.subject_id) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.suspend_tenant(identity.tenant_id, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.reactivate_tenant(identity.tenant_id, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.teardown_tenant(identity.tenant_id, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.reject_lifecycle_event_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.reject_tenant_physical_delete() FROM PUBLIC;

GRANT USAGE ON SCHEMA identity, audit TO tenant_trust_platform_admin;
GRANT EXECUTE ON FUNCTION identity.current_platform_subject_id() TO tenant_trust_platform_admin;
GRANT EXECUTE ON FUNCTION identity.current_platform_actor_is_admin() TO tenant_trust_platform_admin;
GRANT EXECUTE ON FUNCTION identity.set_platform_actor_context(identity.subject_id) TO tenant_trust_platform_admin;
GRANT EXECUTE ON FUNCTION identity.suspend_tenant(identity.tenant_id, text) TO tenant_trust_platform_admin;
GRANT EXECUTE ON FUNCTION identity.reactivate_tenant(identity.tenant_id, text) TO tenant_trust_platform_admin;
GRANT EXECUTE ON FUNCTION identity.teardown_tenant(identity.tenant_id, text) TO tenant_trust_platform_admin;
GRANT SELECT ON audit.tenant_lifecycle_events TO tenant_trust_platform_admin;

COMMENT ON ROLE tenant_trust_platform_admin IS 'NOLOGIN platform lifecycle privilege set; assume only after trusted platform authentication';
COMMENT ON COLUMN identity.tenants.retired_at IS 'Irreversible soft-teardown marker; retired tenants remain suspended and retained';
COMMENT ON TABLE audit.tenant_lifecycle_events IS 'Append-only tenant lifecycle history with actor, reason, version and teardown retention counts';
COMMENT ON FUNCTION identity.set_platform_actor_context(identity.subject_id) IS 'Binds one active platform administrator to the current transaction after trusted authentication';
COMMENT ON FUNCTION identity.suspend_tenant(identity.tenant_id, text) IS 'Immediately suspends an active tenant and appends its lifecycle audit event';
COMMENT ON FUNCTION identity.reactivate_tenant(identity.tenant_id, text) IS 'Reactivates a suspended tenant unless irreversible teardown has completed';
COMMENT ON FUNCTION identity.teardown_tenant(identity.tenant_id, text) IS 'Irreversibly retires a suspended tenant while retaining identities, resources, configuration and audit history';
