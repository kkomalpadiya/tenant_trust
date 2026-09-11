CREATE SCHEMA IF NOT EXISTS app;

CREATE DOMAIN app.resource_id AS text
  CHECK (VALUE ~ '^res_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TABLE app.resources (
  tenant_id identity.tenant_id NOT NULL,
  resource_id app.resource_id NOT NULL,
  owner_subject_id identity.subject_id NOT NULL,
  resource_name text NOT NULL,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT resources_pk PRIMARY KEY (tenant_id, resource_id),
  CONSTRAINT resources_tenant_fk FOREIGN KEY (tenant_id)
    REFERENCES identity.tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT resources_owner_membership_fk FOREIGN KEY (tenant_id, owner_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT resources_name_format CHECK (
    resource_name = btrim(resource_name)
    AND length(resource_name) BETWEEN 1 AND 160
  ),
  CONSTRAINT resources_version_positive CHECK (version > 0),
  CONSTRAINT resources_timestamps_ordered CHECK (updated_at >= created_at)
);

CREATE INDEX resources_owner_lookup
  ON app.resources (tenant_id, owner_subject_id, resource_id);

CREATE FUNCTION identity.current_subject_id()
RETURNS identity.subject_id
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, identity
AS $function$
  SELECT NULLIF(current_setting('tenant_trust.subject_id', true), '')::identity.subject_id
$function$;

CREATE FUNCTION identity.current_actor_is_active()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM identity.tenants AS tenant
    JOIN identity.tenant_memberships AS membership
      ON membership.tenant_id = tenant.tenant_id
    JOIN identity.subjects AS subject
      ON subject.subject_id = membership.subject_id
    WHERE tenant.tenant_id = identity.current_tenant_id()
      AND subject.subject_id = identity.current_subject_id()
      AND tenant.state = 'active'
      AND subject.state = 'active'
      AND membership.state = 'active'
      AND EXISTS (
        SELECT 1
        FROM identity.tenant_role_assignments AS role_assignment
        WHERE role_assignment.tenant_id = membership.tenant_id
          AND role_assignment.subject_id = membership.subject_id
      )
  )
$function$;

CREATE FUNCTION identity.current_actor_is_tenant_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
  SELECT identity.current_actor_is_active()
    AND EXISTS (
      SELECT 1
      FROM identity.tenant_role_assignments AS role_assignment
      WHERE role_assignment.tenant_id = identity.current_tenant_id()
        AND role_assignment.subject_id = identity.current_subject_id()
        AND role_assignment.role_name = 'tenant-admin'
    )
$function$;

CREATE FUNCTION identity.set_tenant_actor_context(
  p_tenant_id identity.tenant_id,
  p_subject_id identity.subject_id
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM identity.tenants AS tenant
    JOIN identity.tenant_memberships AS membership
      ON membership.tenant_id = tenant.tenant_id
    JOIN identity.subjects AS subject
      ON subject.subject_id = membership.subject_id
    WHERE tenant.tenant_id = p_tenant_id
      AND subject.subject_id = p_subject_id
      AND tenant.state = 'active'
      AND subject.state = 'active'
      AND membership.state = 'active'
      AND EXISTS (
        SELECT 1
        FROM identity.tenant_role_assignments AS role_assignment
        WHERE role_assignment.tenant_id = membership.tenant_id
          AND role_assignment.subject_id = membership.subject_id
      )
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = 'Tenant actor context denied.';
  END IF;

  PERFORM set_config('tenant_trust.tenant_id', p_tenant_id::text, true);
  PERFORM set_config('tenant_trust.subject_id', p_subject_id::text, true);
END
$function$;

CREATE FUNCTION identity.enforce_active_membership_subject()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM identity.subjects
    WHERE subject_id = NEW.subject_id
      AND state = 'active'
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = 'Membership change denied.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER tenant_memberships_require_active_subject
BEFORE INSERT OR UPDATE OF tenant_id, subject_id
ON identity.tenant_memberships
FOR EACH ROW EXECUTE FUNCTION identity.enforce_active_membership_subject();

CREATE FUNCTION identity.enforce_role_on_active_membership()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM identity.tenant_memberships
    WHERE tenant_id = NEW.tenant_id
      AND subject_id = NEW.subject_id
      AND state = 'active'
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = 'Tenant role change denied.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER tenant_roles_require_active_membership
BEFORE INSERT OR UPDATE OF tenant_id, subject_id, role_name
ON identity.tenant_role_assignments
FOR EACH ROW EXECUTE FUNCTION identity.enforce_role_on_active_membership();

CREATE FUNCTION identity.prevent_last_active_tenant_admin_loss()
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

  IF removed_active_admin AND NOT EXISTS (
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

CREATE TRIGGER tenant_roles_preserve_active_admin
AFTER DELETE OR UPDATE OF tenant_id, subject_id, role_name
ON identity.tenant_role_assignments
FOR EACH ROW EXECUTE FUNCTION identity.prevent_last_active_tenant_admin_loss();

CREATE TRIGGER tenant_memberships_preserve_active_admin
AFTER DELETE OR UPDATE OF state
ON identity.tenant_memberships
FOR EACH ROW EXECUTE FUNCTION identity.prevent_last_active_tenant_admin_loss();

CREATE FUNCTION app.enforce_active_resource_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, identity
SET row_security = off
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM identity.tenant_memberships AS membership
    JOIN identity.subjects AS subject
      ON subject.subject_id = membership.subject_id
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.subject_id = NEW.owner_subject_id
      AND membership.state = 'active'
      AND subject.state = 'active'
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = 'Resource owner denied.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER resources_require_active_owner
BEFORE INSERT OR UPDATE OF tenant_id, owner_subject_id
ON app.resources
FOR EACH ROW EXECUTE FUNCTION app.enforce_active_resource_owner();

DROP POLICY tenants_current_tenant ON identity.tenants;
CREATE POLICY tenants_current_tenant
  ON identity.tenants
  FOR SELECT
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
  );
CREATE POLICY tenants_tenant_admin_update
  ON identity.tenants
  FOR UPDATE
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  )
  WITH CHECK (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  );

DROP POLICY memberships_current_tenant ON identity.tenant_memberships;
CREATE POLICY memberships_current_tenant
  ON identity.tenant_memberships
  FOR SELECT
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
  );
CREATE POLICY memberships_tenant_admin_insert
  ON identity.tenant_memberships
  FOR INSERT
  TO tenant_trust_app
  WITH CHECK (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  );
CREATE POLICY memberships_tenant_admin_update
  ON identity.tenant_memberships
  FOR UPDATE
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  )
  WITH CHECK (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  );
CREATE POLICY memberships_tenant_admin_delete
  ON identity.tenant_memberships
  FOR DELETE
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  );

DROP POLICY tenant_roles_current_tenant ON identity.tenant_role_assignments;
CREATE POLICY tenant_roles_current_tenant
  ON identity.tenant_role_assignments
  FOR SELECT
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
  );
CREATE POLICY tenant_roles_tenant_admin_insert
  ON identity.tenant_role_assignments
  FOR INSERT
  TO tenant_trust_app
  WITH CHECK (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  );
CREATE POLICY tenant_roles_tenant_admin_update
  ON identity.tenant_role_assignments
  FOR UPDATE
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  )
  WITH CHECK (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  );
CREATE POLICY tenant_roles_tenant_admin_delete
  ON identity.tenant_role_assignments
  FOR DELETE
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_tenant_admin()
  );

ALTER TABLE app.resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.resources FORCE ROW LEVEL SECURITY;
CREATE POLICY resources_current_actor_select
  ON app.resources
  FOR SELECT
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
    AND (
      owner_subject_id = identity.current_subject_id()
      OR identity.current_actor_is_tenant_admin()
    )
  );
CREATE POLICY resources_current_actor_insert
  ON app.resources
  FOR INSERT
  TO tenant_trust_app
  WITH CHECK (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
    AND (
      owner_subject_id = identity.current_subject_id()
      OR identity.current_actor_is_tenant_admin()
    )
  );
CREATE POLICY resources_current_actor_update
  ON app.resources
  FOR UPDATE
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
    AND (
      owner_subject_id = identity.current_subject_id()
      OR identity.current_actor_is_tenant_admin()
    )
  )
  WITH CHECK (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
    AND (
      owner_subject_id = identity.current_subject_id()
      OR identity.current_actor_is_tenant_admin()
    )
  );
CREATE POLICY resources_current_actor_delete
  ON app.resources
  FOR DELETE
  TO tenant_trust_app
  USING (
    tenant_id = identity.current_tenant_id()
    AND identity.current_actor_is_active()
    AND (
      owner_subject_id = identity.current_subject_id()
      OR identity.current_actor_is_tenant_admin()
    )
  );

REVOKE ALL ON FUNCTION identity.current_subject_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.current_actor_is_active() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.current_actor_is_tenant_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.set_tenant_actor_context(identity.tenant_id, identity.subject_id) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_active_membership_subject() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_role_on_active_membership() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.prevent_last_active_tenant_admin_loss() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.enforce_active_resource_owner() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION identity.current_subject_id() TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION identity.current_actor_is_active() TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION identity.current_actor_is_tenant_admin() TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION identity.set_tenant_actor_context(identity.tenant_id, identity.subject_id) TO tenant_trust_app;
GRANT USAGE ON SCHEMA app TO tenant_trust_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.resources TO tenant_trust_app;

COMMENT ON SCHEMA app IS 'Tenant-owned SaaS application records';
COMMENT ON DOMAIN app.resource_id IS 'Opaque protected-resource identifier matching the res_UUID format';
COMMENT ON TABLE app.resources IS 'Sample tenant-owned resources protected by tenant, membership, ownership and tenant-admin rules';
COMMENT ON FUNCTION identity.current_subject_id() IS 'Returns the transaction-local authenticated subject binding used by actor-aware row-level security';
COMMENT ON FUNCTION identity.set_tenant_actor_context(identity.tenant_id, identity.subject_id) IS 'Binds an active authorized tenant member to the current transaction after trusted authentication resolution';
