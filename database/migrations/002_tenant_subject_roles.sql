CREATE DOMAIN identity.tenant_id AS text
  CHECK (VALUE ~ '^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN identity.subject_id AS text
  CHECK (VALUE ~ '^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TYPE identity.tenant_state AS ENUM ('active', 'suspended');
CREATE TYPE identity.subject_state AS ENUM ('active', 'suspended');
CREATE TYPE identity.membership_state AS ENUM ('active', 'suspended');
CREATE TYPE identity.subject_kind AS ENUM ('human', 'service');
CREATE TYPE identity.platform_role_name AS ENUM ('platform-admin');
CREATE TYPE identity.tenant_role_name AS ENUM ('tenant-admin', 'tenant-member');

CREATE TABLE identity.tenants (
  tenant_id identity.tenant_id PRIMARY KEY,
  tenant_slug text NOT NULL,
  display_name text NOT NULL,
  state identity.tenant_state NOT NULL DEFAULT 'active',
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenants_slug_format CHECK (
    tenant_slug = lower(tenant_slug)
    AND tenant_slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    AND length(tenant_slug) BETWEEN 1 AND 63
  ),
  CONSTRAINT tenants_slug_unique UNIQUE (tenant_slug),
  CONSTRAINT tenants_display_name_format CHECK (
    display_name = btrim(display_name)
    AND length(display_name) BETWEEN 1 AND 120
  ),
  CONSTRAINT tenants_version_positive CHECK (version > 0),
  CONSTRAINT tenants_timestamps_ordered CHECK (updated_at >= created_at)
);

CREATE TABLE identity.subjects (
  subject_id identity.subject_id PRIMARY KEY,
  identity_provider text NOT NULL,
  provider_subject text NOT NULL,
  subject_kind identity.subject_kind NOT NULL DEFAULT 'human',
  display_name text NOT NULL,
  state identity.subject_state NOT NULL DEFAULT 'active',
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT subjects_provider_format CHECK (
    identity_provider = btrim(identity_provider)
    AND length(identity_provider) BETWEEN 1 AND 255
  ),
  CONSTRAINT subjects_provider_subject_format CHECK (
    provider_subject = btrim(provider_subject)
    AND length(provider_subject) BETWEEN 1 AND 255
  ),
  CONSTRAINT subjects_external_identity_unique UNIQUE (identity_provider, provider_subject),
  CONSTRAINT subjects_display_name_format CHECK (
    display_name = btrim(display_name)
    AND length(display_name) BETWEEN 1 AND 120
  ),
  CONSTRAINT subjects_version_positive CHECK (version > 0),
  CONSTRAINT subjects_timestamps_ordered CHECK (updated_at >= created_at)
);

CREATE TABLE identity.tenant_memberships (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  state identity.membership_state NOT NULL DEFAULT 'active',
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenant_memberships_pk PRIMARY KEY (tenant_id, subject_id),
  CONSTRAINT tenant_memberships_tenant_fk FOREIGN KEY (tenant_id)
    REFERENCES identity.tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT tenant_memberships_subject_fk FOREIGN KEY (subject_id)
    REFERENCES identity.subjects (subject_id) ON DELETE RESTRICT,
  CONSTRAINT tenant_memberships_version_positive CHECK (version > 0),
  CONSTRAINT tenant_memberships_timestamps_ordered CHECK (updated_at >= created_at)
);

CREATE INDEX tenant_memberships_subject_lookup
  ON identity.tenant_memberships (subject_id, tenant_id);

CREATE TABLE identity.platform_role_assignments (
  subject_id identity.subject_id NOT NULL,
  role_name identity.platform_role_name NOT NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT platform_role_assignments_pk PRIMARY KEY (subject_id, role_name),
  CONSTRAINT platform_role_assignments_subject_fk FOREIGN KEY (subject_id)
    REFERENCES identity.subjects (subject_id) ON DELETE RESTRICT
);

CREATE TABLE identity.tenant_role_assignments (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  role_name identity.tenant_role_name NOT NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenant_role_assignments_pk PRIMARY KEY (tenant_id, subject_id, role_name),
  CONSTRAINT tenant_role_assignments_membership_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT
);

COMMENT ON DOMAIN identity.tenant_id IS 'Opaque tenant identifier matching the shared contract tnt_UUID format';
COMMENT ON DOMAIN identity.subject_id IS 'Opaque subject identifier matching the shared contract sub_UUID format';
COMMENT ON TABLE identity.tenants IS 'Authoritative tenant lifecycle records';
COMMENT ON TABLE identity.subjects IS 'Platform identities; a subject has no tenant authority without a tenant membership';
COMMENT ON TABLE identity.tenant_memberships IS 'Tenant-qualified subject memberships; tenant authorization starts from this composite key';
COMMENT ON TABLE identity.platform_role_assignments IS 'Platform-wide operational roles; these roles do not grant tenant business-data access';
COMMENT ON TABLE identity.tenant_role_assignments IS 'Roles attached to one tenant membership only';
