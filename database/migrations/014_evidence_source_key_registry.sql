CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE DOMAIN trust.evidence_source_key_id AS text
  CHECK (VALUE ~ '^key_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN trust.ed25519_public_key_base64url AS text
  CHECK (VALUE ~ '^[A-Za-z0-9_-]{43}$');

CREATE TYPE trust.evidence_source_key_state AS ENUM ('active', 'rotated', 'revoked');

CREATE FUNCTION trust.ed25519_public_key_sha256(p_public_key trust.ed25519_public_key_base64url)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $function$
  SELECT encode(public.digest(decode(translate(p_public_key::text, '-_', '+/') || '=', 'base64'), 'sha256'), 'hex')
$function$;

CREATE TABLE trust.evidence_source_keys (
  tenant_id identity.tenant_id NOT NULL,
  source_id trust.source_id NOT NULL,
  key_id trust.evidence_source_key_id NOT NULL,
  key_version integer NOT NULL,
  algorithm text NOT NULL DEFAULT 'Ed25519',
  public_key_base64url trust.ed25519_public_key_base64url NOT NULL,
  public_key_sha256 text NOT NULL,
  state trust.evidence_source_key_state NOT NULL DEFAULT 'active',
  enrolled_by_subject_id identity.subject_id NOT NULL,
  enrolled_at timestamptz NOT NULL,
  rotated_by_subject_id identity.subject_id,
  rotated_at timestamptz,
  revoked_by_subject_id identity.subject_id,
  revoked_at timestamptz,
  revocation_reason_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT evidence_source_keys_pk PRIMARY KEY (tenant_id, source_id, key_id),
  CONSTRAINT evidence_source_keys_source_fk FOREIGN KEY (tenant_id, source_id)
    REFERENCES trust.evidence_sources (tenant_id, source_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_source_keys_enroller_fk FOREIGN KEY (tenant_id, enrolled_by_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_source_keys_rotator_fk FOREIGN KEY (tenant_id, rotated_by_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_source_keys_revoker_fk FOREIGN KEY (tenant_id, revoked_by_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_source_keys_version_unique UNIQUE (tenant_id, source_id, key_version),
  CONSTRAINT evidence_source_keys_material_unique UNIQUE (tenant_id, source_id, public_key_sha256),
  CONSTRAINT evidence_source_keys_version_positive CHECK (key_version > 0),
  CONSTRAINT evidence_source_keys_algorithm CHECK (algorithm = 'Ed25519'),
  CONSTRAINT evidence_source_keys_material_length CHECK (
    octet_length(decode(translate(public_key_base64url::text, '-_', '+/') || '=', 'base64')) = 32
  ),
  CONSTRAINT evidence_source_keys_fingerprint_matches CHECK (
    public_key_sha256 = trust.ed25519_public_key_sha256(public_key_base64url)
  ),
  CONSTRAINT evidence_source_keys_reason_format CHECK (
    revocation_reason_code IS NULL OR revocation_reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT evidence_source_keys_state_shape CHECK (
    (
      state = 'active'
      AND rotated_by_subject_id IS NULL
      AND rotated_at IS NULL
      AND revoked_by_subject_id IS NULL
      AND revoked_at IS NULL
      AND revocation_reason_code IS NULL
    )
    OR (
      state = 'rotated'
      AND rotated_by_subject_id IS NOT NULL
      AND rotated_at IS NOT NULL
      AND revoked_by_subject_id IS NULL
      AND revoked_at IS NULL
      AND revocation_reason_code IS NULL
    )
    OR (
      state = 'revoked'
      AND revoked_by_subject_id IS NOT NULL
      AND revoked_at IS NOT NULL
      AND revocation_reason_code IS NOT NULL
    )
  ),
  CONSTRAINT evidence_source_keys_time_order CHECK (
    created_at <= updated_at
    AND enrolled_at <= created_at + interval '2 seconds'
    AND (rotated_at IS NULL OR rotated_at >= enrolled_at)
    AND (revoked_at IS NULL OR revoked_at >= enrolled_at)
  )
);

CREATE UNIQUE INDEX evidence_source_keys_one_active
  ON trust.evidence_source_keys (tenant_id, source_id)
  WHERE state = 'active';

CREATE INDEX evidence_source_keys_verification_lookup
  ON trust.evidence_source_keys (tenant_id, source_id, key_id, state);

CREATE FUNCTION trust.prevent_evidence_source_key_history_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Evidence source key history is append-only.';
  END IF;

  IF (
    to_jsonb(NEW) - ARRAY[
      'state', 'rotated_by_subject_id', 'rotated_at', 'revoked_by_subject_id',
      'revoked_at', 'revocation_reason_code', 'updated_at'
    ]
  ) IS DISTINCT FROM (
    to_jsonb(OLD) - ARRAY[
      'state', 'rotated_by_subject_id', 'rotated_at', 'revoked_by_subject_id',
      'revoked_at', 'revocation_reason_code', 'updated_at'
    ]
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Evidence source key identity and public material are immutable.';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER evidence_source_keys_keep_history
BEFORE UPDATE OR DELETE ON trust.evidence_source_keys
FOR EACH ROW EXECUTE FUNCTION trust.prevent_evidence_source_key_history_rewrite();

CREATE FUNCTION trust.prevent_evidence_source_registry_bypass()
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
       ) THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source lifecycle changes must use the key registry.';
    END IF;

    IF TG_OP = 'DELETE' AND EXISTS (
      SELECT 1 FROM trust.evidence_source_keys AS source_key
      WHERE source_key.tenant_id = OLD.tenant_id AND source_key.source_id = OLD.source_id
    ) THEN
      RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Enrolled evidence source history is append-only.';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER evidence_sources_use_key_registry
BEFORE INSERT OR UPDATE OR DELETE ON trust.evidence_sources
FOR EACH ROW EXECUTE FUNCTION trust.prevent_evidence_source_registry_bypass();

CREATE FUNCTION trust.enroll_evidence_source(
  p_source_id trust.source_id,
  p_key_id trust.evidence_source_key_id,
  p_public_key trust.ed25519_public_key_base64url,
  p_enrolled_at timestamptz
)
RETURNS TABLE (
  enrolled_source_id trust.source_id,
  enrolled_key_id trust.evidence_source_key_id,
  enrolled_key_version integer,
  enrolled_key_sha256 text,
  enrolled_source_state trust.evidence_source_state,
  enrolled_source_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, identity, trust
SET row_security = off
AS $function$
DECLARE
  actor_tenant identity.tenant_id := identity.current_tenant_id();
  actor_id identity.subject_id := identity.current_subject_id();
  source_record trust.evidence_sources%ROWTYPE;
  key_fingerprint text;
BEGIN
  IF actor_tenant IS NULL OR actor_id IS NULL OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source enrollment denied.';
  END IF;
  IF p_enrolled_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Evidence source enrollment time is invalid.';
  END IF;

  SELECT * INTO source_record
  FROM trust.evidence_sources AS source
  WHERE source.tenant_id = actor_tenant AND source.source_id = p_source_id
  FOR UPDATE;

  IF NOT FOUND
     OR source_record.state <> 'planned'
     OR source_record.verification_algorithm <> 'ed25519'
     OR source_record.verification_key_sha256 IS NOT NULL
     OR EXISTS (
       SELECT 1 FROM trust.evidence_source_keys AS source_key
       WHERE source_key.tenant_id = actor_tenant AND source_key.source_id = p_source_id
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source enrollment denied.';
  END IF;

  key_fingerprint := trust.ed25519_public_key_sha256(p_public_key);
  INSERT INTO trust.evidence_source_keys (
    tenant_id, source_id, key_id, key_version, public_key_base64url,
    public_key_sha256, enrolled_by_subject_id, enrolled_at
  ) VALUES (
    actor_tenant, p_source_id, p_key_id, 1, p_public_key,
    key_fingerprint, actor_id, p_enrolled_at
  );

  UPDATE trust.evidence_sources
  SET state = 'active',
      verification_key_sha256 = key_fingerprint,
      version = version + 1,
      updated_at = GREATEST(clock_timestamp(), p_enrolled_at)
  WHERE tenant_id = actor_tenant AND source_id = p_source_id
  RETURNING version INTO source_record.version;

  RETURN QUERY SELECT p_source_id, p_key_id, 1, key_fingerprint,
    'active'::trust.evidence_source_state, source_record.version;
END
$function$;

CREATE FUNCTION trust.rotate_evidence_source_key(
  p_source_id trust.source_id,
  p_key_id trust.evidence_source_key_id,
  p_public_key trust.ed25519_public_key_base64url,
  p_rotated_at timestamptz
)
RETURNS TABLE (
  rotated_source_id trust.source_id,
  active_key_id trust.evidence_source_key_id,
  active_key_version integer,
  active_key_sha256 text,
  rotated_source_state trust.evidence_source_state,
  rotated_source_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, identity, trust
SET row_security = off
AS $function$
DECLARE
  actor_tenant identity.tenant_id := identity.current_tenant_id();
  actor_id identity.subject_id := identity.current_subject_id();
  source_record trust.evidence_sources%ROWTYPE;
  current_key trust.evidence_source_keys%ROWTYPE;
  next_key_version integer;
  key_fingerprint text;
BEGIN
  IF actor_tenant IS NULL OR actor_id IS NULL OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source key rotation denied.';
  END IF;
  IF p_rotated_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Evidence source key rotation time is invalid.';
  END IF;

  SELECT * INTO source_record
  FROM trust.evidence_sources AS source
  WHERE source.tenant_id = actor_tenant AND source.source_id = p_source_id
  FOR UPDATE;

  IF NOT FOUND
     OR source_record.state NOT IN ('active', 'suspended')
     OR source_record.verification_algorithm <> 'ed25519'
     OR NOT EXISTS (
       SELECT 1 FROM trust.evidence_source_keys AS source_key
       WHERE source_key.tenant_id = actor_tenant AND source_key.source_id = p_source_id
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source key rotation denied.';
  END IF;

  SELECT * INTO current_key
  FROM trust.evidence_source_keys AS source_key
  WHERE source_key.tenant_id = actor_tenant
    AND source_key.source_id = p_source_id
    AND source_key.state = 'active'
  FOR UPDATE;

  IF source_record.state = 'active' AND NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Evidence source active key state is inconsistent.';
  END IF;
  IF FOUND AND p_rotated_at < current_key.enrolled_at THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Evidence source key rotation time is invalid.';
  END IF;

  IF current_key.key_id IS NOT NULL THEN
    UPDATE trust.evidence_source_keys
    SET state = 'rotated',
        rotated_by_subject_id = actor_id,
        rotated_at = p_rotated_at,
        updated_at = GREATEST(clock_timestamp(), p_rotated_at)
    WHERE tenant_id = actor_tenant AND source_id = p_source_id AND key_id = current_key.key_id;
  END IF;

  SELECT max(source_key.key_version) + 1 INTO next_key_version
  FROM trust.evidence_source_keys AS source_key
  WHERE source_key.tenant_id = actor_tenant AND source_key.source_id = p_source_id;

  key_fingerprint := trust.ed25519_public_key_sha256(p_public_key);
  INSERT INTO trust.evidence_source_keys (
    tenant_id, source_id, key_id, key_version, public_key_base64url,
    public_key_sha256, enrolled_by_subject_id, enrolled_at
  ) VALUES (
    actor_tenant, p_source_id, p_key_id, next_key_version, p_public_key,
    key_fingerprint, actor_id, p_rotated_at
  );

  UPDATE trust.evidence_sources
  SET state = 'active',
      verification_key_sha256 = key_fingerprint,
      version = version + 1,
      updated_at = GREATEST(clock_timestamp(), p_rotated_at)
  WHERE tenant_id = actor_tenant AND source_id = p_source_id
  RETURNING version INTO source_record.version;

  RETURN QUERY SELECT p_source_id, p_key_id, next_key_version, key_fingerprint,
    'active'::trust.evidence_source_state, source_record.version;
END
$function$;

CREATE FUNCTION trust.revoke_evidence_source_key(
  p_source_id trust.source_id,
  p_key_id trust.evidence_source_key_id,
  p_reason_code text,
  p_revoked_at timestamptz
)
RETURNS TABLE (
  revoked_source_id trust.source_id,
  revoked_key_id trust.evidence_source_key_id,
  revoked_key_version integer,
  revoked_key_state trust.evidence_source_key_state,
  resulting_source_state trust.evidence_source_state,
  resulting_source_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, identity, trust
SET row_security = off
AS $function$
DECLARE
  actor_tenant identity.tenant_id := identity.current_tenant_id();
  actor_id identity.subject_id := identity.current_subject_id();
  source_record trust.evidence_sources%ROWTYPE;
  target_key trust.evidence_source_keys%ROWTYPE;
  next_source_state trust.evidence_source_state;
BEGIN
  IF actor_tenant IS NULL OR actor_id IS NULL OR NOT identity.current_actor_is_tenant_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source key revocation denied.';
  END IF;
  IF p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_revoked_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Evidence source key revocation input is invalid.';
  END IF;

  SELECT * INTO source_record
  FROM trust.evidence_sources AS source
  WHERE source.tenant_id = actor_tenant AND source.source_id = p_source_id
  FOR UPDATE;

  SELECT * INTO target_key
  FROM trust.evidence_source_keys AS source_key
  WHERE source_key.tenant_id = actor_tenant
    AND source_key.source_id = p_source_id
    AND source_key.key_id = p_key_id
  FOR UPDATE;

  IF source_record.source_id IS NULL
     OR target_key.key_id IS NULL
     OR target_key.state = 'revoked'
     OR p_revoked_at < target_key.enrolled_at THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evidence source key revocation denied.';
  END IF;

  UPDATE trust.evidence_source_keys
  SET state = 'revoked',
      revoked_by_subject_id = actor_id,
      revoked_at = p_revoked_at,
      revocation_reason_code = p_reason_code,
      updated_at = GREATEST(clock_timestamp(), p_revoked_at)
  WHERE tenant_id = actor_tenant AND source_id = p_source_id AND key_id = p_key_id;

  next_source_state := source_record.state;
  IF target_key.state = 'active' THEN
    next_source_state := 'suspended';
    UPDATE trust.evidence_sources
    SET state = next_source_state,
        verification_key_sha256 = NULL,
        version = version + 1,
        updated_at = GREATEST(clock_timestamp(), p_revoked_at)
    WHERE tenant_id = actor_tenant AND source_id = p_source_id
    RETURNING version INTO source_record.version;
  ELSE
    UPDATE trust.evidence_sources
    SET version = version + 1,
        updated_at = GREATEST(clock_timestamp(), p_revoked_at)
    WHERE tenant_id = actor_tenant AND source_id = p_source_id
    RETURNING version INTO source_record.version;
  END IF;

  RETURN QUERY SELECT p_source_id, p_key_id, target_key.key_version,
    'revoked'::trust.evidence_source_key_state, next_source_state, source_record.version;
END
$function$;

ALTER TABLE trust.evidence_source_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.evidence_source_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY evidence_source_keys_current_actor_select
  ON trust.evidence_source_keys FOR SELECT TO tenant_trust_app
  USING (tenant_id = identity.current_tenant_id() AND identity.current_actor_is_active());

REVOKE ALL ON TABLE trust.evidence_source_keys FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION trust.ed25519_public_key_sha256(trust.ed25519_public_key_base64url) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.prevent_evidence_source_key_history_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.prevent_evidence_source_registry_bypass() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.enroll_evidence_source(
  trust.source_id, trust.evidence_source_key_id, trust.ed25519_public_key_base64url, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.rotate_evidence_source_key(
  trust.source_id, trust.evidence_source_key_id, trust.ed25519_public_key_base64url, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.revoke_evidence_source_key(
  trust.source_id, trust.evidence_source_key_id, text, timestamptz
) FROM PUBLIC;

GRANT SELECT ON trust.evidence_source_keys TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.enroll_evidence_source(
  trust.source_id, trust.evidence_source_key_id, trust.ed25519_public_key_base64url, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.rotate_evidence_source_key(
  trust.source_id, trust.evidence_source_key_id, trust.ed25519_public_key_base64url, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.revoke_evidence_source_key(
  trust.source_id, trust.evidence_source_key_id, text, timestamptz
) TO tenant_trust_app;

COMMENT ON TABLE trust.evidence_source_keys IS
  'Append-only tenant/source-bound Ed25519 public-key history used to verify signed evidence across rotations and revocations';
COMMENT ON FUNCTION trust.enroll_evidence_source(
  trust.source_id, trust.evidence_source_key_id, trust.ed25519_public_key_base64url, timestamptz
) IS 'Activates a pre-authorized tenant evidence source with its first Ed25519 verification key';
COMMENT ON FUNCTION trust.rotate_evidence_source_key(
  trust.source_id, trust.evidence_source_key_id, trust.ed25519_public_key_base64url, timestamptz
) IS 'Ends the current source key epoch and appends a new active Ed25519 verification key';
COMMENT ON FUNCTION trust.revoke_evidence_source_key(
  trust.source_id, trust.evidence_source_key_id, text, timestamptz
) IS 'Revokes a retained source key; revoking the active key suspends the evidence source';
