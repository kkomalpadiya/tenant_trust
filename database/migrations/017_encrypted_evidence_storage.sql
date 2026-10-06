CREATE TYPE trust.evidence_storage_state AS ENUM ('active', 'deleted');

CREATE TABLE trust.encrypted_evidence (
  tenant_id identity.tenant_id NOT NULL,
  event_id trust.evidence_event_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  source_id trust.source_id NOT NULL,
  content_hash_sha256 text NOT NULL,
  format_version smallint NOT NULL,
  cipher text,
  encryption_key_id text,
  iv bytea,
  authentication_tag bytea,
  ciphertext bytea,
  canonical_sha256 text NOT NULL,
  canonical_byte_length integer NOT NULL,
  retained_until timestamptz NOT NULL,
  state trust.evidence_storage_state NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  deleted_at timestamptz,
  deletion_reason text,
  CONSTRAINT encrypted_evidence_pk PRIMARY KEY (tenant_id, event_id),
  CONSTRAINT encrypted_evidence_receipt_fk FOREIGN KEY (tenant_id, event_id)
    REFERENCES trust.evidence_ingestion_receipts (tenant_id, event_id) ON DELETE RESTRICT,
  CONSTRAINT encrypted_evidence_subject_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT encrypted_evidence_source_fk FOREIGN KEY (tenant_id, source_id)
    REFERENCES trust.evidence_sources (tenant_id, source_id) ON DELETE RESTRICT,
  CONSTRAINT encrypted_evidence_content_hash CHECK (content_hash_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT encrypted_evidence_canonical_hash CHECK (canonical_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT encrypted_evidence_format CHECK (format_version = 1),
  CONSTRAINT encrypted_evidence_size CHECK (canonical_byte_length BETWEEN 1 AND 65536),
  CONSTRAINT encrypted_evidence_retention CHECK (retained_until > created_at),
  CONSTRAINT encrypted_evidence_shape CHECK (
    (
      state = 'active'
      AND cipher = 'AES-256-GCM'
      AND encryption_key_id ~ '^[a-z0-9][a-z0-9._-]{2,63}$'
      AND octet_length(iv) = 12
      AND octet_length(authentication_tag) = 16
      AND octet_length(ciphertext) = canonical_byte_length
      AND deleted_at IS NULL
      AND deletion_reason IS NULL
    ) OR (
      state = 'deleted'
      AND cipher IS NULL
      AND encryption_key_id IS NULL
      AND iv IS NULL
      AND authentication_tag IS NULL
      AND ciphertext IS NULL
      AND deleted_at IS NOT NULL
      AND deletion_reason IS NOT NULL
    )
  )
);

CREATE INDEX encrypted_evidence_retention_lookup
  ON trust.encrypted_evidence (tenant_id, retained_until, event_id)
  WHERE state = 'active';

ALTER TABLE trust.encrypted_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.encrypted_evidence FORCE ROW LEVEL SECURITY;

CREATE FUNCTION trust.store_encrypted_evidence(
  p_tenant_id identity.tenant_id,
  p_event_id trust.evidence_event_id,
  p_format_version smallint,
  p_encryption_key_id text,
  p_iv bytea,
  p_authentication_tag bytea,
  p_ciphertext bytea,
  p_canonical_sha256 text,
  p_canonical_byte_length integer
)
RETURNS TABLE (retained_until timestamptz)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  receipt trust.evidence_ingestion_receipts%ROWTYPE;
  retention_deadline timestamptz;
BEGIN
  SELECT * INTO STRICT receipt
  FROM trust.evidence_ingestion_receipts
  WHERE tenant_id = p_tenant_id AND event_id = p_event_id;

  retention_deadline := receipt.accepted_at + interval '30 days';
  INSERT INTO trust.encrypted_evidence (
    tenant_id, event_id, subject_id, source_id, content_hash_sha256,
    format_version, cipher, encryption_key_id, iv, authentication_tag,
    ciphertext, canonical_sha256, canonical_byte_length, retained_until, created_at
  ) VALUES (
    receipt.tenant_id, receipt.event_id, receipt.subject_id, receipt.source_id,
    receipt.content_hash_sha256, p_format_version, 'AES-256-GCM', p_encryption_key_id,
    p_iv, p_authentication_tag, p_ciphertext, p_canonical_sha256,
    p_canonical_byte_length, retention_deadline, receipt.accepted_at
  );
  RETURN QUERY SELECT retention_deadline;
EXCEPTION
  WHEN no_data_found THEN
    RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Accepted evidence receipt not found.';
END
$function$;

CREATE FUNCTION trust.require_encrypted_evidence_for_receipt()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, trust
SET row_security = off
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM trust.encrypted_evidence AS stored
    WHERE stored.tenant_id = NEW.tenant_id AND stored.event_id = NEW.event_id
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'Accepted evidence requires encrypted off-chain storage.';
  END IF;
  RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER evidence_receipt_requires_encrypted_storage
AFTER INSERT ON trust.evidence_ingestion_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION trust.require_encrypted_evidence_for_receipt();

CREATE FUNCTION trust.retrieve_encrypted_evidence(p_event_id trust.evidence_event_id)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  event_id trust.evidence_event_id,
  subject_id identity.subject_id,
  source_id trust.source_id,
  content_hash_sha256 text,
  format_version smallint,
  cipher text,
  encryption_key_id text,
  iv bytea,
  authentication_tag bytea,
  ciphertext bytea,
  canonical_sha256 text,
  canonical_byte_length integer,
  retained_until timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
  SELECT stored.tenant_id, stored.event_id, stored.subject_id, stored.source_id,
         stored.content_hash_sha256, stored.format_version, stored.cipher,
         stored.encryption_key_id, stored.iv, stored.authentication_tag,
         stored.ciphertext, stored.canonical_sha256, stored.canonical_byte_length,
         stored.retained_until
  FROM trust.encrypted_evidence AS stored
  WHERE stored.tenant_id = identity.current_tenant_id()
    AND stored.event_id = p_event_id
    AND stored.state = 'active'
    AND stored.retained_until > clock_timestamp()
    AND identity.current_actor_is_active()
    AND (
      stored.subject_id = identity.current_subject_id()
      OR identity.current_actor_is_tenant_admin()
    )
$function$;

CREATE FUNCTION trust.delete_encrypted_evidence(
  p_event_id trust.evidence_event_id,
  p_reason text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
BEGIN
  IF NOT identity.current_actor_is_tenant_admin()
    OR p_reason IS NULL
    OR p_reason <> btrim(p_reason)
    OR length(p_reason) NOT BETWEEN 1 AND 160 THEN
    RETURN FALSE;
  END IF;

  UPDATE trust.encrypted_evidence
  SET state = 'deleted',
      cipher = NULL,
      encryption_key_id = NULL,
      iv = NULL,
      authentication_tag = NULL,
      ciphertext = NULL,
      deleted_at = clock_timestamp(),
      deletion_reason = p_reason
  WHERE tenant_id = identity.current_tenant_id()
    AND event_id = p_event_id
    AND state = 'active';
  RETURN FOUND;
END
$function$;

CREATE FUNCTION trust.purge_expired_evidence()
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  purged bigint;
BEGIN
  IF NOT identity.current_actor_is_tenant_admin() THEN RETURN 0; END IF;
  UPDATE trust.encrypted_evidence
  SET state = 'deleted',
      cipher = NULL,
      encryption_key_id = NULL,
      iv = NULL,
      authentication_tag = NULL,
      ciphertext = NULL,
      deleted_at = clock_timestamp(),
      deletion_reason = 'RETENTION_EXPIRED'
  WHERE tenant_id = identity.current_tenant_id()
    AND state = 'active'
    AND retained_until <= clock_timestamp();
  GET DIAGNOSTICS purged = ROW_COUNT;
  RETURN purged;
END
$function$;

REVOKE ALL ON TABLE trust.encrypted_evidence FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION trust.store_encrypted_evidence(
  identity.tenant_id, trust.evidence_event_id, smallint, text, bytea, bytea, bytea, text, integer
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.require_encrypted_evidence_for_receipt() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.retrieve_encrypted_evidence(trust.evidence_event_id) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.delete_encrypted_evidence(trust.evidence_event_id, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.purge_expired_evidence() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust.store_encrypted_evidence(
  identity.tenant_id, trust.evidence_event_id, smallint, text, bytea, bytea, bytea, text, integer
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.retrieve_encrypted_evidence(trust.evidence_event_id) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.delete_encrypted_evidence(trust.evidence_event_id, text) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.purge_expired_evidence() TO tenant_trust_app;

COMMENT ON TABLE trust.encrypted_evidence IS
  'Application-encrypted canonical evidence bytes stored off-chain with tenant-scoped access, fixed retention and deletion tombstones';
COMMENT ON FUNCTION trust.store_encrypted_evidence(
  identity.tenant_id, trust.evidence_event_id, smallint, text, bytea, bytea, bytea, text, integer
) IS 'Stores AES-256-GCM ciphertext for an accepted evidence receipt in the same transaction';
COMMENT ON FUNCTION trust.retrieve_encrypted_evidence(trust.evidence_event_id) IS
  'Returns active encrypted evidence only to its active subject owner or an active tenant administrator';
COMMENT ON FUNCTION trust.delete_encrypted_evidence(trust.evidence_event_id, text) IS
  'Tenant-admin deletion removes ciphertext and key material while retaining a bounded tombstone';
COMMENT ON FUNCTION trust.purge_expired_evidence() IS
  'Tenant-admin retention sweep removes expired ciphertext and key material for the current tenant';
