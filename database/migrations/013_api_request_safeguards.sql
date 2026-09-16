CREATE TABLE audit.api_sensitive_operation_receipts (
  tenant_id identity.tenant_id NOT NULL,
  actor_subject_id identity.subject_id NOT NULL,
  action text NOT NULL,
  idempotency_key_hash_sha256 text NOT NULL,
  request_hash_sha256 text NOT NULL,
  operation_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, actor_subject_id, action, idempotency_key_hash_sha256),
  CONSTRAINT api_sensitive_operation_receipts_membership_fk
    FOREIGN KEY (tenant_id, actor_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id)
    ON DELETE RESTRICT,
  CONSTRAINT api_sensitive_operation_receipts_action_format CHECK (
    action IN ('record:export', 'tenant:admin')
  ),
  CONSTRAINT api_sensitive_operation_receipts_key_hash_format CHECK (
    idempotency_key_hash_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT api_sensitive_operation_receipts_request_hash_format CHECK (
    request_hash_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT api_sensitive_operation_receipts_operation_id_format CHECK (
    operation_id ~ '^op_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CONSTRAINT api_sensitive_operation_receipts_operation_id_unique UNIQUE (operation_id)
);

CREATE INDEX api_sensitive_operation_receipts_created
  ON audit.api_sensitive_operation_receipts (tenant_id, created_at, operation_id);

CREATE FUNCTION audit.reserve_api_sensitive_operation(
  p_tenant_id text,
  p_actor_subject_id text,
  p_action text,
  p_idempotency_key_hash_sha256 text,
  p_request_hash_sha256 text,
  p_candidate_operation_id text
)
RETURNS TABLE (operation_id text, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity
SET row_security = off
AS $function$
DECLARE
  existing audit.api_sensitive_operation_receipts%ROWTYPE;
BEGIN
  INSERT INTO audit.api_sensitive_operation_receipts (
    tenant_id,
    actor_subject_id,
    action,
    idempotency_key_hash_sha256,
    request_hash_sha256,
    operation_id
  ) VALUES (
    p_tenant_id::identity.tenant_id,
    p_actor_subject_id::identity.subject_id,
    p_action,
    p_idempotency_key_hash_sha256,
    p_request_hash_sha256,
    p_candidate_operation_id
  )
  ON CONFLICT (tenant_id, actor_subject_id, action, idempotency_key_hash_sha256)
  DO NOTHING
  RETURNING * INTO existing;

  IF FOUND THEN
    RETURN QUERY SELECT existing.operation_id, false;
    RETURN;
  END IF;

  SELECT receipt.*
  INTO STRICT existing
  FROM audit.api_sensitive_operation_receipts AS receipt
  WHERE receipt.tenant_id = p_tenant_id::identity.tenant_id
    AND receipt.actor_subject_id = p_actor_subject_id::identity.subject_id
    AND receipt.action = p_action
    AND receipt.idempotency_key_hash_sha256 = p_idempotency_key_hash_sha256
  FOR UPDATE;

  IF existing.request_hash_sha256 <> p_request_hash_sha256 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001',
      MESSAGE = 'SENSITIVE_OPERATION_IDEMPOTENCY_CONFLICT';
  END IF;

  RETURN QUERY SELECT existing.operation_id, true;
END
$function$;

REVOKE ALL ON TABLE audit.api_sensitive_operation_receipts FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION audit.reserve_api_sensitive_operation(text, text, text, text, text, text)
  FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit.reserve_api_sensitive_operation(text, text, text, text, text, text)
  TO tenant_trust_app;

COMMENT ON TABLE audit.api_sensitive_operation_receipts IS
  'Append-only tenant-, actor- and action-scoped sensitive-operation replay receipts; client keys and payloads are retained only as SHA-256 digests';
COMMENT ON FUNCTION audit.reserve_api_sensitive_operation(text, text, text, text, text, text) IS
  'Atomically creates or replays a sensitive operation identity and rejects conflicting reuse';
