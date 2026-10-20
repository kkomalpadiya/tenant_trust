CREATE DOMAIN audit.policy_decision_id AS text
  CHECK (VALUE ~ '^dec_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN audit.security_action_id AS text
  CHECK (VALUE ~ '^act_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TYPE audit.quarantine_action_type AS ENUM ('restrict-access', 'suspend-subject');

CREATE TABLE audit.security_action_requests (
  tenant_id identity.tenant_id NOT NULL,
  action_id audit.security_action_id NOT NULL,
  decision_id audit.policy_decision_id NOT NULL,
  request_id identity.request_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  actor_subject_id identity.subject_id NOT NULL,
  target_subject_id identity.subject_id NOT NULL,
  target_certificate_id identity.certificate_id NOT NULL,
  policy_action text NOT NULL,
  action_type audit.quarantine_action_type NOT NULL,
  status text NOT NULL DEFAULT 'requested',
  reason_code text NOT NULL,
  resource_id_hash_sha256 identity.sha256_digest NOT NULL,
  trust_transition_id trust.transition_id NOT NULL,
  policy_version_id trust.policy_version_id NOT NULL,
  policy_input_hash_sha256 identity.sha256_digest NOT NULL,
  requested_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT security_action_requests_pk PRIMARY KEY (tenant_id, action_id),
  CONSTRAINT security_action_requests_decision_unique UNIQUE (tenant_id, decision_id, action_type),
  CONSTRAINT security_action_requests_request_unique UNIQUE (tenant_id, request_id, action_type),
  CONSTRAINT security_action_requests_actor_fk FOREIGN KEY (tenant_id, actor_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT security_action_requests_target_fk FOREIGN KEY (tenant_id, target_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT security_action_requests_certificate_fk FOREIGN KEY (tenant_id, target_certificate_id)
    REFERENCES identity.certificates (tenant_id, certificate_id) ON DELETE RESTRICT,
  CONSTRAINT security_action_requests_transition_fk FOREIGN KEY (tenant_id, trust_transition_id)
    REFERENCES trust.subject_trust_transitions (tenant_id, transition_id) ON DELETE RESTRICT,
  CONSTRAINT security_action_requests_policy_version_fk FOREIGN KEY (tenant_id, policy_version_id)
    REFERENCES trust.policy_versions (tenant_id, policy_version_id) ON DELETE RESTRICT,
  CONSTRAINT security_action_requests_policy_action CHECK (
    policy_action IN (
      'profile:read', 'record:read', 'record:write', 'record:export',
      'tenant:admin', 'member:manage', 'certificate:manage', 'admin-key:rotate'
    )
  ),
  CONSTRAINT security_action_requests_status CHECK (status = 'requested'),
  CONSTRAINT security_action_requests_reason CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  CONSTRAINT security_action_requests_self_target CHECK (target_subject_id = actor_subject_id),
  CONSTRAINT security_action_requests_time CHECK (
    requested_at <= created_at + interval '2 seconds'
    AND requested_at >= created_at - interval '5 minutes'
  )
);

CREATE INDEX security_action_requests_correlation_lookup
  ON audit.security_action_requests (tenant_id, correlation_id, requested_at DESC);

CREATE FUNCTION audit.prevent_security_action_request_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, audit
AS $function$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Security action requests are append-only.';
END
$function$;

CREATE TRIGGER security_action_requests_append_only
BEFORE UPDATE OR DELETE ON audit.security_action_requests
FOR EACH ROW EXECUTE FUNCTION audit.prevent_security_action_request_rewrite();

ALTER TABLE audit.security_action_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.security_action_requests FORCE ROW LEVEL SECURITY;

CREATE FUNCTION audit.request_quarantine_action(
  p_action_id audit.security_action_id,
  p_decision_id audit.policy_decision_id,
  p_request_id identity.request_id,
  p_correlation_id identity.correlation_id,
  p_target_certificate_id identity.certificate_id,
  p_policy_action text,
  p_action_type audit.quarantine_action_type,
  p_reason_code text,
  p_resource_id_hash_sha256 identity.sha256_digest,
  p_trust_transition_id trust.transition_id,
  p_policy_version_id trust.policy_version_id,
  p_policy_input_hash_sha256 identity.sha256_digest,
  p_requested_at timestamptz
)
RETURNS audit.security_action_requests
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, audit
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_subject_id identity.subject_id := identity.current_subject_id();
  v_existing audit.security_action_requests%ROWTYPE;
  v_created audit.security_action_requests%ROWTYPE;
BEGIN
  IF v_tenant_id IS NULL OR v_subject_id IS NULL OR NOT identity.current_actor_is_active()
     OR p_policy_action NOT IN (
       'profile:read', 'record:read', 'record:write', 'record:export',
       'tenant:admin', 'member:manage', 'certificate:manage', 'admin-key:rotate'
     )
     OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_requested_at IS NULL
     OR p_requested_at > clock_timestamp() + interval '2 seconds'
     OR p_requested_at < clock_timestamp() - interval '5 minutes'
     OR NOT EXISTS (
       SELECT 1 FROM identity.certificates AS certificate
       WHERE certificate.tenant_id = v_tenant_id
         AND certificate.subject_id = v_subject_id
         AND certificate.certificate_id = p_target_certificate_id
         AND certificate.state = 'active'
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Quarantine action request denied.';
  END IF;

  SELECT * INTO v_existing
  FROM audit.security_action_requests AS request
  WHERE request.tenant_id = v_tenant_id
    AND request.decision_id = p_decision_id
    AND request.action_type = p_action_type;
  IF FOUND THEN
    IF v_existing.request_id <> p_request_id
       OR v_existing.correlation_id <> p_correlation_id
       OR v_existing.actor_subject_id <> v_subject_id
       OR v_existing.target_subject_id <> v_subject_id
       OR v_existing.target_certificate_id <> p_target_certificate_id
       OR v_existing.policy_action <> p_policy_action
       OR v_existing.reason_code <> p_reason_code
       OR v_existing.resource_id_hash_sha256 <> p_resource_id_hash_sha256
       OR v_existing.trust_transition_id <> p_trust_transition_id
       OR v_existing.policy_version_id <> p_policy_version_id
       OR v_existing.policy_input_hash_sha256 <> p_policy_input_hash_sha256 THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'QUARANTINE_ACTION_IDEMPOTENCY_CONFLICT';
    END IF;
    RETURN v_existing;
  END IF;

  INSERT INTO audit.security_action_requests (
    tenant_id, action_id, decision_id, request_id, correlation_id,
    actor_subject_id, target_subject_id, target_certificate_id,
    policy_action, action_type, reason_code, resource_id_hash_sha256,
    trust_transition_id, policy_version_id, policy_input_hash_sha256, requested_at
  ) VALUES (
    v_tenant_id, p_action_id, p_decision_id, p_request_id, p_correlation_id,
    v_subject_id, v_subject_id, p_target_certificate_id,
    p_policy_action, p_action_type, p_reason_code, p_resource_id_hash_sha256,
    p_trust_transition_id, p_policy_version_id, p_policy_input_hash_sha256, p_requested_at
  ) RETURNING * INTO v_created;
  RETURN v_created;
END
$function$;

REVOKE ALL ON TABLE audit.security_action_requests FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION audit.prevent_security_action_request_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.request_quarantine_action(
  audit.security_action_id, audit.policy_decision_id, identity.request_id,
  identity.correlation_id, identity.certificate_id, text,
  audit.quarantine_action_type, text, identity.sha256_digest,
  trust.transition_id, trust.policy_version_id, identity.sha256_digest, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.request_quarantine_action(
  audit.security_action_id, audit.policy_decision_id, identity.request_id,
  identity.correlation_id, identity.certificate_id, text,
  audit.quarantine_action_type, text, identity.sha256_digest,
  trust.transition_id, trust.policy_version_id, identity.sha256_digest, timestamptz
) TO tenant_trust_app;

COMMENT ON TABLE audit.security_action_requests IS
  'Append-only, idempotent quarantine requests emitted from bound OPA decisions before protected access is denied';
