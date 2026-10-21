CREATE TYPE audit.policy_decision_outcome AS ENUM ('ALLOW', 'STEP_UP', 'DENY', 'QUARANTINE');

CREATE TABLE audit.policy_decision_provenance (
  tenant_id identity.tenant_id NOT NULL,
  decision_id audit.policy_decision_id NOT NULL,
  request_id identity.request_id NOT NULL,
  correlation_id identity.correlation_id NOT NULL,
  actor_subject_id identity.subject_id NOT NULL,
  certificate_id identity.certificate_id NOT NULL,
  certificate_status_version bigint NOT NULL,
  tenant_version bigint NOT NULL,
  subject_version bigint NOT NULL,
  membership_version bigint NOT NULL,
  policy_action text NOT NULL,
  resource_type text NOT NULL,
  resource_sensitivity text NOT NULL,
  resource_id_hash_sha256 identity.sha256_digest NOT NULL,
  outcome audit.policy_decision_outcome NOT NULL,
  reason_codes jsonb NOT NULL,
  trust_transition_id trust.transition_id,
  trust_update_version bigint,
  trust_model_version text,
  trust_configuration_version integer,
  trust_explanation_hash_sha256 identity.sha256_digest,
  policy_version_id trust.policy_version_id NOT NULL,
  policy_bundle_version integer NOT NULL,
  policy_bundle_hash_sha256 identity.sha256_digest NOT NULL,
  policy_decision_path text NOT NULL,
  policy_input_hash_sha256 identity.sha256_digest NOT NULL,
  canonicalization_profile text NOT NULL,
  provenance_canonical_json text NOT NULL,
  provenance_document jsonb NOT NULL,
  provenance_hash_sha256 identity.sha256_digest NOT NULL,
  requested_at timestamptz NOT NULL,
  evaluated_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT policy_decision_provenance_pk PRIMARY KEY (tenant_id, decision_id),
  CONSTRAINT policy_decision_provenance_request_unique UNIQUE (tenant_id, request_id),
  CONSTRAINT policy_decision_provenance_actor_fk
    FOREIGN KEY (tenant_id, actor_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT policy_decision_provenance_certificate_fk
    FOREIGN KEY (tenant_id, certificate_id)
    REFERENCES identity.certificates (tenant_id, certificate_id) ON DELETE RESTRICT,
  CONSTRAINT policy_decision_provenance_transition_fk
    FOREIGN KEY (tenant_id, trust_transition_id)
    REFERENCES trust.subject_trust_transitions (tenant_id, transition_id) ON DELETE RESTRICT,
  CONSTRAINT policy_decision_provenance_policy_fk
    FOREIGN KEY (tenant_id, policy_version_id)
    REFERENCES trust.policy_versions (tenant_id, policy_version_id) ON DELETE RESTRICT,
  CONSTRAINT policy_decision_provenance_positive_versions CHECK (
    certificate_status_version > 0
    AND tenant_version > 0
    AND subject_version > 0
    AND membership_version > 0
    AND policy_bundle_version > 0
  ),
  CONSTRAINT policy_decision_provenance_action CHECK (
    policy_action IN (
      'profile:read', 'record:read', 'record:write', 'record:export',
      'tenant:admin', 'member:manage', 'certificate:manage', 'admin-key:rotate'
    )
  ),
  CONSTRAINT policy_decision_provenance_resource_type CHECK (
    resource_type ~ '^[a-z][a-z0-9-]{1,62}$'
  ),
  CONSTRAINT policy_decision_provenance_sensitivity CHECK (
    resource_sensitivity IN ('public', 'internal', 'confidential', 'sensitive', 'critical')
  ),
  CONSTRAINT policy_decision_provenance_reasons CHECK (
    jsonb_typeof(reason_codes) = 'array'
    AND jsonb_array_length(reason_codes) BETWEEN 1 AND 16
  ),
  CONSTRAINT policy_decision_provenance_trust_shape CHECK (
    (
      trust_transition_id IS NULL
      AND trust_update_version IS NULL
      AND trust_model_version IS NULL
      AND trust_configuration_version IS NULL
      AND trust_explanation_hash_sha256 IS NULL
    ) OR (
      trust_transition_id IS NOT NULL
      AND trust_update_version > 0
      AND trust_model_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
      AND trust_configuration_version > 0
      AND trust_explanation_hash_sha256 IS NOT NULL
    )
  ),
  CONSTRAINT policy_decision_provenance_path CHECK (
    policy_decision_path = 'tenant_trust/authorization/decision'
  ),
  CONSTRAINT policy_decision_provenance_profile CHECK (
    canonicalization_profile = 'tenant-trust-authorization-decision-provenance-json-v1'
  ),
  CONSTRAINT policy_decision_provenance_document_matches CHECK (
    provenance_document = provenance_canonical_json::jsonb
  ),
  CONSTRAINT policy_decision_provenance_time_order CHECK (
    requested_at <= evaluated_at
    AND evaluated_at <= recorded_at + interval '2 seconds'
    AND evaluated_at >= recorded_at - interval '5 minutes'
  )
);

CREATE INDEX policy_decision_provenance_correlation_lookup
  ON audit.policy_decision_provenance (tenant_id, correlation_id, evaluated_at DESC);

CREATE INDEX policy_decision_provenance_trust_lookup
  ON audit.policy_decision_provenance (tenant_id, trust_transition_id, evaluated_at DESC)
  WHERE trust_transition_id IS NOT NULL;

CREATE INDEX policy_decision_provenance_policy_lookup
  ON audit.policy_decision_provenance (tenant_id, policy_version_id, evaluated_at DESC);

CREATE FUNCTION audit.prevent_policy_decision_provenance_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, audit
AS $function$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '42501',
    MESSAGE = 'Policy decision provenance is append-only.';
END
$function$;

CREATE TRIGGER policy_decision_provenance_append_only
BEFORE UPDATE OR DELETE ON audit.policy_decision_provenance
FOR EACH ROW EXECUTE FUNCTION audit.prevent_policy_decision_provenance_rewrite();

ALTER TABLE audit.policy_decision_provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.policy_decision_provenance FORCE ROW LEVEL SECURITY;

CREATE FUNCTION audit.record_policy_decision_provenance(
  p_provenance_canonical_json text,
  p_provenance_hash_sha256 identity.sha256_digest
)
RETURNS audit.policy_decision_provenance
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust, audit
SET row_security = off
AS $function$
DECLARE
  v_document jsonb;
  v_tenant_id identity.tenant_id;
  v_subject_id identity.subject_id;
  v_decision_id audit.policy_decision_id;
  v_request_id identity.request_id;
  v_correlation_id identity.correlation_id;
  v_certificate_id identity.certificate_id;
  v_certificate_status_version bigint;
  v_tenant_version bigint;
  v_subject_version bigint;
  v_membership_version bigint;
  v_policy_action text;
  v_resource_type text;
  v_resource_sensitivity text;
  v_resource_hash identity.sha256_digest;
  v_outcome audit.policy_decision_outcome;
  v_reason_codes jsonb;
  v_trust_transition_id trust.transition_id;
  v_trust_update_version bigint;
  v_trust_model_version text;
  v_trust_configuration_version integer;
  v_trust_explanation_hash identity.sha256_digest;
  v_policy_version_id trust.policy_version_id;
  v_policy_bundle_version integer;
  v_policy_bundle_hash identity.sha256_digest;
  v_policy_decision_path text;
  v_policy_input_hash identity.sha256_digest;
  v_profile text;
  v_requested_at timestamptz;
  v_evaluated_at timestamptz;
  v_existing audit.policy_decision_provenance%ROWTYPE;
  v_created audit.policy_decision_provenance%ROWTYPE;
BEGIN
  IF p_provenance_canonical_json IS NULL
     OR length(p_provenance_canonical_json) NOT BETWEEN 2 AND 32768
     OR p_provenance_hash_sha256 IS NULL
     OR encode(public.digest(convert_to(p_provenance_canonical_json, 'UTF8'), 'sha256'), 'hex')
       <> p_provenance_hash_sha256::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy decision provenance denied.';
  END IF;

  BEGIN
    v_document := p_provenance_canonical_json::jsonb;
    v_tenant_id := (v_document #>> '{request,tenantId}')::identity.tenant_id;
    v_subject_id := (v_document #>> '{request,subjectId}')::identity.subject_id;
    v_decision_id := (v_document #>> '{decision,decisionId}')::audit.policy_decision_id;
    v_request_id := (v_document #>> '{request,requestId}')::identity.request_id;
    v_correlation_id := (v_document #>> '{request,correlationId}')::identity.correlation_id;
    v_certificate_id := (v_document #>> '{identityState,certificateId}')::identity.certificate_id;
    v_certificate_status_version := (v_document #>> '{identityState,certificateStatusVersion}')::bigint;
    v_tenant_version := (v_document #>> '{identityState,tenantVersion}')::bigint;
    v_subject_version := (v_document #>> '{identityState,subjectVersion}')::bigint;
    v_membership_version := (v_document #>> '{identityState,membershipVersion}')::bigint;
    v_policy_action := v_document #>> '{request,action}';
    v_resource_type := v_document #>> '{request,resource,resourceType}';
    v_resource_sensitivity := v_document #>> '{request,resource,sensitivity}';
    v_resource_hash := (v_document #>> '{request,resource,resourceIdHashSha256}')::identity.sha256_digest;
    v_outcome := (v_document #>> '{decision,outcome}')::audit.policy_decision_outcome;
    v_reason_codes := v_document #> '{decision,reasonCodes}';
    v_trust_transition_id := (v_document #>> '{trustState,transitionId}')::trust.transition_id;
    v_trust_update_version := (v_document #>> '{trustState,updateVersion}')::bigint;
    v_trust_model_version := v_document #>> '{trustState,modelVersion}';
    v_trust_configuration_version := (v_document #>> '{trustState,configurationVersion}')::integer;
    v_trust_explanation_hash := (v_document #>> '{trustState,explanationHashSha256}')::identity.sha256_digest;
    v_policy_version_id := (v_document #>> '{policy,policyVersionId}')::trust.policy_version_id;
    v_policy_bundle_version := (v_document #>> '{policy,bundleVersion}')::integer;
    v_policy_bundle_hash := (v_document #>> '{policy,bundleHashSha256}')::identity.sha256_digest;
    v_policy_decision_path := v_document #>> '{policy,decisionPath}';
    v_policy_input_hash := (v_document #>> '{input,hashSha256}')::identity.sha256_digest;
    v_profile := v_document #>> '{canonicalizationProfile}';
    v_requested_at := (v_document #>> '{request,requestedAt}')::timestamptz;
    v_evaluated_at := (v_document #>> '{decision,evaluatedAt}')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy decision provenance denied.';
  END;

  IF v_document->>'schemaVersion' <> '1.0.0'
     OR v_document->>'provenanceType' <> 'authorization-decision'
     OR v_profile <> 'tenant-trust-authorization-decision-provenance-json-v1'
     OR v_document #>> '{decision,contractId}' <> 'opa-decision-output-v1'
     OR v_document #>> '{input,contractId}' <> 'opa-decision-input-v1'
     OR v_tenant_id IS NULL OR v_tenant_id <> identity.current_tenant_id()
     OR v_subject_id IS NULL OR v_subject_id <> identity.current_subject_id()
     OR NOT identity.current_actor_is_active()
     OR v_decision_id IS NULL OR v_request_id IS NULL OR v_correlation_id IS NULL
     OR substring(v_decision_id::text FROM 5) <> substring(v_request_id::text FROM 5)
     OR v_policy_action NOT IN (
       'profile:read', 'record:read', 'record:write', 'record:export',
       'tenant:admin', 'member:manage', 'certificate:manage', 'admin-key:rotate'
     )
     OR v_resource_type !~ '^[a-z][a-z0-9-]{1,62}$'
     OR v_resource_sensitivity NOT IN ('public', 'internal', 'confidential', 'sensitive', 'critical')
     OR jsonb_typeof(v_reason_codes) <> 'array'
     OR jsonb_array_length(v_reason_codes) NOT BETWEEN 1 AND 16
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements_text(v_reason_codes) AS reason(code)
       WHERE reason.code !~ '^[A-Z][A-Z0-9_]{2,63}$'
     )
     OR v_requested_at IS NULL OR v_evaluated_at IS NULL
     OR v_requested_at > v_evaluated_at
     OR v_evaluated_at > clock_timestamp() + interval '2 seconds'
     OR v_evaluated_at < clock_timestamp() - interval '5 minutes'
     OR NOT EXISTS (
       SELECT 1 FROM identity.certificates AS certificate
       WHERE certificate.tenant_id = v_tenant_id
         AND certificate.subject_id = v_subject_id
         AND certificate.certificate_id = v_certificate_id
         AND certificate.version = v_certificate_status_version
     )
     OR NOT EXISTS (
       SELECT 1 FROM identity.tenants AS tenant
       WHERE tenant.tenant_id = v_tenant_id AND tenant.version = v_tenant_version
     )
     OR NOT EXISTS (
       SELECT 1 FROM identity.subjects AS subject
       WHERE subject.subject_id = v_subject_id AND subject.version = v_subject_version
     )
     OR NOT EXISTS (
       SELECT 1 FROM identity.tenant_memberships AS membership
       WHERE membership.tenant_id = v_tenant_id
         AND membership.subject_id = v_subject_id
         AND membership.version = v_membership_version
     )
     OR NOT EXISTS (
       SELECT 1 FROM trust.policy_versions AS policy
       WHERE policy.tenant_id = v_tenant_id
         AND policy.policy_version_id = v_policy_version_id
         AND policy.bundle_version = v_policy_bundle_version
         AND policy.bundle_hash_sha256 = v_policy_bundle_hash::text
         AND policy.entrypoint = v_policy_decision_path
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy decision provenance denied.';
  END IF;

  IF (v_trust_transition_id IS NULL) <> (v_trust_update_version IS NULL)
     OR (v_trust_transition_id IS NULL) <> (v_trust_model_version IS NULL)
     OR (v_trust_transition_id IS NULL) <> (v_trust_configuration_version IS NULL)
     OR (v_trust_transition_id IS NULL) <> (v_trust_explanation_hash IS NULL)
     OR (v_trust_transition_id IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM trust.subject_trust_transitions AS transition
       WHERE transition.tenant_id = v_tenant_id
         AND transition.subject_id = v_subject_id
         AND transition.transition_id = v_trust_transition_id
         AND transition.update_version = v_trust_update_version
         AND transition.model_version = v_trust_model_version
         AND transition.configuration_version = v_trust_configuration_version
         AND transition.explanation_hash_sha256 = v_trust_explanation_hash
     )) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy decision provenance denied.';
  END IF;

  IF (v_outcome IN ('ALLOW', 'DENY')
      AND (
        v_document #> '{decision,obligations,stepUp}' <> 'null'::jsonb
        OR v_document #> '{decision,obligations,quarantine}' <> 'null'::jsonb
      ))
     OR (v_outcome = 'STEP_UP'
      AND (
        v_document #>> '{decision,obligations,stepUp,required}' <> 'true'
        OR v_document #> '{decision,obligations,quarantine}' <> 'null'::jsonb
      ))
     OR (v_outcome = 'QUARANTINE'
      AND (
        v_document #>> '{decision,obligations,quarantine,required}' <> 'true'
        OR v_document #> '{decision,obligations,stepUp}' <> 'null'::jsonb
      )) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy decision provenance denied.';
  END IF;

  SELECT * INTO v_existing
  FROM audit.policy_decision_provenance AS provenance
  WHERE provenance.tenant_id = v_tenant_id
    AND provenance.decision_id = v_decision_id;
  IF FOUND THEN
    IF v_existing.provenance_hash_sha256 <> p_provenance_hash_sha256 THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'POLICY_DECISION_PROVENANCE_CONFLICT';
    END IF;
    RETURN v_existing;
  END IF;

  INSERT INTO audit.policy_decision_provenance (
    tenant_id, decision_id, request_id, correlation_id, actor_subject_id,
    certificate_id, certificate_status_version, tenant_version, subject_version,
    membership_version, policy_action, resource_type, resource_sensitivity,
    resource_id_hash_sha256, outcome, reason_codes, trust_transition_id,
    trust_update_version, trust_model_version, trust_configuration_version,
    trust_explanation_hash_sha256, policy_version_id, policy_bundle_version,
    policy_bundle_hash_sha256, policy_decision_path, policy_input_hash_sha256,
    canonicalization_profile, provenance_canonical_json, provenance_document,
    provenance_hash_sha256, requested_at, evaluated_at
  ) VALUES (
    v_tenant_id, v_decision_id, v_request_id, v_correlation_id, v_subject_id,
    v_certificate_id, v_certificate_status_version, v_tenant_version, v_subject_version,
    v_membership_version, v_policy_action, v_resource_type, v_resource_sensitivity,
    v_resource_hash, v_outcome, v_reason_codes, v_trust_transition_id,
    v_trust_update_version, v_trust_model_version, v_trust_configuration_version,
    v_trust_explanation_hash, v_policy_version_id, v_policy_bundle_version,
    v_policy_bundle_hash, v_policy_decision_path, v_policy_input_hash,
    v_profile, p_provenance_canonical_json, v_document,
    p_provenance_hash_sha256, v_requested_at, v_evaluated_at
  ) RETURNING * INTO v_created;
  RETURN v_created;
END
$function$;

REVOKE ALL ON TABLE audit.policy_decision_provenance FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION audit.prevent_policy_decision_provenance_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.record_policy_decision_provenance(
  text, identity.sha256_digest
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit.record_policy_decision_provenance(
  text, identity.sha256_digest
) TO tenant_trust_app;

COMMENT ON TABLE audit.policy_decision_provenance IS
  'Append-only canonical authorization decisions linked to request, identity, trust/evidence explanation and policy versions for later ledger commitment';
COMMENT ON COLUMN audit.policy_decision_provenance.provenance_hash_sha256 IS
  'SHA-256 of provenance_canonical_json; intended as the stable off-chain digest for later Fabric commitment';
