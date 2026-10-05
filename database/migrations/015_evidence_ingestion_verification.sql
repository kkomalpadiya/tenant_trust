CREATE FUNCTION trust.resolve_evidence_verification_context(
  p_tenant_id identity.tenant_id,
  p_subject_id identity.subject_id,
  p_source_id trust.source_id,
  p_key_id trust.evidence_source_key_id
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  source_id trust.source_id,
  evidence_type trust.evidence_type,
  source_synthetic boolean,
  maximum_age_seconds integer,
  source_state trust.evidence_source_state,
  verification_algorithm text,
  key_id trust.evidence_source_key_id,
  key_state trust.evidence_source_key_state,
  key_version integer,
  public_key_base64url trust.ed25519_public_key_base64url,
  public_key_sha256 text,
  key_enrolled_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
  SELECT
    tenant.tenant_id,
    subject.subject_id,
    source.source_id,
    source.evidence_type,
    source.synthetic,
    source.maximum_age_seconds,
    source.state,
    'Ed25519'::text,
    source_key.key_id,
    source_key.state,
    source_key.key_version,
    source_key.public_key_base64url,
    source_key.public_key_sha256,
    source_key.enrolled_at
  FROM identity.tenants AS tenant
  JOIN identity.tenant_memberships AS membership
    ON membership.tenant_id = tenant.tenant_id
   AND membership.subject_id = p_subject_id
  JOIN identity.subjects AS subject
    ON subject.subject_id = membership.subject_id
  JOIN trust.evidence_sources AS source
    ON source.tenant_id = tenant.tenant_id
   AND source.source_id = p_source_id
  JOIN trust.evidence_source_keys AS source_key
    ON source_key.tenant_id = source.tenant_id
   AND source_key.source_id = source.source_id
   AND source_key.key_id = p_key_id
  WHERE tenant.tenant_id = p_tenant_id
    AND tenant.state = 'active'
    AND subject.state = 'active'
    AND membership.state = 'active'
    AND source.state = 'active'
    AND source.verification_algorithm = 'ed25519'
    AND source.verification_key_sha256 = source_key.public_key_sha256
    AND source_key.state = 'active'
    AND source_key.algorithm = 'Ed25519'
$function$;

REVOKE ALL ON FUNCTION trust.resolve_evidence_verification_context(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust.resolve_evidence_verification_context(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id
) TO tenant_trust_app;

COMMENT ON FUNCTION trust.resolve_evidence_verification_context(
  identity.tenant_id, identity.subject_id, trust.source_id, trust.evidence_source_key_id
) IS 'Returns one active exact tenant, subject membership, evidence source and Ed25519 key tuple for signature verification without treating submitted identity fields as database authority';
