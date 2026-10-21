DO $create_audit_verifier$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_audit_verifier') THEN
    CREATE ROLE tenant_trust_audit_verifier;
  END IF;
END
$create_audit_verifier$;

ALTER ROLE tenant_trust_audit_verifier
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;

CREATE FUNCTION audit.list_fabric_causal_verification_records(
  p_tenant_id identity.tenant_id,
  p_correlation_id identity.correlation_id
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  event_id identity.event_id,
  channel_name text,
  event_document jsonb,
  canonical_preimage_json text,
  ledger_key text,
  ledger_value jsonb,
  delivery_status audit.audit_outbox_state,
  transaction_id identity.sha256_digest,
  validation_code integer,
  block_number bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity
SET row_security = off
AS $function$
  SELECT outbox.tenant_id, outbox.event_id, outbox.channel_name,
    outbox.event_document, outbox.canonical_preimage_json,
    outbox.ledger_key, outbox.ledger_value, outbox.status,
    outbox.transaction_id, outbox.validation_code, outbox.block_number
  FROM audit.fabric_commitment_outbox AS outbox
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.event_document ->> 'correlationId' = p_correlation_id::text
  ORDER BY outbox.event_document ->> 'occurredAt', outbox.event_id;
$function$;

CREATE FUNCTION audit.list_fabric_causal_evidence_anchors(
  p_tenant_id identity.tenant_id,
  p_correlation_id identity.correlation_id
)
RETURNS TABLE (
  transition_id trust.transition_id,
  subject_id identity.subject_id,
  evidence_id trust.evidence_id,
  evidence_event_id identity.event_id,
  evidence_correlation_id identity.correlation_id
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity, trust
SET row_security = off
AS $function$
  SELECT contribution.transition_id, contribution.subject_id,
    contribution.evidence_id, evidence.delivery_event_id, evidence.correlation_id
  FROM audit.fabric_commitment_outbox AS outbox
  JOIN trust.subject_trust_transition_contributions AS contribution
    ON contribution.tenant_id = outbox.tenant_id
   AND contribution.transition_id::text = outbox.event_document #>> '{payload,transitionId}'
  JOIN trust.evidence_event_outbox AS evidence
    ON evidence.tenant_id = contribution.tenant_id
   AND evidence.evidence_id = contribution.evidence_id
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.event_document ->> 'correlationId' = p_correlation_id::text
    AND outbox.event_type = 'trust.updated.v1'
  ORDER BY contribution.transition_id, contribution.component_id;
$function$;

REVOKE ALL ON TABLE audit.fabric_commitment_outbox,
  trust.subject_trust_transition_contributions, trust.evidence_event_outbox
  FROM PUBLIC, tenant_trust_audit_verifier;
REVOKE ALL ON FUNCTION audit.list_fabric_causal_verification_records(
  identity.tenant_id, identity.correlation_id
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.list_fabric_causal_evidence_anchors(
  identity.tenant_id, identity.correlation_id
) FROM PUBLIC;

GRANT USAGE ON SCHEMA audit TO tenant_trust_audit_verifier;
GRANT EXECUTE ON FUNCTION audit.list_fabric_causal_verification_records(
  identity.tenant_id, identity.correlation_id
) TO tenant_trust_audit_verifier;
GRANT EXECUTE ON FUNCTION audit.list_fabric_causal_evidence_anchors(
  identity.tenant_id, identity.correlation_id
) TO tenant_trust_audit_verifier;

COMMENT ON ROLE tenant_trust_audit_verifier IS
  'NOLOGIN privilege set limited to reading bounded off-chain causal audit verification bundles';
COMMENT ON FUNCTION audit.list_fabric_causal_verification_records(identity.tenant_id, identity.correlation_id) IS
  'Returns one tenant and correlation bounded set of off-chain audit records plus durable commit metadata';
COMMENT ON FUNCTION audit.list_fabric_causal_evidence_anchors(identity.tenant_id, identity.correlation_id) IS
  'Returns the accepted evidence identities durably attached to trust transitions in one audit correlation';
