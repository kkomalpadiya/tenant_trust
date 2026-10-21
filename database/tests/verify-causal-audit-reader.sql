\set ON_ERROR_STOP on

DO $privileges$
BEGIN
  IF has_table_privilege('tenant_trust_audit_verifier','audit.fabric_commitment_outbox','SELECT')
     OR has_table_privilege('tenant_trust_audit_verifier','trust.subject_trust_transition_contributions','SELECT')
     OR has_table_privilege('tenant_trust_audit_verifier','trust.evidence_event_outbox','SELECT') THEN
    RAISE EXCEPTION 'audit verifier received direct table access';
  END IF;
  IF NOT has_function_privilege('tenant_trust_audit_verifier',
       'audit.list_fabric_causal_verification_records(identity.tenant_id,identity.correlation_id)','EXECUTE')
     OR NOT has_function_privilege('tenant_trust_audit_verifier',
       'audit.list_fabric_causal_evidence_anchors(identity.tenant_id,identity.correlation_id)','EXECUTE') THEN
    RAISE EXCEPTION 'audit verifier lacks bounded reader functions';
  END IF;
END $privileges$;

BEGIN;
INSERT INTO identity.tenants(tenant_id,tenant_slug,display_name)
VALUES('tnt_018f1234-5678-7abc-8def-0123456789e1','causal-audit-verifier','Causal Audit Verifier');

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_context('tnt_018f1234-5678-7abc-8def-0123456789e1');
SELECT * FROM audit.enqueue_fabric_commitment(
  'tnt_018f1234-5678-7abc-8def-0123456789e1','evt_018f1234-5678-7abc-8def-0123456789e2',
  'tt-audit-verifier-v1','trust.updated.v1','trust-transition',
  '{"tenantId":"tnt_018f1234-5678-7abc-8def-0123456789e1","eventId":"evt_018f1234-5678-7abc-8def-0123456789e2","eventType":"trust.updated.v1","correlationId":"cor_018f1234-5678-7abc-8def-0123456789e3","occurredAt":"2026-10-21T08:00:00.000Z","payload":{"transitionId":"trn_018f1234-5678-7abc-8def-0123456789e4"}}'::jsonb,
  '{"canonical":"bounded-reader-test"}',
  'audit~trust-transition~aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  repeat('a',64),repeat('b',64),
  '{"canonicalizationProfile":"tenant-trust-audit-commitment-json-v1","commitmentHashSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","digestAlgorithm":"sha256","eventKeyHashSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recordType":"trust-transition","schemaVersion":"1.0.0"}'::jsonb,
  clock_timestamp()
);

RESET ROLE;
SET LOCAL ROLE tenant_trust_audit_verifier;
DO $bounded_reader$
DECLARE matching_count integer; wrong_correlation_count integer; evidence_count integer;
BEGIN
  SELECT count(*) INTO matching_count
  FROM audit.list_fabric_causal_verification_records(
    'tnt_018f1234-5678-7abc-8def-0123456789e1','cor_018f1234-5678-7abc-8def-0123456789e3');
  SELECT count(*) INTO wrong_correlation_count
  FROM audit.list_fabric_causal_verification_records(
    'tnt_018f1234-5678-7abc-8def-0123456789e1','cor_018f1234-5678-7abc-8def-0123456789e5');
  SELECT count(*) INTO evidence_count
  FROM audit.list_fabric_causal_evidence_anchors(
    'tnt_018f1234-5678-7abc-8def-0123456789e1','cor_018f1234-5678-7abc-8def-0123456789e3');
  IF matching_count <> 1 OR wrong_correlation_count <> 0 OR evidence_count <> 0 THEN
    RAISE EXCEPTION 'causal audit reader did not preserve tenant/correlation bounds';
  END IF;
END $bounded_reader$;
ROLLBACK;
