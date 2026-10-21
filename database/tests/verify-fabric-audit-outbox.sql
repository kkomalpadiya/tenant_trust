\set ON_ERROR_STOP on

DO $privileges$
BEGIN
  IF has_table_privilege('tenant_trust_app','audit.fabric_commitment_outbox','SELECT')
     OR has_table_privilege('tenant_trust_audit_outbox_worker','audit.fabric_commitment_outbox','SELECT')
     OR has_table_privilege('tenant_trust_audit_outbox_worker','audit.fabric_commitment_attempt','SELECT') THEN
    RAISE EXCEPTION 'audit roles received direct table access';
  END IF;
  IF NOT has_function_privilege('tenant_trust_audit_outbox_worker','audit.claim_fabric_commitment_confirmation(text,audit.audit_outbox_claim_token,timestamptz)','EXECUTE')
     OR NOT has_function_privilege('tenant_trust_audit_outbox_worker','audit.list_fabric_commitment_gaps(integer)','EXECUTE') THEN
    RAISE EXCEPTION 'worker lacks constrained reconciliation/status functions';
  END IF;
END $privileges$;

BEGIN;
INSERT INTO identity.tenants(tenant_id,tenant_slug,display_name)
VALUES('tnt_018f1234-5678-7abc-8def-0123456789f1','audit-reconcile-verifier','Audit Reconcile Verifier');

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_context('tnt_018f1234-5678-7abc-8def-0123456789f1');
SELECT * FROM audit.enqueue_fabric_commitment(
  'tnt_018f1234-5678-7abc-8def-0123456789f1','evt_018f1234-5678-7abc-8def-0123456789f2',
  'tt-audit-verifier-v1','trust.updated.v1','trust-transition',
  '{"tenantId":"tnt_018f1234-5678-7abc-8def-0123456789f1","eventId":"evt_018f1234-5678-7abc-8def-0123456789f2","eventType":"trust.updated.v1"}'::jsonb,
  '{"canonical":"off-chain-preimage"}',
  'audit~trust-transition~aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  repeat('a',64),repeat('b',64),
  '{"canonicalizationProfile":"tenant-trust-audit-commitment-json-v1","commitmentHashSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","digestAlgorithm":"sha256","eventKeyHashSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recordType":"trust-transition","schemaVersion":"1.0.0"}'::jsonb,
  clock_timestamp()
);

RESET ROLE;
SET LOCAL ROLE tenant_trust_audit_outbox_worker;
DO $lifecycle$
DECLARE c record; recorded record; pending record; recovered record; committed record; gap_count integer;
BEGIN
  SELECT * INTO c FROM audit.claim_fabric_commitment('audit-worker.verify-1',
    'clm_018f1234-5678-7abc-8def-0123456789f3',clock_timestamp());
  IF c.attempt_count<>1 THEN RAISE EXCEPTION 'submission claim was invalid'; END IF;

  SELECT * INTO recorded FROM audit.record_fabric_commitment_submission(c.tenant_id,c.event_id,c.claim_token,c.ledger_key,
    'created',repeat('c',64),clock_timestamp());
  IF recorded.status<>'confirming' THEN RAISE EXCEPTION 'transaction ID was not persisted before confirmation'; END IF;

  SELECT * INTO pending FROM audit.mark_fabric_commitment_confirmation_pending(c.tenant_id,c.event_id,c.claim_token,
    repeat('c',64),'COMMIT_STATUS_UNAVAILABLE',clock_timestamp(),1);
  IF pending.status<>'submitted' THEN RAISE EXCEPTION 'lost status response did not leave a reconciliation gap'; END IF;

  PERFORM pg_sleep(1.1);
  SELECT * INTO recovered FROM audit.claim_fabric_commitment_confirmation('audit-worker.verify-restarted',
    'clm_018f1234-5678-7abc-8def-0123456789f4',clock_timestamp());
  IF recovered.transaction_id<>repeat('c',64) THEN RAISE EXCEPTION 'restart did not recover transaction identity'; END IF;

  SELECT * INTO committed FROM audit.mark_fabric_commitment_committed(recovered.tenant_id,recovered.event_id,recovered.claim_token,
    recovered.transaction_id,0,42,'qscc',clock_timestamp());
  IF committed.status<>'committed' OR committed.block_number<>42 THEN RAISE EXCEPTION 'commit confirmation was not durable'; END IF;

  SELECT count(*) INTO gap_count FROM audit.list_fabric_commitment_gaps(100);
  IF gap_count<>0 THEN RAISE EXCEPTION 'committed row remained visible as a gap'; END IF;
END $lifecycle$;

RESET ROLE;
DO $final_state$
DECLARE o audit.fabric_commitment_outbox%ROWTYPE; a audit.fabric_commitment_attempt%ROWTYPE;
BEGIN
  SELECT * INTO o FROM audit.fabric_commitment_outbox WHERE tenant_id='tnt_018f1234-5678-7abc-8def-0123456789f1';
  SELECT * INTO a FROM audit.fabric_commitment_attempt WHERE tenant_id=o.tenant_id AND event_id=o.event_id;
  IF o.status<>'committed' OR o.validation_code<>0 OR o.block_number<>42 OR o.confirmation_source<>'qscc'
     OR a.state<>'committed' OR a.transaction_id<>repeat('c',64) THEN
    RAISE EXCEPTION 'durable commit/attempt state is invalid';
  END IF;
END $final_state$;
ROLLBACK;
