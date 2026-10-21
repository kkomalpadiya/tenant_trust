DROP FUNCTION audit.mark_fabric_commitment_submitted(
  identity.tenant_id, identity.event_id, audit.audit_outbox_claim_token, text, text, timestamptz
);

DROP INDEX audit.fabric_commitment_outbox_due;
CREATE INDEX fabric_commitment_outbox_due
  ON audit.fabric_commitment_outbox (next_attempt_at, created_at, tenant_id, event_id)
  WHERE status IN ('pending', 'failed');

COMMENT ON INDEX audit.fabric_commitment_outbox_due IS
  'Orders new and failed audit submissions for bounded worker retry claims';
