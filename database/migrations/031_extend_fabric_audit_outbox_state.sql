ALTER TYPE audit.audit_outbox_state ADD VALUE IF NOT EXISTS 'confirming';
ALTER TYPE audit.audit_outbox_state ADD VALUE IF NOT EXISTS 'committed';
ALTER TYPE audit.audit_outbox_state ADD VALUE IF NOT EXISTS 'failed';
