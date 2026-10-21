ALTER TABLE audit.fabric_commitment_outbox
  DROP CONSTRAINT fabric_commitment_outbox_state_shape,
  DROP CONSTRAINT fabric_commitment_outbox_time_order;

ALTER TABLE audit.fabric_commitment_outbox
  ADD COLUMN transaction_id identity.sha256_digest,
  ADD COLUMN validation_code integer,
  ADD COLUMN block_number bigint,
  ADD COLUMN confirmation_source text,
  ADD COLUMN next_confirmation_at timestamptz,
  ADD COLUMN committed_at timestamptz,
  ADD COLUMN failed_at timestamptz;

-- T8.6 did not persist a transaction ID, so legacy submitted rows must be
-- idempotently resubmitted before they can be truthfully called committed.
UPDATE audit.fabric_commitment_outbox
SET status = 'pending', submission_status = NULL, submitted_at = NULL,
    next_attempt_at = clock_timestamp(), last_failure_code = 'LEGACY_SUBMISSION_RECONCILIATION_REQUIRED',
    updated_at = clock_timestamp()
WHERE status = 'submitted';

ALTER TABLE audit.fabric_commitment_outbox
  ADD CONSTRAINT fabric_commitment_outbox_validation_code CHECK (
    validation_code IS NULL OR validation_code BETWEEN 0 AND 255
  ),
  ADD CONSTRAINT fabric_commitment_outbox_block_nonnegative CHECK (
    block_number IS NULL OR block_number >= 0
  ),
  ADD CONSTRAINT fabric_commitment_outbox_confirmation_source CHECK (
    confirmation_source IS NULL OR confirmation_source IN ('gateway-status', 'qscc')
  ),
  ADD CONSTRAINT fabric_commitment_outbox_state_shape CHECK (
    (status = 'pending' AND claim_token IS NULL AND transaction_id IS NULL AND submission_status IS NULL)
    OR (status = 'submitting' AND claim_token IS NOT NULL AND transaction_id IS NULL AND submission_status IS NULL)
    OR (status = 'confirming' AND claim_token IS NOT NULL AND transaction_id IS NOT NULL AND submission_status IS NOT NULL)
    OR (status = 'submitted' AND claim_token IS NULL AND transaction_id IS NOT NULL AND submission_status IS NOT NULL
        AND next_confirmation_at IS NOT NULL AND validation_code IS NULL)
    OR (status = 'committed' AND claim_token IS NULL AND transaction_id IS NOT NULL AND submission_status IS NOT NULL
        AND validation_code = 0 AND block_number IS NOT NULL AND confirmation_source IS NOT NULL AND committed_at IS NOT NULL)
    OR (status = 'failed' AND claim_token IS NULL AND failed_at IS NOT NULL AND last_failure_code IS NOT NULL
        AND ((transaction_id IS NULL AND submission_status IS NULL AND validation_code IS NULL)
          OR (transaction_id IS NOT NULL AND submission_status IS NOT NULL AND validation_code > 0)))
  ),
  ADD CONSTRAINT fabric_commitment_outbox_time_order CHECK (
    updated_at >= created_at AND next_attempt_at >= created_at
    AND (claimed_at IS NULL OR claimed_at >= created_at)
    AND (submitted_at IS NULL OR submitted_at >= created_at)
    AND (next_confirmation_at IS NULL OR next_confirmation_at >= created_at)
    AND (committed_at IS NULL OR committed_at >= created_at)
    AND (failed_at IS NULL OR failed_at >= created_at)
  );

CREATE TABLE audit.fabric_commitment_attempt (
  tenant_id identity.tenant_id NOT NULL,
  event_id identity.event_id NOT NULL,
  attempt_number integer NOT NULL CHECK (attempt_number > 0),
  transaction_id identity.sha256_digest NOT NULL,
  submission_status text NOT NULL CHECK (submission_status IN ('created', 'duplicate')),
  state text NOT NULL CHECK (state IN ('submitted', 'committed', 'failed')),
  validation_code integer CHECK (validation_code IS NULL OR validation_code BETWEEN 0 AND 255),
  block_number bigint CHECK (block_number IS NULL OR block_number >= 0),
  confirmation_source text CHECK (confirmation_source IS NULL OR confirmation_source IN ('gateway-status', 'qscc')),
  submitted_at timestamptz NOT NULL,
  resolved_at timestamptz,
  PRIMARY KEY (tenant_id, event_id, attempt_number),
  UNIQUE (transaction_id),
  FOREIGN KEY (tenant_id, event_id) REFERENCES audit.fabric_commitment_outbox (tenant_id, event_id) ON DELETE CASCADE,
  CHECK ((state = 'submitted' AND validation_code IS NULL AND resolved_at IS NULL)
      OR (state = 'committed' AND validation_code = 0 AND block_number IS NOT NULL AND resolved_at IS NOT NULL)
      OR (state = 'failed' AND validation_code > 0 AND resolved_at IS NOT NULL))
);

CREATE INDEX fabric_commitment_outbox_confirmation_due
  ON audit.fabric_commitment_outbox (next_confirmation_at, created_at, tenant_id, event_id)
  WHERE status = 'submitted';

CREATE OR REPLACE FUNCTION audit.claim_fabric_commitment(
  p_worker_id text, p_claim_token audit.audit_outbox_claim_token, p_claimed_at timestamptz
) RETURNS TABLE (
  tenant_id identity.tenant_id, event_id identity.event_id, channel_name text,
  event_document jsonb, canonical_preimage_json text, ledger_key text,
  ledger_value jsonb, claim_token audit.audit_outbox_claim_token, attempt_count integer
) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, audit, identity SET row_security = off AS $function$
BEGIN
  IF p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{2,127}$' OR p_claimed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Audit commitment claim denied.';
  END IF;
  UPDATE audit.fabric_commitment_outbox AS o
  SET status='failed', claim_token=NULL, claimed_by=NULL, claimed_at=NULL,
      failed_at=p_claimed_at, next_attempt_at=p_claimed_at,
      last_failure_code='STALE_SUBMISSION_CLAIM_RECOVERED', updated_at=GREATEST(clock_timestamp(), p_claimed_at)
  WHERE o.status='submitting' AND o.claimed_at < p_claimed_at - interval '5 minutes';
  RETURN QUERY WITH candidate AS (
    SELECT o.tenant_id,o.event_id FROM audit.fabric_commitment_outbox o
    WHERE o.status IN ('pending','failed') AND o.next_attempt_at <= p_claimed_at
    ORDER BY o.next_attempt_at,o.created_at,o.tenant_id,o.event_id FOR UPDATE SKIP LOCKED LIMIT 1
  ), claimed AS (
    UPDATE audit.fabric_commitment_outbox o SET status='submitting', claim_token=p_claim_token,
      claimed_by=p_worker_id, claimed_at=p_claimed_at, attempt_count=o.attempt_count+1,
      transaction_id=NULL, submission_status=NULL, submitted_at=NULL, validation_code=NULL,
      block_number=NULL, confirmation_source=NULL, next_confirmation_at=NULL,
      committed_at=NULL, failed_at=NULL, last_failure_code=NULL,
      updated_at=GREATEST(clock_timestamp(),p_claimed_at)
    FROM candidate c WHERE o.tenant_id=c.tenant_id AND o.event_id=c.event_id RETURNING o.*
  ) SELECT c.tenant_id,c.event_id,c.channel_name,c.event_document,c.canonical_preimage_json,
      c.ledger_key,c.ledger_value,c.claim_token,c.attempt_count FROM claimed c;
END $function$;

CREATE FUNCTION audit.record_fabric_commitment_submission(
  p_tenant_id identity.tenant_id, p_event_id identity.event_id,
  p_claim_token audit.audit_outbox_claim_token, p_ledger_key text,
  p_submission_status text, p_transaction_id identity.sha256_digest, p_submitted_at timestamptz
) RETURNS TABLE (event_id identity.event_id, status audit.audit_outbox_state, transaction_id identity.sha256_digest)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,audit,identity SET row_security=off AS $function$
DECLARE updated audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  IF p_submission_status NOT IN ('created','duplicate') OR p_submitted_at > clock_timestamp()+interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment submission update denied.';
  END IF;
  UPDATE audit.fabric_commitment_outbox o SET status='confirming', submission_status=p_submission_status,
    transaction_id=p_transaction_id, submitted_at=p_submitted_at, last_failure_code=NULL,
    updated_at=GREATEST(clock_timestamp(),p_submitted_at)
  WHERE o.tenant_id=p_tenant_id AND o.event_id=p_event_id AND o.status='submitting'
    AND o.claim_token=p_claim_token AND o.ledger_key=p_ledger_key RETURNING o.* INTO updated;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment submission update denied.'; END IF;
  INSERT INTO audit.fabric_commitment_attempt(tenant_id,event_id,attempt_number,transaction_id,submission_status,state,submitted_at)
  VALUES(updated.tenant_id,updated.event_id,updated.attempt_count,p_transaction_id,p_submission_status,'submitted',p_submitted_at);
  RETURN QUERY SELECT updated.event_id,updated.status,updated.transaction_id;
END $function$;

CREATE FUNCTION audit.claim_fabric_commitment_confirmation(
  p_worker_id text, p_claim_token audit.audit_outbox_claim_token, p_claimed_at timestamptz
) RETURNS TABLE (tenant_id identity.tenant_id,event_id identity.event_id,transaction_id identity.sha256_digest,
  claim_token audit.audit_outbox_claim_token,attempt_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,audit,identity SET row_security=off AS $function$
BEGIN
  IF p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{2,127}$' OR p_claimed_at > clock_timestamp()+interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment confirmation claim denied.';
  END IF;
  UPDATE audit.fabric_commitment_outbox o SET status='submitted',claim_token=NULL,claimed_by=NULL,claimed_at=NULL,
    next_confirmation_at=p_claimed_at,last_failure_code='STALE_CONFIRMATION_CLAIM_RECOVERED',updated_at=GREATEST(clock_timestamp(),p_claimed_at)
  WHERE o.status='confirming' AND o.claimed_at < p_claimed_at-interval '5 minutes';
  RETURN QUERY WITH candidate AS (
    SELECT o.tenant_id,o.event_id FROM audit.fabric_commitment_outbox o
    WHERE o.status='submitted' AND o.next_confirmation_at<=p_claimed_at
    ORDER BY o.next_confirmation_at,o.created_at,o.tenant_id,o.event_id FOR UPDATE SKIP LOCKED LIMIT 1
  ), claimed AS (
    UPDATE audit.fabric_commitment_outbox o SET status='confirming',claim_token=p_claim_token,
      claimed_by=p_worker_id,claimed_at=p_claimed_at,updated_at=GREATEST(clock_timestamp(),p_claimed_at)
    FROM candidate c WHERE o.tenant_id=c.tenant_id AND o.event_id=c.event_id RETURNING o.*
  ) SELECT c.tenant_id,c.event_id,c.transaction_id,c.claim_token,c.attempt_count FROM claimed c;
END $function$;

CREATE FUNCTION audit.mark_fabric_commitment_committed(
  p_tenant_id identity.tenant_id,p_event_id identity.event_id,p_claim_token audit.audit_outbox_claim_token,
  p_transaction_id identity.sha256_digest,p_validation_code integer,p_block_number bigint,
  p_confirmation_source text,p_confirmed_at timestamptz
) RETURNS TABLE(event_id identity.event_id,status audit.audit_outbox_state,block_number bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,audit,identity SET row_security=off AS $function$
DECLARE updated audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  IF p_validation_code<>0 OR p_block_number<0 OR p_confirmation_source NOT IN ('gateway-status','qscc')
     OR p_confirmed_at>clock_timestamp()+interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment confirmation denied.';
  END IF;
  UPDATE audit.fabric_commitment_outbox o SET status='committed',claim_token=NULL,claimed_by=NULL,claimed_at=NULL,
    validation_code=p_validation_code,block_number=p_block_number,confirmation_source=p_confirmation_source,
    committed_at=p_confirmed_at,next_confirmation_at=NULL,last_failure_code=NULL,updated_at=GREATEST(clock_timestamp(),p_confirmed_at)
  WHERE o.tenant_id=p_tenant_id AND o.event_id=p_event_id AND o.status='confirming'
    AND o.claim_token=p_claim_token AND o.transaction_id=p_transaction_id RETURNING o.* INTO updated;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment confirmation denied.'; END IF;
  UPDATE audit.fabric_commitment_attempt a SET state='committed',validation_code=p_validation_code,
    block_number=p_block_number,confirmation_source=p_confirmation_source,resolved_at=p_confirmed_at
  WHERE a.tenant_id=p_tenant_id AND a.event_id=p_event_id AND a.transaction_id=p_transaction_id;
  RETURN QUERY SELECT updated.event_id,updated.status,updated.block_number;
END $function$;

CREATE FUNCTION audit.mark_fabric_commitment_commit_failed(
  p_tenant_id identity.tenant_id,p_event_id identity.event_id,p_claim_token audit.audit_outbox_claim_token,
  p_transaction_id identity.sha256_digest,p_validation_code integer,p_block_number bigint,
  p_confirmation_source text,p_failed_at timestamptz,p_retry_delay_seconds integer
) RETURNS TABLE(event_id identity.event_id,status audit.audit_outbox_state,next_attempt_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,audit,identity SET row_security=off AS $function$
DECLARE updated audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  IF p_validation_code<=0 OR p_block_number<0 OR p_confirmation_source NOT IN ('gateway-status','qscc')
     OR p_retry_delay_seconds NOT BETWEEN 1 AND 600 OR p_failed_at>clock_timestamp()+interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment failure update denied.';
  END IF;
  UPDATE audit.fabric_commitment_outbox o SET status='failed',claim_token=NULL,claimed_by=NULL,claimed_at=NULL,
    validation_code=p_validation_code,block_number=p_block_number,confirmation_source=p_confirmation_source,
    failed_at=p_failed_at,next_attempt_at=p_failed_at+make_interval(secs=>p_retry_delay_seconds),
    next_confirmation_at=NULL,last_failure_code='FABRIC_COMMIT_INVALID',updated_at=GREATEST(clock_timestamp(),p_failed_at)
  WHERE o.tenant_id=p_tenant_id AND o.event_id=p_event_id AND o.status='confirming'
    AND o.claim_token=p_claim_token AND o.transaction_id=p_transaction_id RETURNING o.* INTO updated;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment failure update denied.'; END IF;
  UPDATE audit.fabric_commitment_attempt a SET state='failed',validation_code=p_validation_code,
    block_number=p_block_number,confirmation_source=p_confirmation_source,resolved_at=p_failed_at
  WHERE a.tenant_id=p_tenant_id AND a.event_id=p_event_id AND a.transaction_id=p_transaction_id;
  RETURN QUERY SELECT updated.event_id,updated.status,updated.next_attempt_at;
END $function$;

CREATE FUNCTION audit.mark_fabric_commitment_confirmation_pending(
  p_tenant_id identity.tenant_id,p_event_id identity.event_id,p_claim_token audit.audit_outbox_claim_token,
  p_transaction_id identity.sha256_digest,p_failure_code text,p_failed_at timestamptz,p_retry_delay_seconds integer
) RETURNS TABLE(event_id identity.event_id,status audit.audit_outbox_state,next_confirmation_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,audit,identity SET row_security=off AS $function$
DECLARE updated audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  IF p_failure_code!~'^[A-Z][A-Z0-9_]{2,63}$' OR p_retry_delay_seconds NOT BETWEEN 1 AND 600
     OR p_failed_at>clock_timestamp()+interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment reconciliation update denied.';
  END IF;
  UPDATE audit.fabric_commitment_outbox o SET status='submitted',claim_token=NULL,claimed_by=NULL,claimed_at=NULL,
    next_confirmation_at=p_failed_at+make_interval(secs=>p_retry_delay_seconds),last_failure_code=p_failure_code,
    updated_at=GREATEST(clock_timestamp(),p_failed_at)
  WHERE o.tenant_id=p_tenant_id AND o.event_id=p_event_id AND o.status='confirming'
    AND o.claim_token=p_claim_token AND o.transaction_id=p_transaction_id RETURNING o.* INTO updated;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Audit commitment reconciliation update denied.'; END IF;
  RETURN QUERY SELECT updated.event_id,updated.status,updated.next_confirmation_at;
END $function$;

CREATE OR REPLACE FUNCTION audit.mark_fabric_commitment_failed(
  p_tenant_id identity.tenant_id,p_event_id identity.event_id,p_claim_token audit.audit_outbox_claim_token,
  p_failure_code text,p_failed_at timestamptz,p_retry_delay_seconds integer
) RETURNS TABLE(event_id identity.event_id,status audit.audit_outbox_state,next_attempt_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,audit,identity SET row_security=off AS $function$
DECLARE updated audit.fabric_commitment_outbox%ROWTYPE;
BEGIN
  IF p_failure_code!~'^[A-Z][A-Z0-9_]{2,63}$' OR p_retry_delay_seconds NOT BETWEEN 1 AND 600
     OR p_failed_at>clock_timestamp()+interval '2 seconds' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Audit commitment failure update denied.'; END IF;
  UPDATE audit.fabric_commitment_outbox o SET status='failed',claim_token=NULL,claimed_by=NULL,claimed_at=NULL,
    failed_at=p_failed_at,next_attempt_at=p_failed_at+make_interval(secs=>p_retry_delay_seconds),
    last_failure_code=p_failure_code,updated_at=GREATEST(clock_timestamp(),p_failed_at)
  WHERE o.tenant_id=p_tenant_id AND o.event_id=p_event_id AND o.status='submitting' AND o.claim_token=p_claim_token
  RETURNING o.* INTO updated;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Audit commitment failure update denied.'; END IF;
  RETURN QUERY SELECT updated.event_id,updated.status,updated.next_attempt_at;
END $function$;

CREATE FUNCTION audit.get_fabric_commitment_delivery_summary()
RETURNS TABLE(status audit.audit_outbox_state,event_count bigint,oldest_event_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,audit SET row_security=off
AS $$ SELECT o.status,count(*),min(o.created_at) FROM audit.fabric_commitment_outbox o GROUP BY o.status ORDER BY o.status::text $$;

CREATE FUNCTION audit.list_fabric_commitment_gaps(p_limit integer DEFAULT 100)
RETURNS TABLE(tenant_id identity.tenant_id,event_id identity.event_id,status audit.audit_outbox_state,
  attempt_count integer,transaction_id identity.sha256_digest,last_failure_code text,updated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,audit,identity SET row_security=off AS $function$
BEGIN
  IF p_limit NOT BETWEEN 1 AND 500 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Gap limit must be between 1 and 500.'; END IF;
  RETURN QUERY SELECT o.tenant_id,o.event_id,o.status,o.attempt_count,o.transaction_id,o.last_failure_code,o.updated_at
  FROM audit.fabric_commitment_outbox o WHERE o.status<>'committed'
  ORDER BY o.updated_at,o.tenant_id,o.event_id LIMIT p_limit;
END $function$;

REVOKE ALL ON TABLE audit.fabric_commitment_attempt FROM PUBLIC,tenant_trust_app,tenant_trust_audit_outbox_worker;
REVOKE ALL ON FUNCTION audit.record_fabric_commitment_submission(identity.tenant_id,identity.event_id,audit.audit_outbox_claim_token,text,text,identity.sha256_digest,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.claim_fabric_commitment_confirmation(text,audit.audit_outbox_claim_token,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.mark_fabric_commitment_committed(identity.tenant_id,identity.event_id,audit.audit_outbox_claim_token,identity.sha256_digest,integer,bigint,text,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.mark_fabric_commitment_commit_failed(identity.tenant_id,identity.event_id,audit.audit_outbox_claim_token,identity.sha256_digest,integer,bigint,text,timestamptz,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.mark_fabric_commitment_confirmation_pending(identity.tenant_id,identity.event_id,audit.audit_outbox_claim_token,identity.sha256_digest,text,timestamptz,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.get_fabric_commitment_delivery_summary() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.list_fabric_commitment_gaps(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.record_fabric_commitment_submission(identity.tenant_id,identity.event_id,audit.audit_outbox_claim_token,text,text,identity.sha256_digest,timestamptz) TO tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.claim_fabric_commitment_confirmation(text,audit.audit_outbox_claim_token,timestamptz) TO tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.mark_fabric_commitment_committed(identity.tenant_id,identity.event_id,audit.audit_outbox_claim_token,identity.sha256_digest,integer,bigint,text,timestamptz) TO tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.mark_fabric_commitment_commit_failed(identity.tenant_id,identity.event_id,audit.audit_outbox_claim_token,identity.sha256_digest,integer,bigint,text,timestamptz,integer) TO tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.mark_fabric_commitment_confirmation_pending(identity.tenant_id,identity.event_id,audit.audit_outbox_claim_token,identity.sha256_digest,text,timestamptz,integer) TO tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.get_fabric_commitment_delivery_summary() TO tenant_trust_audit_outbox_worker;
GRANT EXECUTE ON FUNCTION audit.list_fabric_commitment_gaps(integer) TO tenant_trust_audit_outbox_worker;

COMMENT ON TABLE audit.fabric_commitment_attempt IS 'Immutable transaction identity plus mutable final validation result for every Fabric delivery attempt';
COMMENT ON FUNCTION audit.list_fabric_commitment_gaps(integer) IS 'Shows bounded pending, in-flight, reconciliation, and failed audit delivery gaps without direct table access';
