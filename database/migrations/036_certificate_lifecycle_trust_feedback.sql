DO $role$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'tenant_trust_certificate_feedback_consumer'
  ) THEN
    CREATE ROLE tenant_trust_certificate_feedback_consumer;
  END IF;
END
$role$;

ALTER ROLE tenant_trust_certificate_feedback_consumer
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;

CREATE UNIQUE INDEX security_actions_external_result_unique
  ON orchestration.security_actions (tenant_id, external_reference)
  WHERE external_reference IS NOT NULL;

CREATE TABLE trust.certificate_lifecycle_evidence (
  tenant_id identity.tenant_id NOT NULL,
  evidence_id trust.evidence_id NOT NULL,
  lifecycle_event_id identity.event_id NOT NULL,
  causal_parent_event_id identity.event_id,
  correlation_id identity.correlation_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  certificate_id identity.certificate_id NOT NULL,
  event_type identity.certificate_lifecycle_event_type NOT NULL,
  certificate_state identity.certificate_state NOT NULL,
  evidence_kind text NOT NULL,
  component_score numeric(5,2) NOT NULL,
  terminal boolean NOT NULL,
  security_action_eligible boolean NOT NULL DEFAULT false,
  source_action_id audit.security_action_id,
  consumer_name text NOT NULL,
  stream_sequence bigint NOT NULL,
  signed_event_sha256 identity.sha256_digest NOT NULL,
  observed_at timestamptz NOT NULL,
  processed_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT certificate_lifecycle_evidence_pk PRIMARY KEY (tenant_id, evidence_id),
  CONSTRAINT certificate_lifecycle_evidence_event_unique UNIQUE (tenant_id, lifecycle_event_id),
  CONSTRAINT certificate_lifecycle_evidence_event_fk FOREIGN KEY (tenant_id, lifecycle_event_id)
    REFERENCES identity.certificate_lifecycle_events (tenant_id, event_id) ON DELETE RESTRICT,
  CONSTRAINT certificate_lifecycle_evidence_parent_fk FOREIGN KEY (tenant_id, causal_parent_event_id)
    REFERENCES identity.certificate_lifecycle_events (tenant_id, event_id) ON DELETE RESTRICT,
  CONSTRAINT certificate_lifecycle_evidence_subject_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT certificate_lifecycle_evidence_certificate_fk FOREIGN KEY (tenant_id, certificate_id)
    REFERENCES identity.certificates (tenant_id, certificate_id) ON DELETE RESTRICT,
  CONSTRAINT certificate_lifecycle_evidence_action_fk FOREIGN KEY (tenant_id, source_action_id)
    REFERENCES orchestration.security_actions (tenant_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT certificate_lifecycle_evidence_score CHECK (component_score BETWEEN 0 AND 100),
  CONSTRAINT certificate_lifecycle_evidence_sequence CHECK (stream_sequence > 0),
  CONSTRAINT certificate_lifecycle_evidence_consumer CHECK (
    consumer_name ~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
  ),
  CONSTRAINT certificate_lifecycle_evidence_non_recursive CHECK (
    security_action_eligible = false
  ),
  CONSTRAINT certificate_lifecycle_evidence_mapping CHECK (
    (event_type = 'issued' AND certificate_state = 'active'
      AND evidence_kind = 'certificate-issued' AND component_score = 100 AND terminal = false)
    OR (event_type = 'renewed' AND certificate_state = 'active'
      AND evidence_kind = 'certificate-renewed' AND component_score = 100 AND terminal = false)
    OR (event_type = 'superseded' AND certificate_state = 'superseded'
      AND evidence_kind = 'certificate-superseded' AND component_score = 100 AND terminal = true)
    OR (event_type = 'revoked' AND certificate_state = 'revoked'
      AND evidence_kind = 'certificate-revoked' AND component_score = 0 AND terminal = true)
    OR (event_type = 'expired' AND certificate_state = 'expired'
      AND evidence_kind = 'certificate-expired' AND component_score = 0 AND terminal = true)
  ),
  CONSTRAINT certificate_lifecycle_evidence_causation CHECK (
    (event_type = 'issued' AND causal_parent_event_id IS NULL)
    OR (event_type <> 'issued' AND causal_parent_event_id IS NOT NULL)
  ),
  CONSTRAINT certificate_lifecycle_evidence_action_shape CHECK (
    source_action_id IS NULL OR event_type = 'revoked'
  ),
  CONSTRAINT certificate_lifecycle_evidence_time CHECK (
    observed_at <= processed_at AND processed_at <= recorded_at + interval '2 seconds'
  )
);

CREATE INDEX certificate_lifecycle_evidence_subject_history
  ON trust.certificate_lifecycle_evidence (
    tenant_id, subject_id, observed_at DESC, lifecycle_event_id DESC
  );
CREATE INDEX certificate_lifecycle_evidence_action_lookup
  ON trust.certificate_lifecycle_evidence (tenant_id, source_action_id)
  WHERE source_action_id IS NOT NULL;

CREATE FUNCTION trust.prevent_certificate_lifecycle_evidence_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, trust
AS $function$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate lifecycle evidence is append-only.';
END
$function$;

CREATE TRIGGER certificate_lifecycle_evidence_append_only
BEFORE UPDATE OR DELETE ON trust.certificate_lifecycle_evidence
FOR EACH ROW EXECUTE FUNCTION trust.prevent_certificate_lifecycle_evidence_rewrite();

CREATE FUNCTION trust.record_certificate_lifecycle_evidence(
  p_consumer_name text,
  p_tenant_id identity.tenant_id,
  p_lifecycle_event_id identity.event_id,
  p_stream_sequence bigint,
  p_signed_event_sha256 identity.sha256_digest,
  p_processed_at timestamptz
)
RETURNS TABLE (
  applied boolean,
  outcome_code text,
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  certificate_id identity.certificate_id,
  evidence_id trust.evidence_id,
  lifecycle_event_id identity.event_id,
  causal_parent_event_id identity.event_id,
  evidence_kind text,
  component_score numeric,
  terminal boolean,
  security_action_eligible boolean,
  source_action_id audit.security_action_id
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust, orchestration, audit
SET row_security = off
AS $function$
DECLARE
  v_event identity.certificate_lifecycle_events%ROWTYPE;
  v_evidence trust.certificate_lifecycle_evidence%ROWTYPE;
  v_evidence_id trust.evidence_id;
  v_kind text;
  v_score numeric;
  v_terminal boolean;
  v_source_action_id audit.security_action_id;
  v_inserted integer;
BEGIN
  IF p_consumer_name !~ '^[a-z0-9][a-z0-9._:-]{2,127}$'
     OR p_stream_sequence < 1
     OR p_processed_at IS NULL
     OR p_processed_at > clock_timestamp() + interval '2 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'CERTIFICATE_FEEDBACK_REQUEST_INVALID';
  END IF;

  SELECT event.* INTO v_event
  FROM identity.certificate_event_outbox AS outbox
  JOIN identity.certificate_lifecycle_events AS event
    ON event.tenant_id = outbox.tenant_id AND event.event_id = outbox.event_id
  WHERE outbox.tenant_id = p_tenant_id
    AND outbox.event_id = p_lifecycle_event_id
    AND outbox.status = 'published'
    AND outbox.stream_sequence = p_stream_sequence
    AND outbox.signed_event_sha256 = p_signed_event_sha256
    AND outbox.published_at <= p_processed_at + interval '2 seconds'
  FOR SHARE OF outbox, event;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'CERTIFICATE_FEEDBACK_NOT_AUTHORITATIVE';
  END IF;

  v_evidence_id := ('evd_' || substring(v_event.event_id::text from 5))::trust.evidence_id;
  CASE v_event.event_type
    WHEN 'issued' THEN v_kind := 'certificate-issued'; v_score := 100; v_terminal := false;
    WHEN 'renewed' THEN v_kind := 'certificate-renewed'; v_score := 100; v_terminal := false;
    WHEN 'superseded' THEN v_kind := 'certificate-superseded'; v_score := 100; v_terminal := true;
    WHEN 'revoked' THEN v_kind := 'certificate-revoked'; v_score := 0; v_terminal := true;
    WHEN 'expired' THEN v_kind := 'certificate-expired'; v_score := 0; v_terminal := true;
    ELSE
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'CERTIFICATE_FEEDBACK_EVENT_INVALID';
  END CASE;

  IF v_event.event_type = 'revoked' THEN
    SELECT action.action_id INTO v_source_action_id
    FROM orchestration.security_actions AS action
    WHERE action.tenant_id = v_event.tenant_id
      AND action.target_subject_id = v_event.subject_id
      AND action.target_certificate_id = v_event.certificate_id
      AND action.action_type = 'revoke-certificate'
      AND action.status = 'succeeded'
      AND action.external_reference = v_event.event_id::text;
  END IF;

  INSERT INTO trust.certificate_lifecycle_evidence (
    tenant_id, evidence_id, lifecycle_event_id, causal_parent_event_id,
    correlation_id, subject_id, certificate_id, event_type, certificate_state,
    evidence_kind, component_score, terminal, security_action_eligible,
    source_action_id, consumer_name, stream_sequence, signed_event_sha256,
    observed_at, processed_at
  ) VALUES (
    v_event.tenant_id, v_evidence_id, v_event.event_id, v_event.causation_event_id,
    v_event.correlation_id, v_event.subject_id, v_event.certificate_id,
    v_event.event_type, v_event.certificate_state, v_kind, v_score, v_terminal,
    false, v_source_action_id, p_consumer_name, p_stream_sequence,
    p_signed_event_sha256, v_event.occurred_at, p_processed_at
  )
  ON CONFLICT ON CONSTRAINT certificate_lifecycle_evidence_event_unique DO NOTHING
  RETURNING * INTO v_evidence;
  GET DIAGNOSTICS v_inserted = ROW_COUNT;

  IF v_inserted = 0 THEN
    SELECT * INTO v_evidence FROM trust.certificate_lifecycle_evidence AS evidence
    WHERE evidence.tenant_id = v_event.tenant_id
      AND evidence.lifecycle_event_id = v_event.event_id;
    IF NOT FOUND
       OR v_evidence.evidence_id <> v_evidence_id
       OR v_evidence.causal_parent_event_id IS DISTINCT FROM v_event.causation_event_id
       OR v_evidence.correlation_id <> v_event.correlation_id
       OR v_evidence.subject_id <> v_event.subject_id
       OR v_evidence.certificate_id <> v_event.certificate_id
       OR v_evidence.event_type <> v_event.event_type
       OR v_evidence.certificate_state <> v_event.certificate_state
       OR v_evidence.evidence_kind <> v_kind
       OR v_evidence.component_score <> v_score
       OR v_evidence.terminal <> v_terminal
       OR v_evidence.security_action_eligible <> false
       OR v_evidence.source_action_id IS DISTINCT FROM v_source_action_id
       OR v_evidence.stream_sequence <> p_stream_sequence
       OR v_evidence.signed_event_sha256 <> p_signed_event_sha256 THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'CERTIFICATE_FEEDBACK_IDEMPOTENCY_CONFLICT';
    END IF;
  END IF;

  RETURN QUERY SELECT v_inserted = 1,
    CASE WHEN v_inserted = 1 THEN 'recorded'::text ELSE 'duplicate'::text END,
    v_evidence.tenant_id, v_evidence.subject_id, v_evidence.certificate_id,
    v_evidence.evidence_id, v_evidence.lifecycle_event_id,
    v_evidence.causal_parent_event_id, v_evidence.evidence_kind,
    v_evidence.component_score, v_evidence.terminal,
    v_evidence.security_action_eligible, v_evidence.source_action_id;
END
$function$;

ALTER TABLE trust.certificate_lifecycle_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.certificate_lifecycle_evidence FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE trust.certificate_lifecycle_evidence FROM PUBLIC,
  tenant_trust_app, tenant_trust_trust_engine,
  tenant_trust_evidence_event_consumer, tenant_trust_certificate_feedback_consumer;
REVOKE ALL ON FUNCTION trust.prevent_certificate_lifecycle_evidence_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION trust.record_certificate_lifecycle_evidence(
  text, identity.tenant_id, identity.event_id, bigint,
  identity.sha256_digest, timestamptz
) FROM PUBLIC;

GRANT USAGE ON SCHEMA trust TO tenant_trust_certificate_feedback_consumer;
GRANT EXECUTE ON FUNCTION trust.record_certificate_lifecycle_evidence(
  text, identity.tenant_id, identity.event_id, bigint,
  identity.sha256_digest, timestamptz
) TO tenant_trust_certificate_feedback_consumer;

COMMENT ON TABLE trust.certificate_lifecycle_evidence IS
  'Immutable exactly-once trust feedback derived only from authenticated published certificate lifecycle outcomes';
COMMENT ON FUNCTION trust.record_certificate_lifecycle_evidence(
  text, identity.tenant_id, identity.event_id, bigint,
  identity.sha256_digest, timestamptz
) IS
  'Records one authoritative lifecycle outcome as non-recursive certificate evidence with its immediate causal parent and optional source action';
