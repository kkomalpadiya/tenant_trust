\set ON_ERROR_STOP on

BEGIN;

DO $fixture$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_action orchestration.security_actions%ROWTYPE;
BEGIN
  INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name, created_at, updated_at)
  VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'feedback-verifier', 'Feedback Verifier', v_now, v_now
  );
  INSERT INTO identity.subjects (
    subject_id, identity_provider, provider_subject, display_name, created_at, updated_at
  ) VALUES (
    'sub_018f1234-5678-7abc-8def-0123456789d0',
    'verification', 'feedback-verifier', 'Feedback Verifier', v_now, v_now
  );
  INSERT INTO identity.tenant_memberships (tenant_id, subject_id, created_at, updated_at)
  VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'sub_018f1234-5678-7abc-8def-0123456789d0', v_now, v_now
  );
  INSERT INTO identity.tenant_role_assignments (tenant_id, subject_id, role_name)
  VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'sub_018f1234-5678-7abc-8def-0123456789d0', 'tenant-member'
  );
  INSERT INTO identity.tenant_issuer_mappings (
    tenant_id, issuer_id, issuer_name, authority_url, state,
    root_certificate_sha256, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'iss_018f1234-5678-7abc-8def-0123456789d0',
    'feedback-verifier', 'https://feedback.verifier.invalid', 'active', repeat('1', 64),
    v_now, v_now
  );
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after, issued_at,
    state_changed_at, requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'crt_018f1234-5678-7abc-8def-0123456789d0',
    'sub_018f1234-5678-7abc-8def-0123456789d0',
    'iss_018f1234-5678-7abc-8def-0123456789d0',
    'tenant-client-auth-v1', 'D0000000000000000000000000000001', repeat('2', 64),
    'ed25519', 'revoked', v_now - interval '1 hour', v_now + interval '1 hour',
    v_now - interval '30 minutes', v_now - interval '1 minute',
    'sub_018f1234-5678-7abc-8def-0123456789d0',
    'req_018f1234-5678-7abc-8def-0123456789d0', 'feedback-verifier-certificate',
    'evt_018f1234-5678-7abc-8def-0123456789d0',
    'evt_018f1234-5678-7abc-8def-0123456789d1',
    'cor_018f1234-5678-7abc-8def-0123456789d0', 2, v_now, v_now
  );

  INSERT INTO identity.certificate_lifecycle_events (
    tenant_id, event_id, certificate_id, event_type, certificate_state,
    subject_id, issuer_id, serial_number, fingerprint_sha256, not_after,
    request_id, correlation_id, causation_event_id, idempotency_key,
    actor_subject_id, reason_code, occurred_at, recorded_at, issuer_confirmation_id
  ) VALUES
  (
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'evt_018f1234-5678-7abc-8def-0123456789d0',
    'crt_018f1234-5678-7abc-8def-0123456789d0', 'issued', 'active',
    'sub_018f1234-5678-7abc-8def-0123456789d0',
    'iss_018f1234-5678-7abc-8def-0123456789d0',
    'D0000000000000000000000000000001', repeat('2', 64), v_now + interval '1 hour',
    'req_018f1234-5678-7abc-8def-0123456789d0',
    'cor_018f1234-5678-7abc-8def-0123456789d0', NULL,
    'feedback-verifier-issued-event',
    'sub_018f1234-5678-7abc-8def-0123456789d0', NULL,
    v_now - interval '30 minutes', v_now - interval '30 minutes', NULL
  ),
  (
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'evt_018f1234-5678-7abc-8def-0123456789d1',
    'crt_018f1234-5678-7abc-8def-0123456789d0', 'revoked', 'revoked',
    'sub_018f1234-5678-7abc-8def-0123456789d0',
    'iss_018f1234-5678-7abc-8def-0123456789d0',
    'D0000000000000000000000000000001', repeat('2', 64), v_now + interval '1 hour',
    'req_018f1234-5678-7abc-8def-0123456789d1',
    'cor_018f1234-5678-7abc-8def-0123456789d2',
    'evt_018f1234-5678-7abc-8def-0123456789d0',
    'feedback-verifier-revoked-event',
    'sub_018f1234-5678-7abc-8def-0123456789d0', 'KEY_COMPROMISE',
    v_now - interval '1 minute', v_now - interval '1 minute',
    'step-ca:feedback-verifier-revocation'
  );

  UPDATE identity.certificate_event_outbox SET
    status = 'published', stream_sequence = 77,
    signed_event_sha256 = repeat('b', 64), published_at = v_now,
    updated_at = v_now
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789d0'
    AND event_id = 'evt_018f1234-5678-7abc-8def-0123456789d1';

  v_action := orchestration.enqueue_security_action_internal(
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'act_018f1234-5678-7abc-8def-0123456789d3',
    'dec_018f1234-5678-7abc-8def-0123456789d4',
    'cor_018f1234-5678-7abc-8def-0123456789d2',
    'sub_018f1234-5678-7abc-8def-0123456789d0',
    'crt_018f1234-5678-7abc-8def-0123456789d0',
    'revoke-certificate', 'severity-rule', 'CORROBORATED_CRITICAL_EVIDENCE',
    repeat('c', 64), v_now
  );
  UPDATE orchestration.security_actions SET
    status = 'succeeded', external_reference = 'evt_018f1234-5678-7abc-8def-0123456789d1',
    result_state = '{"access":"suspended","renewal":"blocked","targetCertificate":"revoked","replacement":"required"}',
    succeeded_at = v_now, updated_at = v_now
  WHERE tenant_id = v_action.tenant_id AND action_id = v_action.action_id;
END
$fixture$;

DO $privileges$
BEGIN
  IF has_table_privilege('tenant_trust_app', 'trust.certificate_lifecycle_evidence', 'SELECT')
     OR has_table_privilege('tenant_trust_trust_engine', 'trust.certificate_lifecycle_evidence', 'INSERT')
     OR has_table_privilege('tenant_trust_certificate_feedback_consumer', 'trust.certificate_lifecycle_evidence', 'INSERT') THEN
    RAISE EXCEPTION 'certificate feedback table exposes direct privileges';
  END IF;
END
$privileges$;

SET LOCAL ROLE tenant_trust_certificate_feedback_consumer;

DO $record_and_replay$
DECLARE v_feedback record;
BEGIN
  SELECT * INTO v_feedback FROM trust.record_certificate_lifecycle_evidence(
    'trust-feedback.verify',
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'evt_018f1234-5678-7abc-8def-0123456789d1',
    77, repeat('b', 64), clock_timestamp()
  );
  IF NOT v_feedback.applied OR v_feedback.outcome_code <> 'recorded'
     OR v_feedback.evidence_id <> 'evd_018f1234-5678-7abc-8def-0123456789d1'
     OR v_feedback.causal_parent_event_id <> 'evt_018f1234-5678-7abc-8def-0123456789d0'
     OR v_feedback.evidence_kind <> 'certificate-revoked'
     OR v_feedback.component_score <> 0 OR NOT v_feedback.terminal
     OR v_feedback.security_action_eligible
     OR v_feedback.source_action_id <> 'act_018f1234-5678-7abc-8def-0123456789d3' THEN
    RAISE EXCEPTION 'validated revocation did not produce exact causal non-recursive trust evidence';
  END IF;

  SELECT * INTO v_feedback FROM trust.record_certificate_lifecycle_evidence(
    'trust-feedback.verify',
    'tnt_018f1234-5678-7abc-8def-0123456789d0',
    'evt_018f1234-5678-7abc-8def-0123456789d1',
    77, repeat('b', 64), clock_timestamp()
  );
  IF v_feedback.applied OR v_feedback.outcome_code <> 'duplicate' THEN
    RAISE EXCEPTION 'certificate lifecycle redelivery applied a duplicate trust effect';
  END IF;

  BEGIN
    PERFORM trust.record_certificate_lifecycle_evidence(
      'trust-feedback.verify',
      'tnt_018f1234-5678-7abc-8def-0123456789d0',
      'evt_018f1234-5678-7abc-8def-0123456789d1',
      78, repeat('b', 64), clock_timestamp()
    );
    RAISE EXCEPTION 'unpublished stream identity was accepted';
  EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM <> 'CERTIFICATE_FEEDBACK_NOT_AUTHORITATIVE' THEN RAISE; END IF;
  END;
END
$record_and_replay$;

RESET ROLE;

DO $append_only_and_count$
BEGIN
  IF (SELECT count(*) FROM trust.certificate_lifecycle_evidence
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789d0') <> 1 THEN
    RAISE EXCEPTION 'certificate lifecycle evidence count is not exactly one';
  END IF;
  BEGIN
    UPDATE trust.certificate_lifecycle_evidence SET component_score = 50
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789d0';
    RAISE EXCEPTION 'certificate lifecycle evidence was mutable';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$append_only_and_count$;

ROLLBACK;
\echo 'Verified authenticated lifecycle feedback, causal action binding, exact replay suppression and non-recursive trust evidence.'
