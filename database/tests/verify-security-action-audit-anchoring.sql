\set ON_ERROR_STOP on

DO $privileges$
BEGIN
  IF has_table_privilege('tenant_trust_security_action_audit_projector',
       'audit.security_action_audit_events', 'SELECT')
     OR has_table_privilege('tenant_trust_security_action_audit_projector',
       'audit.fabric_commitment_outbox', 'INSERT') THEN
    RAISE EXCEPTION 'security-action audit projector received direct table privileges';
  END IF;
  IF NOT has_function_privilege('tenant_trust_security_action_audit_projector',
       'audit.get_pending_security_action_audit_event()','EXECUTE')
     OR NOT has_function_privilege('tenant_trust_security_action_audit_projector',
       'audit.record_security_action_audit_commitment(identity.tenant_id,identity.event_id,text,jsonb,text,text,identity.sha256_digest,identity.sha256_digest,jsonb,timestamptz)','EXECUTE') THEN
    RAISE EXCEPTION 'security-action audit projector lacks its bounded functions';
  END IF;
  IF NOT has_function_privilege('tenant_trust_audit_verifier',
       'audit.list_security_action_audit_expectations(identity.tenant_id,identity.correlation_id)','EXECUTE')
     OR NOT has_function_privilege('tenant_trust_audit_verifier',
       'audit.list_security_action_audit_records(identity.tenant_id,identity.correlation_id)','EXECUTE') THEN
    RAISE EXCEPTION 'audit verifier lacks action expectation readers';
  END IF;
END
$privileges$;

BEGIN;

DO $fixture$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  INSERT INTO identity.tenants (tenant_id, tenant_slug, display_name, created_at, updated_at)
  VALUES ('tnt_018f1234-5678-7abc-8def-012345678c00',
    'action-audit-verifier', 'Action Audit Verifier', v_now, v_now);
  INSERT INTO identity.subjects (
    subject_id, identity_provider, provider_subject, display_name, created_at, updated_at
  ) VALUES ('sub_018f1234-5678-7abc-8def-012345678c01', 'verification',
    'action-audit-target', 'Action Audit Target', v_now, v_now);
  INSERT INTO identity.tenant_memberships (tenant_id, subject_id, created_at, updated_at)
  VALUES ('tnt_018f1234-5678-7abc-8def-012345678c00',
    'sub_018f1234-5678-7abc-8def-012345678c01', v_now, v_now);
  INSERT INTO identity.tenant_issuer_mappings (
    tenant_id, issuer_id, issuer_name, authority_url, state,
    root_certificate_sha256, created_at, updated_at
  ) VALUES ('tnt_018f1234-5678-7abc-8def-012345678c00',
    'iss_018f1234-5678-7abc-8def-012345678c02', 'action-audit-verifier',
    'https://ca.action-audit.invalid', 'active', repeat('1',64), v_now, v_now);
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after, issued_at,
    state_changed_at, requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version, created_at, updated_at
  ) VALUES ('tnt_018f1234-5678-7abc-8def-012345678c00',
    'crt_018f1234-5678-7abc-8def-012345678c03',
    'sub_018f1234-5678-7abc-8def-012345678c01',
    'iss_018f1234-5678-7abc-8def-012345678c02', 'tenant-client-auth-v1',
    'C0000000000000000000000000000001', repeat('2',64), 'ed25519', 'active',
    v_now - interval '1 minute', v_now + interval '1 hour', v_now - interval '1 minute',
    v_now - interval '1 minute', 'sub_018f1234-5678-7abc-8def-012345678c01',
    'req_018f1234-5678-7abc-8def-012345678c04', 'action-audit-certificate',
    'evt_018f1234-5678-7abc-8def-012345678c05',
    'evt_018f1234-5678-7abc-8def-012345678c05',
    'cor_018f1234-5678-7abc-8def-012345678c06', 1, v_now, v_now);
  INSERT INTO orchestration.subject_security_states (
    tenant_id, subject_id, certificate_id, state_version, updated_at
  ) VALUES ('tnt_018f1234-5678-7abc-8def-012345678c00',
    'sub_018f1234-5678-7abc-8def-012345678c01',
    'crt_018f1234-5678-7abc-8def-012345678c03', 1, v_now);

  INSERT INTO audit.fabric_commitment_outbox (
    tenant_id, event_id, channel_name, event_type, record_type,
    event_document, canonical_preimage_json, ledger_key,
    event_key_hash_sha256, commitment_hash_sha256, ledger_value,
    next_attempt_at, created_at, updated_at
  ) VALUES ('tnt_018f1234-5678-7abc-8def-012345678c00',
    'evt_018f1234-5678-7abc-8def-012345678c07', 'tt-audit-action-test-v1',
    'access.decided.v1', 'access-decision', jsonb_build_object(
      'schemaVersion','1.0.0','eventId','evt_018f1234-5678-7abc-8def-012345678c07',
      'eventType','access.decided.v1','tenantId','tnt_018f1234-5678-7abc-8def-012345678c00',
      'subjectId','sub_018f1234-5678-7abc-8def-012345678c01',
      'aggregateId','dec_018f1234-5678-7abc-8def-012345678c08',
      'correlationId','cor_018f1234-5678-7abc-8def-012345678c09',
      'causationId',NULL,'idempotencyKey','action-audit-decision',
      'occurredAt',to_char((v_now - interval '1 second') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'recordedAt',to_char((v_now - interval '1 second') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'producer',jsonb_build_object('service','action-audit-test','instanceId','database-1'),
      'payload',jsonb_build_object('decisionId','dec_018f1234-5678-7abc-8def-012345678c08',
        'certificateId','crt_018f1234-5678-7abc-8def-012345678c03')
    ), '{"decision":true}',
    'audit~access-decision~aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    repeat('a',64), repeat('b',64), jsonb_build_object(
      'canonicalizationProfile','tenant-trust-audit-commitment-json-v1',
      'commitmentHashSha256',repeat('b',64),'digestAlgorithm','sha256',
      'eventKeyHashSha256',repeat('a',64),'recordType','access-decision','schemaVersion','1.0.0'
    ), v_now - interval '1 second', v_now - interval '1 second', v_now - interval '1 second');

  INSERT INTO orchestration.security_actions (
    tenant_id, action_id, decision_id, correlation_id, target_subject_id,
    target_certificate_id, action_type, authority_class, reason_code,
    trigger_context_hash_sha256, expected_state_version, next_attempt_at,
    requested_at, created_at, updated_at
  ) VALUES ('tnt_018f1234-5678-7abc-8def-012345678c00',
    'act_018f1234-5678-7abc-8def-012345678c10',
    'dec_018f1234-5678-7abc-8def-012345678c08',
    'cor_018f1234-5678-7abc-8def-012345678c09',
    'sub_018f1234-5678-7abc-8def-012345678c01',
    'crt_018f1234-5678-7abc-8def-012345678c03', 'restrict-access',
    'policy-quarantine', 'TRUST_RESTRICTED', repeat('3',64), 1, v_now, v_now, v_now, v_now);
END
$fixture$;

DO $captured$
DECLARE v_count integer;
BEGIN
  SELECT count(*) INTO v_count FROM audit.security_action_audit_events
  WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-012345678c00'
    AND action_id = 'act_018f1234-5678-7abc-8def-012345678c10'
    AND event_type = 'security-action.requested.v1';
  IF v_count <> 1 THEN RAISE EXCEPTION 'requested action event was not captured exactly once'; END IF;
  IF (SELECT count(*) FROM audit.list_security_action_audit_expectations(
      'tnt_018f1234-5678-7abc-8def-012345678c00',
      'cor_018f1234-5678-7abc-8def-012345678c09')) <> 1 THEN
    RAISE EXCEPTION 'missing action commitment was not visible to verification';
  END IF;
END
$captured$;

SET LOCAL ROLE tenant_trust_security_action_audit_projector;
DO $project_requested$
DECLARE v_source record; v_event jsonb; v_result record;
BEGIN
  SELECT * INTO v_source FROM audit.get_pending_security_action_audit_event();
  IF v_source.action_id <> 'act_018f1234-5678-7abc-8def-012345678c10'
     OR v_source.causation_event_id <> 'evt_018f1234-5678-7abc-8def-012345678c07' THEN
    RAISE EXCEPTION 'projector did not resolve the exact decision cause';
  END IF;
  v_event := jsonb_build_object(
    'schemaVersion','1.0.0','eventId',v_source.event_id,'eventType',v_source.event_type,
    'tenantId',v_source.tenant_id,'subjectId',v_source.target_subject_id,
    'aggregateId',v_source.action_id,'correlationId',v_source.correlation_id,
    'causationId',v_source.causation_event_id,
    'idempotencyKey','security-action-audit:' || v_source.action_id || ':requested:0',
    'occurredAt',to_char(date_trunc('milliseconds',v_source.occurred_at) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'recordedAt',to_char(date_trunc('milliseconds',v_source.recorded_at) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'producer',jsonb_build_object('service','security-action-audit','instanceId','projection-v1'),
    'payload',jsonb_build_object(
      'actionId',v_source.action_id,'decisionId',v_source.decision_id,
      'actionType',v_source.action_type,'status',v_source.event_status,
      'targetCertificateId',v_source.target_certificate_id,'reasonCode',v_source.reason_code,
      'authorityClass',v_source.authority_class,'attemptNumber',v_source.attempt_number,
      'recoveryAuthorizationId',NULL,'recoveryTrustTransitionId',NULL,
      'authorizedBySubjectId',NULL,'causeResolutionReference',NULL,
      'externalReference',NULL,'certificateEventId',NULL
    )
  );
  SELECT * INTO v_result FROM audit.record_security_action_audit_commitment(
    v_source.tenant_id, v_source.event_id, 'tt-audit-action-test-v1', v_event,
    '{"requested":true}',
    'audit~security-action~cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    repeat('c',64), repeat('d',64), jsonb_build_object(
      'canonicalizationProfile','tenant-trust-audit-commitment-json-v1',
      'commitmentHashSha256',repeat('d',64),'digestAlgorithm','sha256',
      'eventKeyHashSha256',repeat('c',64),'recordType','security-action','schemaVersion','1.0.0'
    ), clock_timestamp()
  );
  IF v_result.status <> 'pending' THEN RAISE EXCEPTION 'requested event was not queued'; END IF;
END
$project_requested$;

RESET ROLE;
DO $complete_action$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  UPDATE orchestration.security_actions SET status='executing', attempt_count=1,
    claimed_by='action-audit.worker',
    claim_token='clm_018f1234-5678-7abc-8def-012345678c11',
    claimed_at=v_now, lease_expires_at=v_now + interval '5 minutes', updated_at=v_now
  WHERE tenant_id='tnt_018f1234-5678-7abc-8def-012345678c00'
    AND action_id='act_018f1234-5678-7abc-8def-012345678c10';
  INSERT INTO orchestration.security_action_attempts (
    tenant_id, action_id, attempt_number, claim_token, worker_id, status, started_at
  ) VALUES ('tnt_018f1234-5678-7abc-8def-012345678c00',
    'act_018f1234-5678-7abc-8def-012345678c10',1,
    'clm_018f1234-5678-7abc-8def-012345678c11','action-audit.worker','executing',v_now);
  UPDATE orchestration.security_action_attempts SET status='succeeded',completed_at=v_now
  WHERE tenant_id='tnt_018f1234-5678-7abc-8def-012345678c00'
    AND action_id='act_018f1234-5678-7abc-8def-012345678c10' AND attempt_number=1;
  UPDATE orchestration.security_actions SET status='succeeded', claimed_by=NULL,
    claim_token=NULL, claimed_at=NULL, lease_expires_at=NULL,
    result_state='{"access":"restricted","renewal":"allowed","targetCertificate":"active","replacement":"not-required"}',
    succeeded_at=v_now, updated_at=v_now
  WHERE tenant_id='tnt_018f1234-5678-7abc-8def-012345678c00'
    AND action_id='act_018f1234-5678-7abc-8def-012345678c10';
END
$complete_action$;

SET LOCAL ROLE tenant_trust_security_action_audit_projector;
DO $project_terminal$
DECLARE v_source record; v_event jsonb; v_result record;
BEGIN
  SELECT * INTO v_source FROM audit.get_pending_security_action_audit_event();
  IF v_source.event_type <> 'security-action.succeeded.v1'
     OR v_source.causation_event_id IS NULL THEN
    RAISE EXCEPTION 'terminal action event did not link to the requested event';
  END IF;
  v_event := jsonb_build_object(
    'schemaVersion','1.0.0','eventId',v_source.event_id,'eventType',v_source.event_type,
    'tenantId',v_source.tenant_id,'subjectId',v_source.target_subject_id,
    'aggregateId',v_source.action_id,'correlationId',v_source.correlation_id,
    'causationId',v_source.causation_event_id,
    'idempotencyKey','security-action-audit:' || v_source.action_id || ':succeeded:1',
    'occurredAt',to_char(date_trunc('milliseconds',v_source.occurred_at) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'recordedAt',to_char(date_trunc('milliseconds',v_source.recorded_at) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'producer',jsonb_build_object('service','security-action-audit','instanceId','projection-v1'),
    'payload',jsonb_build_object(
      'actionId',v_source.action_id,'decisionId',v_source.decision_id,
      'actionType',v_source.action_type,'status',v_source.event_status,
      'targetCertificateId',v_source.target_certificate_id,'reasonCode',v_source.reason_code,
      'authorityClass',v_source.authority_class,'attemptNumber',v_source.attempt_number,
      'recoveryAuthorizationId',NULL,'recoveryTrustTransitionId',NULL,
      'authorizedBySubjectId',NULL,'causeResolutionReference',NULL,
      'externalReference',NULL,'certificateEventId',NULL
    )
  );
  SELECT * INTO v_result FROM audit.record_security_action_audit_commitment(
    v_source.tenant_id, v_source.event_id, 'tt-audit-action-test-v1', v_event,
    '{"succeeded":true}',
    'audit~security-action~eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    repeat('e',64), repeat('f',64), jsonb_build_object(
      'canonicalizationProfile','tenant-trust-audit-commitment-json-v1',
      'commitmentHashSha256',repeat('f',64),'digestAlgorithm','sha256',
      'eventKeyHashSha256',repeat('e',64),'recordType','security-action','schemaVersion','1.0.0'
    ), clock_timestamp()
  );
  IF v_result.status <> 'pending' THEN RAISE EXCEPTION 'terminal event was not queued'; END IF;
END
$project_terminal$;

RESET ROLE;
DO $verify$
DECLARE v_expected integer; v_records integer;
BEGIN
  SELECT count(*) INTO v_expected FROM audit.list_security_action_audit_expectations(
    'tnt_018f1234-5678-7abc-8def-012345678c00',
    'cor_018f1234-5678-7abc-8def-012345678c09');
  SELECT count(*) INTO v_records FROM audit.list_security_action_audit_records(
    'tnt_018f1234-5678-7abc-8def-012345678c00',
    'cor_018f1234-5678-7abc-8def-012345678c09');
  IF v_expected <> 2 OR v_records <> 3 THEN
    RAISE EXCEPTION 'bounded verification bundle did not include two actions and their decision cause';
  END IF;
  BEGIN
    UPDATE audit.security_action_audit_events SET reason_code='CHANGED'
    WHERE tenant_id='tnt_018f1234-5678-7abc-8def-012345678c00';
    RAISE EXCEPTION 'immutable action expectation was mutable';
  EXCEPTION WHEN SQLSTATE '55000' THEN NULL;
  END;
END
$verify$;

ROLLBACK;
\echo 'Verified immutable action capture, least-privilege projection, exact causation and visible verification expectations.'
