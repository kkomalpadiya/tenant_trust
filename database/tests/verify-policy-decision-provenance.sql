\set ON_ERROR_STOP on

BEGIN;

DO $fixture$
DECLARE
  v_now timestamptz := clock_timestamp();
BEGIN
  INSERT INTO identity.certificates (
    tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
    fingerprint_sha256, public_key_algorithm, state, not_before, not_after, issued_at,
    state_changed_at, requested_by_subject_id, request_id, idempotency_key,
    issued_event_id, last_event_id, correlation_id, version, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'crt_018f1234-5678-7abc-8def-0123456789f1',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-client-auth-v1', '10000000000000000000000000000011', repeat('1', 64),
    'ed25519', 'active', v_now - interval '1 hour', v_now + interval '1 hour',
    v_now - interval '30 minutes', v_now - interval '30 minutes',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'req_018f1234-5678-7abc-8def-0123456789f1', 'verify-policy-provenance-certificate',
    'evt_018f1234-5678-7abc-8def-0123456789f1',
    'evt_018f1234-5678-7abc-8def-0123456789f1',
    'cor_018f1234-5678-7abc-8def-0123456789f1', 1,
    v_now - interval '30 minutes', v_now - interval '30 minutes'
  );

  INSERT INTO trust.subject_trust_state_versions (
    tenant_id, subject_id, update_version, model_version, configuration_version,
    identity_component, device_component, behaviour_component, certificate_component,
    compliance_component, observed_at, recorded_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ac', 9101, '1.0.0', 1,
    90, 90, 90, 90, 90, v_now - interval '1 minute', v_now
  );

  INSERT INTO trust.subject_trust_transitions (
    tenant_id, subject_id, transition_id, event_id, update_version,
    previous_transition_id, previous_score, previous_band, previous_recovery_streak,
    new_score, new_band, new_recovery_streak, weighted_score, smoothed_score,
    transition_kind, model_version, configuration_version, observed_at, evaluated_at,
    explanation_json, explanation_hash_sha256, recorded_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'trn_018f1234-5678-7abc-8def-0123456789f1',
    'evt_018f1234-5678-7abc-8def-0123456789f2', 9101,
    NULL, 85, 'uninitialized', 0, 90, 'high', 0, 90, 90,
    'recovered', '1.0.0', 1, v_now - interval '1 minute', v_now,
    '{}', repeat('2', 64), v_now
  );

  INSERT INTO trust.policy_versions (
    tenant_id, policy_version_id, policy_name, bundle_version, bundle_hash_sha256,
    entrypoint, state, published_by_subject_id, created_at, updated_at
  ) VALUES (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'pol_018f1234-5678-7abc-8def-0123456789f1', 'access-control', 9101,
    repeat('3', 64), 'tenant_trust/authorization/decision', 'published',
    'sub_018f1234-5678-7abc-8def-0123456789ac', v_now, v_now
  );
END
$fixture$;

DO $verify_privileges$
BEGIN
  IF has_table_privilege('tenant_trust_app', 'audit.policy_decision_provenance', 'SELECT')
     OR has_table_privilege('tenant_trust_app', 'audit.policy_decision_provenance', 'INSERT')
     OR has_table_privilege('tenant_trust_app', 'audit.policy_decision_provenance', 'UPDATE')
     OR has_table_privilege('tenant_trust_app', 'audit.policy_decision_provenance', 'DELETE')
     OR NOT has_function_privilege(
       'tenant_trust_app',
       'audit.record_policy_decision_provenance(text,identity.sha256_digest)',
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'policy provenance least-privilege boundary is incorrect';
  END IF;
END
$verify_privileges$;

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $verify_recording$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_tenant_version bigint;
  v_subject_version bigint;
  v_membership_version bigint;
  v_document jsonb;
  v_canonical text;
  v_hash identity.sha256_digest;
  v_row audit.policy_decision_provenance%ROWTYPE;
  v_tampered jsonb;
  v_tampered_canonical text;
  v_tampered_hash identity.sha256_digest;
BEGIN
  SELECT tenant.version, subject.version, membership.version
  INTO v_tenant_version, v_subject_version, v_membership_version
  FROM identity.tenants AS tenant
  JOIN identity.tenant_memberships AS membership ON membership.tenant_id = tenant.tenant_id
  JOIN identity.subjects AS subject ON subject.subject_id = membership.subject_id
  WHERE tenant.tenant_id = identity.current_tenant_id()
    AND subject.subject_id = identity.current_subject_id();

  v_document := jsonb_build_object(
    'schemaVersion', '1.0.0',
    'provenanceType', 'authorization-decision',
    'canonicalizationProfile', 'tenant-trust-authorization-decision-provenance-json-v1',
    'decision', jsonb_build_object(
      'contractId', 'opa-decision-output-v1',
      'decisionId', 'dec_018f1234-5678-7abc-8def-0123456789f3',
      'outcome', 'ALLOW',
      'reasonCodes', jsonb_build_array('POLICY_ALLOW'),
      'obligations', jsonb_build_object('stepUp', NULL, 'quarantine', NULL),
      'evaluatedAt', v_now
    ),
    'request', jsonb_build_object(
      'requestId', 'req_018f1234-5678-7abc-8def-0123456789f3',
      'correlationId', 'cor_018f1234-5678-7abc-8def-0123456789f3',
      'requestedAt', v_now - interval '50 milliseconds',
      'method', 'GET',
      'routeTemplate', '/v1/profile',
      'sourceNetworkZone', 'unknown',
      'tenantId', identity.current_tenant_id(),
      'subjectId', identity.current_subject_id(),
      'action', 'profile:read',
      'resource', jsonb_build_object(
        'resourceType', 'subject-profile',
        'resourceIdHashSha256', repeat('4', 64),
        'sensitivity', 'confidential',
        'scope', 'self',
        'ownerSubjectId', identity.current_subject_id()
      ),
      'stepUp', jsonb_build_object(
        'status', 'absent', 'proofIdHashSha256', NULL, 'tenantId', NULL,
        'subjectId', NULL, 'action', NULL, 'sessionIdHashSha256', NULL,
        'verifiedAt', NULL, 'expiresAt', NULL
      )
    ),
    'identityState', jsonb_build_object(
      'certificateId', 'crt_018f1234-5678-7abc-8def-0123456789f1',
      'certificateStatusVersion', 1,
      'tenantVersion', v_tenant_version,
      'subjectVersion', v_subject_version,
      'membershipVersion', v_membership_version
    ),
    'trustState', jsonb_build_object(
      'transitionId', 'trn_018f1234-5678-7abc-8def-0123456789f1',
      'updateVersion', 9101,
      'modelVersion', '1.0.0',
      'configurationVersion', 1,
      'explanationHashSha256', repeat('2', 64)
    ),
    'policy', jsonb_build_object(
      'policyVersionId', 'pol_018f1234-5678-7abc-8def-0123456789f1',
      'bundleVersion', 9101,
      'bundleHashSha256', repeat('3', 64),
      'decisionPath', 'tenant_trust/authorization/decision'
    ),
    'input', jsonb_build_object(
      'contractId', 'opa-decision-input-v1',
      'hashSha256', repeat('5', 64)
    )
  );
  v_canonical := v_document::text;
  v_hash := encode(public.digest(convert_to(v_canonical, 'UTF8'), 'sha256'), 'hex');

  SELECT * INTO v_row
  FROM audit.record_policy_decision_provenance(v_canonical, v_hash);
  IF v_row.decision_id <> 'dec_018f1234-5678-7abc-8def-0123456789f3'
     OR v_row.request_id <> 'req_018f1234-5678-7abc-8def-0123456789f3'
     OR v_row.correlation_id <> 'cor_018f1234-5678-7abc-8def-0123456789f3'
     OR v_row.trust_transition_id <> 'trn_018f1234-5678-7abc-8def-0123456789f1'
     OR v_row.trust_update_version <> 9101
     OR v_row.trust_explanation_hash_sha256 <> repeat('2', 64)
     OR v_row.policy_version_id <> 'pol_018f1234-5678-7abc-8def-0123456789f1'
     OR v_row.policy_bundle_version <> 9101
     OR v_row.policy_input_hash_sha256 <> repeat('5', 64)
     OR v_row.outcome <> 'ALLOW'
     OR v_row.provenance_hash_sha256 <> v_hash THEN
    RAISE EXCEPTION 'policy decision provenance did not preserve exact bindings';
  END IF;

  SELECT * INTO v_row
  FROM audit.record_policy_decision_provenance(v_canonical, v_hash);
  IF v_row.provenance_hash_sha256 <> v_hash THEN
    RAISE EXCEPTION 'exact policy decision replay did not return its original row';
  END IF;

  BEGIN
    PERFORM audit.record_policy_decision_provenance(v_canonical, repeat('9', 64));
    RAISE EXCEPTION 'incorrect provenance digest was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  v_tampered := jsonb_set(v_document, '{decision,reasonCodes}', '["DIFFERENT_REASON"]'::jsonb);
  v_tampered_canonical := v_tampered::text;
  v_tampered_hash := encode(public.digest(convert_to(v_tampered_canonical, 'UTF8'), 'sha256'), 'hex');
  BEGIN
    PERFORM audit.record_policy_decision_provenance(v_tampered_canonical, v_tampered_hash);
    RAISE EXCEPTION 'conflicting decision replay was accepted';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM <> 'POLICY_DECISION_PROVENANCE_CONFLICT' THEN RAISE; END IF;
  END;

  v_tampered := jsonb_set(
    v_document,
    '{request,tenantId}',
    to_jsonb('tnt_018f1234-5678-7abc-8def-0123456789ac'::text)
  );
  v_tampered_canonical := v_tampered::text;
  v_tampered_hash := encode(public.digest(convert_to(v_tampered_canonical, 'UTF8'), 'sha256'), 'hex');
  BEGIN
    PERFORM audit.record_policy_decision_provenance(v_tampered_canonical, v_tampered_hash);
    RAISE EXCEPTION 'cross-tenant provenance was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_recording$;

RESET ROLE;

DO $verify_append_only$
BEGIN
  BEGIN
    UPDATE audit.policy_decision_provenance
    SET reason_codes = reason_codes
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND decision_id = 'dec_018f1234-5678-7abc-8def-0123456789f3';
    RAISE EXCEPTION 'policy decision provenance was mutable';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$verify_append_only$;

ROLLBACK;
\echo 'Verified canonical policy decision provenance, bindings, digest integrity, idempotency, isolation and append-only enforcement.'
