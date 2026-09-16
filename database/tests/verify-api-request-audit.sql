BEGIN;

DO $verify_api_request_audit_schema$
BEGIN
  IF to_regclass('audit.api_request_events') IS NULL THEN
    RAISE EXCEPTION 'API request audit table is missing';
  END IF;
  IF NOT has_function_privilege(
    'tenant_trust_app',
    'audit.record_api_request_event(text,text,text,text,text,text,text,text,text,text,text,text,text,integer,text,text,timestamptz)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'tenant runtime cannot execute the constrained audit writer';
  END IF;
  IF has_table_privilege('tenant_trust_app', 'audit.api_request_events', 'SELECT')
     OR has_table_privilege('tenant_trust_app', 'audit.api_request_events', 'INSERT')
     OR has_table_privilege('tenant_trust_app', 'audit.api_request_events', 'UPDATE')
     OR has_table_privilege('tenant_trust_app', 'audit.api_request_events', 'DELETE') THEN
    RAISE EXCEPTION 'tenant runtime has unsafe direct audit table privileges';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'audit'
      AND table_name = 'api_request_events'
      AND column_name IN ('headers', 'query', 'body', 'payload', 'request_payload', 'response_payload')
  ) THEN
    RAISE EXCEPTION 'API request audit schema contains a raw request or payload column';
  END IF;
END
$verify_api_request_audit_schema$;

SET LOCAL ROLE tenant_trust_app;

SELECT audit.record_api_request_event(
  'req_018f1234-5678-7abc-8def-0123456789d1',
  'cor_018f1234-5678-7abc-8def-0123456789e1',
  'authentication',
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'mtls-certificate',
  'profile:read',
  'tenant-profile',
  repeat('a', 64),
  'allow',
  'AUTHENTICATION_ACCEPTED',
  'GET',
  '/v1/profile',
  200,
  NULL,
  NULL,
  '2026-09-16T12:00:00.000Z'
);

SELECT audit.record_api_request_event(
  'req_018f1234-5678-7abc-8def-0123456789d1',
  'cor_018f1234-5678-7abc-8def-0123456789e1',
  'access',
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'mtls-certificate',
  'profile:read',
  'tenant-profile',
  repeat('a', 64),
  'deny',
  'ACCESS_DENIED',
  'GET',
  '/v1/profile',
  403,
  'pki-rbac-baseline-v1',
  NULL,
  '2026-09-16T12:00:00.010Z'
);

SELECT audit.record_api_request_event(
  'req_018f1234-5678-7abc-8def-0123456789d2',
  'cor_018f1234-5678-7abc-8def-0123456789e2',
  'authentication',
  NULL,
  NULL,
  'mtls-certificate',
  'record:read',
  'tenant-records',
  repeat('b', 64),
  'deny',
  'CLIENT_CERTIFICATE_REQUIRED',
  'GET',
  '/v1/tenant-records',
  401,
  NULL,
  NULL,
  '2026-09-16T12:00:01.000Z'
);

DO $verify_no_direct_insert$
BEGIN
  BEGIN
    INSERT INTO audit.api_request_events (
      request_id, correlation_id, event_kind, authentication_source, action,
      resource_type, resource_id_hash_sha256, decision, reason_code,
      http_method, route_template, status_code, occurred_at
    ) VALUES (
      'req_018f1234-5678-7abc-8def-0123456789d3',
      'cor_018f1234-5678-7abc-8def-0123456789e3',
      'authentication', 'mtls-certificate', 'profile:read', 'tenant-profile',
      repeat('c', 64), 'deny', 'CLIENT_CERTIFICATE_REQUIRED',
      'GET', '/v1/profile', 401, clock_timestamp()
    );
    RAISE EXCEPTION 'tenant runtime inserted directly into the audit table';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_no_direct_insert$;

RESET ROLE;

DO $verify_api_request_audit_rows$
DECLARE
  row_text text;
BEGIN
  IF (SELECT count(*) FROM audit.api_request_events) <> 3 THEN
    RAISE EXCEPTION 'API request audit event count is incorrect';
  END IF;
  IF (SELECT count(*) FROM audit.api_request_events
      WHERE request_id = 'req_018f1234-5678-7abc-8def-0123456789d1'
        AND correlation_id = 'cor_018f1234-5678-7abc-8def-0123456789e1') <> 2 THEN
    RAISE EXCEPTION 'authentication and access outcomes did not retain one request correlation';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM audit.api_request_events
    WHERE event_kind = 'access'
      AND tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND actor_subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab'
      AND action = 'profile:read'
      AND resource_type = 'tenant-profile'
      AND resource_id_hash_sha256 = repeat('a', 64)
      AND decision = 'deny'
      AND reason_code = 'ACCESS_DENIED'
      AND authorization_mode_id = 'pki-rbac-baseline-v1'
  ) THEN
    RAISE EXCEPTION 'trusted actor, tenant, action, resource or decision metadata is incomplete';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM audit.api_request_events
    WHERE request_id = 'req_018f1234-5678-7abc-8def-0123456789d2'
      AND event_kind = 'authentication'
      AND tenant_id IS NULL
      AND actor_subject_id IS NULL
      AND decision = 'deny'
  ) THEN
    RAISE EXCEPTION 'failed authentication improperly asserted an untrusted actor or tenant';
  END IF;
  SELECT string_agg(row_to_json(event)::text, '')
  INTO row_text
  FROM audit.api_request_events AS event;
  IF row_text ~* '(cookie|password|secret|payload)' THEN
    RAISE EXCEPTION 'audit rows contain a secret or payload field';
  END IF;

  BEGIN
    UPDATE audit.api_request_events SET reason_code = 'ALTERED_AUDIT_EVENT';
    RAISE EXCEPTION 'API request audit history was mutable';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    DELETE FROM audit.api_request_events;
    RAISE EXCEPTION 'API request audit history was deletable';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_api_request_audit_rows$;

ROLLBACK;

SELECT 'API request audit verification passed' AS result;
