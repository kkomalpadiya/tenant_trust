CREATE TYPE audit.api_request_event_kind AS ENUM ('authentication', 'access');
CREATE TYPE audit.api_request_decision AS ENUM ('allow', 'deny');

CREATE TABLE audit.api_request_events (
  api_request_event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id text NOT NULL,
  correlation_id text NOT NULL,
  event_kind audit.api_request_event_kind NOT NULL,
  tenant_id identity.tenant_id,
  actor_subject_id identity.subject_id,
  authentication_source text NOT NULL,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id_hash_sha256 text NOT NULL,
  decision audit.api_request_decision NOT NULL,
  reason_code text NOT NULL,
  http_method text NOT NULL,
  route_template text NOT NULL,
  status_code integer NOT NULL,
  authorization_mode_id text,
  operation_id text,
  occurred_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT api_request_events_actor_membership_fk
    FOREIGN KEY (tenant_id, actor_subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id)
    MATCH FULL
    ON DELETE RESTRICT,
  CONSTRAINT api_request_events_request_id_format CHECK (
    request_id ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CONSTRAINT api_request_events_correlation_id_format CHECK (
    correlation_id ~ '^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CONSTRAINT api_request_events_authentication_source CHECK (
    authentication_source = 'mtls-certificate'
  ),
  CONSTRAINT api_request_events_action_format CHECK (
    action ~ '^[a-z][a-z0-9-]{0,31}:[a-z][a-z0-9-]{0,31}$'
  ),
  CONSTRAINT api_request_events_resource_type_format CHECK (
    resource_type ~ '^[a-z][a-z0-9-]{1,62}$'
  ),
  CONSTRAINT api_request_events_resource_hash_format CHECK (
    resource_id_hash_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT api_request_events_reason_format CHECK (
    reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  CONSTRAINT api_request_events_http_method CHECK (
    http_method IN ('GET', 'POST')
  ),
  CONSTRAINT api_request_events_route_template CHECK (
    route_template ~ '^/v1/[A-Za-z0-9/.:_-]{1,247}$'
  ),
  CONSTRAINT api_request_events_status_code CHECK (
    status_code BETWEEN 200 AND 599
  ),
  CONSTRAINT api_request_events_mode_format CHECK (
    authorization_mode_id IS NULL
    OR authorization_mode_id ~ '^[a-z][a-z0-9-]{2,63}$'
  ),
  CONSTRAINT api_request_events_operation_id_format CHECK (
    operation_id IS NULL
    OR operation_id ~ '^op_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CONSTRAINT api_request_events_decision_status CHECK (
    (decision = 'allow' AND status_code < 400)
    OR (decision = 'deny' AND status_code >= 400)
  ),
  CONSTRAINT api_request_events_trusted_actor CHECK (
    (event_kind = 'authentication' AND decision = 'deny' AND tenant_id IS NULL AND actor_subject_id IS NULL)
    OR (tenant_id IS NOT NULL AND actor_subject_id IS NOT NULL)
  ),
  CONSTRAINT api_request_events_access_mode CHECK (
    (event_kind = 'authentication' AND authorization_mode_id IS NULL AND operation_id IS NULL)
    OR (event_kind = 'access' AND authorization_mode_id IS NOT NULL)
  ),
  CONSTRAINT api_request_events_request_kind_unique UNIQUE (request_id, event_kind)
);

CREATE INDEX api_request_events_tenant_time
  ON audit.api_request_events (tenant_id, recorded_at, api_request_event_id)
  WHERE tenant_id IS NOT NULL;

CREATE INDEX api_request_events_correlation
  ON audit.api_request_events (correlation_id, request_id, event_kind);

CREATE FUNCTION audit.reject_api_request_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, audit
AS $function$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '42501',
    MESSAGE = 'API request audit events are append-only.';
END
$function$;

CREATE TRIGGER api_request_events_append_only
BEFORE UPDATE OR DELETE ON audit.api_request_events
FOR EACH ROW EXECUTE FUNCTION audit.reject_api_request_event_mutation();

CREATE FUNCTION audit.record_api_request_event(
  p_request_id text,
  p_correlation_id text,
  p_event_kind text,
  p_tenant_id text,
  p_actor_subject_id text,
  p_authentication_source text,
  p_action text,
  p_resource_type text,
  p_resource_id_hash_sha256 text,
  p_decision text,
  p_reason_code text,
  p_http_method text,
  p_route_template text,
  p_status_code integer,
  p_authorization_mode_id text,
  p_operation_id text,
  p_occurred_at timestamptz
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, identity
SET row_security = off
AS $function$
DECLARE
  inserted_event_id bigint;
BEGIN
  INSERT INTO audit.api_request_events (
    request_id,
    correlation_id,
    event_kind,
    tenant_id,
    actor_subject_id,
    authentication_source,
    action,
    resource_type,
    resource_id_hash_sha256,
    decision,
    reason_code,
    http_method,
    route_template,
    status_code,
    authorization_mode_id,
    operation_id,
    occurred_at
  ) VALUES (
    p_request_id,
    p_correlation_id,
    p_event_kind::audit.api_request_event_kind,
    p_tenant_id::identity.tenant_id,
    p_actor_subject_id::identity.subject_id,
    p_authentication_source,
    p_action,
    p_resource_type,
    p_resource_id_hash_sha256,
    p_decision::audit.api_request_decision,
    p_reason_code,
    p_http_method,
    p_route_template,
    p_status_code,
    p_authorization_mode_id,
    p_operation_id,
    p_occurred_at
  )
  RETURNING api_request_event_id INTO inserted_event_id;

  RETURN inserted_event_id;
END
$function$;

REVOKE ALL ON TABLE audit.api_request_events FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON SEQUENCE audit.api_request_events_api_request_event_id_seq FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION audit.reject_api_request_event_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.record_api_request_event(
  text, text, text, text, text, text, text, text, text,
  text, text, text, text, integer, text, text, timestamptz
) FROM PUBLIC;

GRANT USAGE ON SCHEMA audit TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION audit.record_api_request_event(
  text, text, text, text, text, text, text, text, text,
  text, text, text, text, integer, text, text, timestamptz
) TO tenant_trust_app;

COMMENT ON TABLE audit.api_request_events IS
  'Append-only sanitized authentication and access outcomes with server-generated request correlation';
COMMENT ON COLUMN audit.api_request_events.resource_id_hash_sha256 IS
  'SHA-256 of the server-selected resource identifier; raw resource identifiers and payloads are not stored';
COMMENT ON FUNCTION audit.record_api_request_event(
  text, text, text, text, text, text, text, text, text,
  text, text, text, text, integer, text, text, timestamptz
) IS 'Constrained API request audit writer; callers receive no direct table privileges';
