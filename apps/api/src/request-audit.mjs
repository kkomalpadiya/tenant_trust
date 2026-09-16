import { createHash } from "node:crypto";

const REQUEST_ID = /^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const OPERATION_ID = /^op_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const ACTION = /^[a-z][a-z0-9-]{0,31}:[a-z][a-z0-9-]{0,31}$/u;
const RESOURCE_TYPE = /^[a-z][a-z0-9-]{1,62}$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const ROUTE_TEMPLATE = /^\/v1\/[A-Za-z0-9/.:_-]{1,247}$/u;
const AUTHORIZATION_MODE_ID = /^[a-z][a-z0-9-]{2,63}$/u;
const EVENT_KINDS = new Set(["authentication", "access"]);
const DECISIONS = new Set(["allow", "deny"]);
const METHODS = new Set(["GET", "POST"]);
const EVENT_KEYS = Object.freeze([
  "schemaVersion",
  "eventKind",
  "requestId",
  "correlationId",
  "tenantId",
  "actorSubjectId",
  "authenticationSource",
  "action",
  "resourceType",
  "resourceIdHashSha256",
  "decision",
  "reasonCode",
  "method",
  "routeTemplate",
  "statusCode",
  "authorizationModeId",
  "operationId",
  "occurredAt",
]);
const recorders = new WeakSet();

export const REQUEST_AUDIT_POLICY = Object.freeze({
  schemaVersion: "1.0.0",
  mechanism: "append-only-request-outcomes-v1",
  correlationSource: "server-generated",
  failClosedOnCaptureFailure: true,
  rawHeadersCaptured: false,
  requestPayloadCaptured: false,
  responsePayloadCaptured: false,
  resourceIdentifiers: "sha256",
});

export class RequestAuditUnavailableError extends Error {
  constructor() {
    super("Request audit capture is unavailable.");
    this.name = "RequestAuditUnavailableError";
  }
}

function exactObject(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("A request audit event object is required.");
  }
  const keys = Object.keys(input).sort();
  const expected = [...EVENT_KEYS].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError("Request audit events may contain only the fixed sanitized fields.");
  }
}

function validTimestamp(value) {
  if (typeof value !== "string") return false;
  const timestamp = new Date(value);
  return Number.isFinite(timestamp.getTime()) && timestamp.toISOString() === value;
}

function normalizeEvent(input) {
  exactObject(input);
  if (input.schemaVersion !== REQUEST_AUDIT_POLICY.schemaVersion
    || !EVENT_KINDS.has(input.eventKind)
    || !REQUEST_ID.test(input.requestId ?? "")
    || !CORRELATION_ID.test(input.correlationId ?? "")
    || input.authenticationSource !== "mtls-certificate"
    || !ACTION.test(input.action ?? "")
    || !RESOURCE_TYPE.test(input.resourceType ?? "")
    || !SHA256.test(input.resourceIdHashSha256 ?? "")
    || !DECISIONS.has(input.decision)
    || !REASON_CODE.test(input.reasonCode ?? "")
    || !METHODS.has(input.method)
    || !ROUTE_TEMPLATE.test(input.routeTemplate ?? "")
    || !Number.isInteger(input.statusCode)
    || input.statusCode < 200
    || input.statusCode > 599
    || !validTimestamp(input.occurredAt)) {
    throw new TypeError("Request audit event fields are invalid.");
  }

  const hasTrustedActor = TENANT_ID.test(input.tenantId ?? "")
    && SUBJECT_ID.test(input.actorSubjectId ?? "");
  if ((input.tenantId === null) !== (input.actorSubjectId === null)
    || (input.decision === "allow" && !hasTrustedActor)
    || (input.eventKind === "access" && !hasTrustedActor)
    || (input.eventKind === "authentication" && input.decision === "deny" && hasTrustedActor)) {
    throw new TypeError("Request audit actor and tenant binding is invalid.");
  }

  if ((input.eventKind === "authentication" && (input.authorizationModeId !== null || input.operationId !== null))
    || (input.eventKind === "access" && !AUTHORIZATION_MODE_ID.test(input.authorizationModeId ?? ""))
    || (input.operationId !== null && !OPERATION_ID.test(input.operationId ?? ""))
    || (input.decision === "allow" && input.statusCode >= 400)
    || (input.decision === "deny" && input.statusCode < 400)) {
    throw new TypeError("Request audit decision metadata is invalid.");
  }

  return Object.freeze(Object.fromEntries(EVENT_KEYS.map((key) => [key, input[key]])));
}

export function hashAuditResourceIdentifier(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 4_096) {
    throw new TypeError("A bounded resource identifier is required for audit hashing.");
  }
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function createRequestAuditRecorder({ write } = {}) {
  if (typeof write !== "function") throw new TypeError("A request audit writer is required.");
  const recorder = Object.freeze({
    policy: REQUEST_AUDIT_POLICY,
    async record(input) {
      const event = normalizeEvent(input);
      try {
        await write(event);
      } catch {
        throw new RequestAuditUnavailableError();
      }
      return event;
    },
  });
  recorders.add(recorder);
  return recorder;
}

export function assertRequestAuditRecorder(recorder) {
  if (!recorders.has(recorder) || recorder.policy !== REQUEST_AUDIT_POLICY) {
    throw new TypeError("A branded fail-closed request audit recorder is required.");
  }
  return recorder;
}

export function createPostgresRequestAuditRecorder({ database } = {}) {
  if (!database || typeof database.query !== "function") {
    throw new TypeError("A PostgreSQL request audit database is required.");
  }
  return createRequestAuditRecorder({
    async write(event) {
      const result = await database.query({
        name: "record-api-request-event-v1",
        text: `SELECT audit.record_api_request_event(
          $1, $2, $3, $4, $5, $6, $7, $8, $9,
          $10, $11, $12, $13, $14, $15, $16, $17
        ) AS api_request_event_id`,
        values: [
          event.requestId,
          event.correlationId,
          event.eventKind,
          event.tenantId,
          event.actorSubjectId,
          event.authenticationSource,
          event.action,
          event.resourceType,
          event.resourceIdHashSha256,
          event.decision,
          event.reasonCode,
          event.method,
          event.routeTemplate,
          event.statusCode,
          event.authorizationModeId,
          event.operationId,
          event.occurredAt,
        ],
      });
      if (result?.rowCount !== 1) throw new Error("Request audit insert was not confirmed.");
    },
  });
}
