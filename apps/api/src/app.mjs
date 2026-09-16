import { randomUUID } from "node:crypto";
import Fastify, { LogController } from "fastify";
import { AuthorizationError, assertAuthorizationMode } from "@tenant-trust/authorization";
import { GatewayIdentityError } from "@tenant-trust/gateway-identity";
import { TenantContextError } from "@tenant-trust/tenant-context";
import { AccessDeniedError } from "./repository.mjs";
import {
  RequestAuditUnavailableError,
  assertRequestAuditRecorder,
  hashAuditResourceIdentifier,
} from "./request-audit.mjs";
import {
  CertificateNotAcceptedError,
  REQUEST_STATE_POLICY,
  RequestStateUnavailableError,
} from "./request-state.mjs";
import {
  IdempotencyConflictError,
  REQUEST_SAFEGUARD_POLICY,
  RequestTimeoutError,
  SENSITIVE_IDEMPOTENCY_KEY_PATTERN,
  UnsupportedSessionError,
  assertRequestTimeoutMilliseconds,
  assertStatelessMtlsRequest,
  runWithRequestTimeout,
} from "./request-safeguards.mjs";

const RECORD_ID_PATTERN = "^res_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const SUBJECT_ID_PATTERN = "^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const ACCESS_DENIED = Object.freeze({ error: Object.freeze({ code: "ACCESS_DENIED" }) });
const AUTHENTICATION_REQUIRED = Object.freeze({
  error: Object.freeze({ code: "CLIENT_CERTIFICATE_REQUIRED" }),
});
const CERTIFICATE_NOT_ACCEPTED = Object.freeze({
  error: Object.freeze({ code: "CERTIFICATE_NOT_ACCEPTED" }),
});
const INVALID_REQUEST = Object.freeze({ error: Object.freeze({ code: "INVALID_REQUEST" }) });
const REQUEST_TOO_LARGE = Object.freeze({ error: Object.freeze({ code: "REQUEST_TOO_LARGE" }) });
const IDEMPOTENCY_CONFLICT = Object.freeze({
  error: Object.freeze({ code: "IDEMPOTENCY_CONFLICT" }),
});
const SERVICE_UNAVAILABLE = Object.freeze({ error: Object.freeze({ code: "SERVICE_UNAVAILABLE" }) });
const REQUEST_ID = /^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const requestAuditContext = Symbol("requestAuditContext");

function defaultRequestIdFactory() {
  return `req_${randomUUID()}`;
}

function defaultCorrelationIdFactory() {
  return `cor_${randomUUID()}`;
}

function failureDecision(error) {
  if (error instanceof GatewayIdentityError) {
    return Object.freeze({ statusCode: 401, reasonCode: "CLIENT_CERTIFICATE_REQUIRED" });
  }
  if (error instanceof UnsupportedSessionError) {
    return Object.freeze({ statusCode: 401, reasonCode: "SESSION_CREDENTIAL_UNSUPPORTED" });
  }
  if (error instanceof CertificateNotAcceptedError) {
    return Object.freeze({ statusCode: 401, reasonCode: "CERTIFICATE_NOT_ACCEPTED" });
  }
  if (error instanceof TenantContextError || error instanceof AccessDeniedError) {
    return Object.freeze({ statusCode: 403, reasonCode: "ACCESS_DENIED" });
  }
  if (error instanceof RequestStateUnavailableError) {
    return Object.freeze({ statusCode: 503, reasonCode: "AUTHORITY_UNAVAILABLE" });
  }
  if (error instanceof IdempotencyConflictError) {
    return Object.freeze({ statusCode: 409, reasonCode: "IDEMPOTENCY_CONFLICT" });
  }
  if (error instanceof RequestTimeoutError) {
    return Object.freeze({ statusCode: 503, reasonCode: "REQUEST_TIMEOUT" });
  }
  return Object.freeze({ statusCode: 503, reasonCode: "INTERNAL_FAILURE" });
}

function occurredAt(clock) {
  const value = clock();
  const timestamp = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(timestamp.getTime())) throw new RequestAuditUnavailableError();
  return timestamp.toISOString();
}

export function createGatewayRequestAuthenticator(identityResolver) {
  if (!identityResolver || typeof identityResolver.resolve !== "function") {
    throw new TypeError("A gateway identity resolver is required.");
  }
  return async function authenticateGatewayRequest(request) {
    return identityResolver.resolve({
      socket: request.raw.socket,
      headers: request.headers,
    });
  };
}

function noQueryParameters() {
  return { type: "object", additionalProperties: false };
}

function sensitiveRequestHeaders() {
  return {
    type: "object",
    required: ["idempotency-key"],
    properties: {
      "idempotency-key": { type: "string", pattern: SENSITIVE_IDEMPOTENCY_KEY_PATTERN },
    },
  };
}

export function createTenantTrustApi({
  identityResolver,
  repository,
  requestAuditRecorder,
  requestIdFactory = defaultRequestIdFactory,
  correlationIdFactory = defaultCorrelationIdFactory,
  clock = () => new Date(),
  requestTimeoutMilliseconds = REQUEST_SAFEGUARD_POLICY.requestTimeoutMilliseconds,
  logger = false,
} = {}) {
  if (!repository
    || typeof repository.getProfile !== "function"
    || typeof repository.listRecords !== "function"
    || typeof repository.getRecord !== "function"
    || typeof repository.exportRecords !== "function"
    || typeof repository.reviewMembership !== "function") {
    throw new TypeError("A tenant API repository is required.");
  }
  try {
    assertAuthorizationMode(repository.authorizationMode);
  } catch (error) {
    if (!(error instanceof AuthorizationError)) throw error;
    throw new TypeError("The tenant API repository must declare an explicit supported authorization mode.");
  }
  if (repository.requestStatePolicy !== REQUEST_STATE_POLICY) {
    throw new TypeError("The tenant API repository must declare authoritative per-request state revalidation.");
  }
  if (repository.requestSafeguardPolicy !== REQUEST_SAFEGUARD_POLICY) {
    throw new TypeError("The tenant API repository must declare the fixed request safeguard policy.");
  }
  assertRequestAuditRecorder(requestAuditRecorder);
  if (typeof requestIdFactory !== "function" || typeof correlationIdFactory !== "function") {
    throw new TypeError("Server-side request and correlation ID factories are required.");
  }
  if (typeof clock !== "function") throw new TypeError("A trusted request audit clock is required.");
  assertRequestTimeoutMilliseconds(requestTimeoutMilliseconds);

  const authenticateRequest = createGatewayRequestAuthenticator(identityResolver);

  const api = Fastify({
    logger,
    bodyLimit: REQUEST_SAFEGUARD_POLICY.sensitiveBodyLimitBytes,
    logController: new LogController({ disableRequestLogging: true }),
    ajv: {
      customOptions: {
        removeAdditional: false,
      },
    },
  });

  api.addHook("onRequest", async (request, reply) => {
    const requestId = requestIdFactory();
    const correlationId = correlationIdFactory();
    if (!REQUEST_ID.test(requestId ?? "") || !CORRELATION_ID.test(correlationId ?? "")) {
      throw new RequestAuditUnavailableError();
    }
    request[requestAuditContext] = Object.freeze({ requestId, correlationId });
    reply.header("x-request-id", requestId);
    reply.header("x-correlation-id", correlationId);
    reply.header("cache-control", "no-store");
    reply.header("pragma", "no-cache");
  });

  api.setErrorHandler((error, request, reply) => {
    if (error.validation) return reply.code(400).send(INVALID_REQUEST);
    if (error.code === "FST_ERR_CTP_BODY_TOO_LARGE") {
      return reply.code(413).send(REQUEST_TOO_LARGE);
    }
    if (error instanceof GatewayIdentityError) return reply.code(401).send(AUTHENTICATION_REQUIRED);
    if (error instanceof UnsupportedSessionError) return reply.code(401).send(AUTHENTICATION_REQUIRED);
    if (error instanceof CertificateNotAcceptedError) return reply.code(401).send(CERTIFICATE_NOT_ACCEPTED);
    if (error instanceof TenantContextError || error instanceof AccessDeniedError) {
      return reply.code(403).send(ACCESS_DENIED);
    }
    if (error instanceof IdempotencyConflictError) {
      return reply.code(409).send(IDEMPOTENCY_CONFLICT);
    }
    if (error instanceof RequestStateUnavailableError || error instanceof RequestAuditUnavailableError) {
      return reply.code(503).send(SERVICE_UNAVAILABLE);
    }
    if (error instanceof RequestTimeoutError) return reply.code(503).send(SERVICE_UNAVAILABLE);
    request.log.error({ err: error }, "Tenant API request failed");
    return reply.code(503).send(SERVICE_UNAVAILABLE);
  });

  function createAuditedHandler({
    action,
    resourceType,
    routeTemplate,
    resourceIdentifier,
    execute,
  }) {
    return async function auditedHandler(request) {
      const correlation = request[requestAuditContext];
      let authentication;
      try {
        assertStatelessMtlsRequest(request.headers);
        authentication = await authenticateRequest(request);
        if (authentication?.source !== "mtls-certificate") {
          throw new GatewayIdentityError("AUTHENTICATION_SOURCE_INVALID");
        }
      } catch (error) {
        const failure = failureDecision(error);
        await requestAuditRecorder.record({
          schemaVersion: "1.0.0",
          eventKind: "authentication",
          requestId: correlation.requestId,
          correlationId: correlation.correlationId,
          tenantId: null,
          actorSubjectId: null,
          authenticationSource: "mtls-certificate",
          action,
          resourceType,
          resourceIdHashSha256: hashAuditResourceIdentifier(routeTemplate),
          decision: "deny",
          reasonCode: failure.reasonCode,
          method: request.method,
          routeTemplate,
          statusCode: failure.statusCode,
          authorizationModeId: null,
          operationId: null,
          occurredAt: occurredAt(clock),
        });
        throw error;
      }

      const resourceIdHashSha256 = hashAuditResourceIdentifier(resourceIdentifier(request, authentication));
      await requestAuditRecorder.record({
        schemaVersion: "1.0.0",
        eventKind: "authentication",
        requestId: correlation.requestId,
        correlationId: correlation.correlationId,
        tenantId: authentication.tenantId,
        actorSubjectId: authentication.subjectId,
        authenticationSource: authentication.source,
        action,
        resourceType,
        resourceIdHashSha256,
        decision: "allow",
        reasonCode: "AUTHENTICATION_ACCEPTED",
        method: request.method,
        routeTemplate,
        statusCode: 200,
        authorizationModeId: null,
        operationId: null,
        occurredAt: occurredAt(clock),
      });

      let result;
      try {
        result = await runWithRequestTimeout(
          (signal) => execute(authentication, request, signal),
          requestTimeoutMilliseconds,
        );
      } catch (error) {
        const failure = failureDecision(error);
        await requestAuditRecorder.record({
          schemaVersion: "1.0.0",
          eventKind: "access",
          requestId: correlation.requestId,
          correlationId: correlation.correlationId,
          tenantId: authentication.tenantId,
          actorSubjectId: authentication.subjectId,
          authenticationSource: authentication.source,
          action,
          resourceType,
          resourceIdHashSha256,
          decision: "deny",
          reasonCode: failure.reasonCode,
          method: request.method,
          routeTemplate,
          statusCode: failure.statusCode,
          authorizationModeId: repository.authorizationMode.modeId,
          operationId: null,
          occurredAt: occurredAt(clock),
        });
        throw error;
      }

      const operationId = result?.operation?.operationId ?? null;
      await requestAuditRecorder.record({
        schemaVersion: "1.0.0",
        eventKind: "access",
        requestId: correlation.requestId,
        correlationId: correlation.correlationId,
        tenantId: authentication.tenantId,
        actorSubjectId: authentication.subjectId,
        authenticationSource: authentication.source,
        action,
        resourceType,
        resourceIdHashSha256,
        decision: "allow",
        reasonCode: "ACCESS_ALLOWED",
        method: request.method,
        routeTemplate,
        statusCode: 200,
        authorizationModeId: repository.authorizationMode.modeId,
        operationId,
        occurredAt: occurredAt(clock),
      });
      return result;
    };
  }

  api.get("/v1/profile", {
    schema: { querystring: noQueryParameters() },
  }, createAuditedHandler({
    action: "profile:read",
    resourceType: "tenant-profile",
    routeTemplate: "/v1/profile",
    resourceIdentifier: (_request, authentication) => authentication.subjectId,
    execute: async (authentication, _request, signal) => ({
      profile: await repository.getProfile(authentication, { signal }),
    }),
  }));

  api.get("/v1/tenant-records", {
    schema: { querystring: noQueryParameters() },
  }, createAuditedHandler({
    action: "record:read",
    resourceType: "tenant-records",
    routeTemplate: "/v1/tenant-records",
    resourceIdentifier: (_request, authentication) => authentication.tenantId,
    execute: async (authentication, _request, signal) => ({
      records: await repository.listRecords(authentication, { signal }),
    }),
  }));

  api.get("/v1/tenant-records/:recordId", {
    schema: {
      querystring: noQueryParameters(),
      params: {
        type: "object",
        additionalProperties: false,
        required: ["recordId"],
        properties: {
          recordId: { type: "string", pattern: RECORD_ID_PATTERN },
        },
      },
    },
  }, createAuditedHandler({
    action: "record:read",
    resourceType: "tenant-record",
    routeTemplate: "/v1/tenant-records/:recordId",
    resourceIdentifier: (request) => request.params.recordId,
    execute: async (authentication, request, signal) => ({
      record: await repository.getRecord(authentication, request.params.recordId, { signal }),
    }),
  }));

  api.post("/v1/tenant-records/export", {
    bodyLimit: REQUEST_SAFEGUARD_POLICY.sensitiveBodyLimitBytes,
    schema: {
      headers: sensitiveRequestHeaders(),
      querystring: {
        type: "object",
        additionalProperties: false,
      },
      body: {
        type: "object",
        additionalProperties: false,
        required: ["recordIds"],
        properties: {
          recordIds: {
            type: "array",
            minItems: 1,
            maxItems: REQUEST_SAFEGUARD_POLICY.maximumExportRecords,
            uniqueItems: true,
            items: { type: "string", pattern: RECORD_ID_PATTERN },
          },
        },
      },
    },
  }, createAuditedHandler({
    action: "record:export",
    resourceType: "tenant-record-export",
    routeTemplate: "/v1/tenant-records/export",
    resourceIdentifier: (request) => [...request.body.recordIds].sort().join(","),
    execute: async (authentication, request, signal) => repository.exportRecords(
      authentication,
      request.body.recordIds,
      { idempotencyKey: request.headers["idempotency-key"], signal },
    ),
  }));

  api.post("/v1/admin/membership-reviews", {
    bodyLimit: REQUEST_SAFEGUARD_POLICY.sensitiveBodyLimitBytes,
    schema: {
      headers: sensitiveRequestHeaders(),
      querystring: {
        type: "object",
        additionalProperties: false,
      },
      body: {
        type: "object",
        additionalProperties: false,
        required: ["subjectId"],
        properties: {
          subjectId: { type: "string", pattern: SUBJECT_ID_PATTERN },
        },
      },
    },
  }, createAuditedHandler({
    action: "tenant:admin",
    resourceType: "tenant-membership",
    routeTemplate: "/v1/admin/membership-reviews",
    resourceIdentifier: (request) => request.body.subjectId,
    execute: async (authentication, request, signal) => repository.reviewMembership(
      authentication,
      request.body.subjectId,
      { idempotencyKey: request.headers["idempotency-key"], signal },
    ),
  }));

  return api;
}
