import Fastify, { LogController } from "fastify";
import { GatewayIdentityError } from "@tenant-trust/gateway-identity";
import { TenantContextError } from "@tenant-trust/tenant-context";
import { AccessDeniedError } from "./repository.mjs";

const RECORD_ID_PATTERN = "^res_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const ACCESS_DENIED = Object.freeze({ error: Object.freeze({ code: "ACCESS_DENIED" }) });
const AUTHENTICATION_REQUIRED = Object.freeze({
  error: Object.freeze({ code: "CLIENT_CERTIFICATE_REQUIRED" }),
});
const INVALID_REQUEST = Object.freeze({ error: Object.freeze({ code: "INVALID_REQUEST" }) });
const SERVICE_UNAVAILABLE = Object.freeze({ error: Object.freeze({ code: "SERVICE_UNAVAILABLE" }) });

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

export function createTenantTrustApi({ identityResolver, repository, logger = false } = {}) {
  if (!repository
    || typeof repository.getProfile !== "function"
    || typeof repository.listRecords !== "function"
    || typeof repository.getRecord !== "function") {
    throw new TypeError("A tenant API repository is required.");
  }

  const authenticateRequest = createGatewayRequestAuthenticator(identityResolver);

  const api = Fastify({
    logger,
    logController: new LogController({ disableRequestLogging: true }),
  });

  api.setErrorHandler((error, request, reply) => {
    if (error.validation) return reply.code(400).send(INVALID_REQUEST);
    if (error instanceof GatewayIdentityError) return reply.code(401).send(AUTHENTICATION_REQUIRED);
    if (error instanceof TenantContextError || error instanceof AccessDeniedError) {
      return reply.code(403).send(ACCESS_DENIED);
    }
    request.log.error({ err: error }, "Tenant API request failed");
    return reply.code(503).send(SERVICE_UNAVAILABLE);
  });

  api.get("/v1/profile", async (request) => {
    const authentication = await authenticateRequest(request);
    return { profile: await repository.getProfile(authentication) };
  });

  api.get("/v1/tenant-records", async (request) => {
    const authentication = await authenticateRequest(request);
    return { records: await repository.listRecords(authentication) };
  });

  api.get("/v1/tenant-records/:recordId", {
    schema: {
      params: {
        type: "object",
        additionalProperties: false,
        required: ["recordId"],
        properties: {
          recordId: { type: "string", pattern: RECORD_ID_PATTERN },
        },
      },
    },
  }, async (request) => {
    const authentication = await authenticateRequest(request);
    return { record: await repository.getRecord(authentication, request.params.recordId) };
  });

  return api;
}
