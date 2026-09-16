import { createHash } from "node:crypto";

export const SENSITIVE_IDEMPOTENCY_KEY_PATTERN = "^idem_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const IDEMPOTENCY_KEY = new RegExp(SENSITIVE_IDEMPOTENCY_KEY_PATTERN, "u");
const SAFE_TIMEOUT_MINIMUM_MILLISECONDS = 10;

export const REQUEST_SAFEGUARD_POLICY = Object.freeze({
  schemaVersion: "1.0.0",
  mechanism: "stateless-mtls-replay-guard-v1",
  sessionMode: "stateless-mtls",
  ambientSessionCredentialsAccepted: false,
  sensitiveBodyLimitBytes: 4_096,
  maximumExportRecords: 25,
  requestTimeoutMilliseconds: 5_000,
  databaseStatementTimeoutMilliseconds: 4_000,
  databaseLockTimeoutMilliseconds: 1_000,
  idempotencyScope: "tenant-actor-action-key",
  idempotencyKeyStorage: "sha256",
});

export class UnsupportedSessionError extends Error {
  constructor() {
    super("Ambient session credentials are not accepted.");
    this.name = "UnsupportedSessionError";
  }
}

export class RequestTimeoutError extends Error {
  constructor() {
    super("The protected request exceeded its deadline.");
    this.name = "RequestTimeoutError";
  }
}

export class IdempotencyConflictError extends Error {
  constructor() {
    super("The idempotency identity conflicts with another operation.");
    this.name = "IdempotencyConflictError";
  }
}

export function assertStatelessMtlsRequest(headers) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
    throw new UnsupportedSessionError();
  }
  if (Object.hasOwn(headers, "authorization") || Object.hasOwn(headers, "cookie")) {
    throw new UnsupportedSessionError();
  }
}

export function normalizeSensitiveIdempotencyKey(value) {
  if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) {
    throw new TypeError("A valid sensitive-operation idempotency key is required.");
  }
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function hashSensitiveIdempotencyKey(value) {
  return sha256(normalizeSensitiveIdempotencyKey(value));
}

export function hashSensitiveRequest(action, resourceIdentifiers) {
  if (typeof action !== "string"
    || !Array.isArray(resourceIdentifiers)
    || resourceIdentifiers.length < 1
    || resourceIdentifiers.some((value) => typeof value !== "string" || value.length < 1)) {
    throw new TypeError("A bounded sensitive-operation request identity is required.");
  }
  return sha256(JSON.stringify([action, [...resourceIdentifiers].sort()]));
}

export function assertRequestTimeoutMilliseconds(value) {
  if (!Number.isInteger(value)
    || value < SAFE_TIMEOUT_MINIMUM_MILLISECONDS
    || value > REQUEST_SAFEGUARD_POLICY.requestTimeoutMilliseconds) {
    throw new TypeError("The request timeout must stay within the fixed safeguard policy.");
  }
  return value;
}

export async function runWithRequestTimeout(operation, timeoutMilliseconds) {
  if (typeof operation !== "function") throw new TypeError("A protected request operation is required.");
  const deadline = assertRequestTimeoutMilliseconds(timeoutMilliseconds);
  const controller = new AbortController();
  let timeout;
  const timedOut = new Promise((_, reject) => {
    timeout = setTimeout(() => {
      controller.abort();
      reject(new RequestTimeoutError());
    }, deadline);
    timeout.unref?.();
  });

  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      timedOut,
    ]);
  } catch (error) {
    if (controller.signal.aborted && !(error instanceof RequestTimeoutError)) {
      throw new RequestTimeoutError();
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
