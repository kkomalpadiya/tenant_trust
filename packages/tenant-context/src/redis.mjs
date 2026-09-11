import { assertNoTenantSwitch } from "./index.mjs";

const KEY_NAMESPACE = /^[a-z][a-z0-9-]{0,63}$/u;

function encodeKeyPart(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 255) {
    throw new TypeError(`${label} must be a non-empty string of at most 255 characters.`);
  }
  return encodeURIComponent(value);
}

function tenantRedisKey(context, kind, namespace, segments) {
  const trustedContext = assertNoTenantSwitch(context);
  if (!KEY_NAMESPACE.test(namespace ?? "")) {
    throw new TypeError("namespace must be a lowercase Redis-safe token.");
  }
  if (segments.length === 0) {
    throw new TypeError("At least one key segment is required.");
  }

  return [
    "tenant",
    trustedContext.tenantId,
    kind,
    namespace,
    ...segments.map((segment) => encodeKeyPart(segment, "key segment")),
  ].join(":");
}

export function tenantCacheKey(context, namespace, ...segments) {
  return tenantRedisKey(context, "cache", namespace, segments);
}

export function tenantLockKey(context, namespace, ...segments) {
  return tenantRedisKey(context, "lock", namespace, segments);
}
