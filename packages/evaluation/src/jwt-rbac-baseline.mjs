import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
  verify,
} from "node:crypto";
import {
  RESOURCE_TYPES,
  resolveRoleAction,
} from "@tenant-trust/authorization";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import { JWT_RBAC_BASELINE_MODE_ID } from "./comparison-scope.mjs";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TOKEN_ID = /^jwt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RESOURCE_ID = /^[a-z]{3}_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._:-]{2,63}$/u;
const ROLES = new Set(["tenant-admin", "tenant-member"]);
const HEADER_FIELDS = Object.freeze(["alg", "kid", "typ"]);
const CLAIM_FIELDS = Object.freeze(["aud", "exp", "iat", "iss", "jti", "nbf", "roles", "sub", "tid"]);

export const JWT_RBAC_BASELINE_POLICY = Object.freeze({
  modeId: JWT_RBAC_BASELINE_MODE_ID,
  authenticationPolicy: "signed-jwt-eddsa-v1",
  rolePolicy: "role-action-matrix-v1",
  algorithm: "EdDSA",
  maximumTokenTtlSeconds: 300,
  adaptiveTrustUsed: false,
  certificateRequired: false,
  sensitiveOperationsUseRoleOnly: true,
});

export const JWT_RBAC_SAFE_DENIAL = Object.freeze({
  statusCode: 401,
  code: "AUTHENTICATION_FAILED",
});

export class JwtRbacBaselineError extends Error {
  constructor(reasonCode, options) {
    super("JWT plus RBAC baseline authentication failed.", options);
    this.name = "JwtRbacBaselineError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new JwtRbacBaselineError(reasonCode, cause === undefined ? undefined : { cause });
}

function exactFields(value, fields) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).length === fields.length
    && Object.keys(value).sort().every((field, index) => field === fields[index]);
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodeJson(segment, reasonCode) {
  try {
    const bytes = Buffer.from(segment, "base64url");
    if (bytes.length === 0 || bytes.toString("base64url") !== segment) fail(reasonCode);
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    if (error instanceof JwtRbacBaselineError) throw error;
    fail(reasonCode, error);
  }
}

function date(value) {
  const result = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(result.getTime())) throw new TypeError("A valid evaluation clock is required.");
  return result;
}

function nowSeconds(clock) {
  return Math.floor(date(clock()).getTime() / 1_000);
}

function privateEd25519Key(value) {
  try {
    const key = value?.type === "private" ? value : createPrivateKey(value);
    if (key.asymmetricKeyType !== "ed25519") fail("JWT_SIGNING_KEY_INVALID");
    return key;
  } catch (error) {
    if (error instanceof JwtRbacBaselineError) throw error;
    fail("JWT_SIGNING_KEY_INVALID", error);
  }
}

function publicEd25519Key(value) {
  try {
    const key = value?.type === "public" ? value : createPublicKey(value);
    if (key.asymmetricKeyType !== "ed25519") fail("JWT_VERIFICATION_KEY_INVALID");
    return key;
  } catch (error) {
    if (error instanceof JwtRbacBaselineError) throw error;
    fail("JWT_VERIFICATION_KEY_INVALID", error);
  }
}

function text(value, label) {
  if (typeof value !== "string" || value.length < 3 || value.length > 255) {
    throw new TypeError(`${label} must be a bounded string.`);
  }
  return value;
}

function normalizedRoles(value, reasonCode = "JWT_CLAIMS_INVALID") {
  if (!Array.isArray(value) || value.length === 0 || value.some((role) => !ROLES.has(role))) fail(reasonCode);
  const roles = [...new Set(value)].sort();
  if (roles.length !== value.length || roles.some((role, index) => role !== value[index])) fail(reasonCode);
  return Object.freeze(roles);
}

function normalizeClaims(claims, expected, now) {
  if (!exactFields(claims, CLAIM_FIELDS)
    || claims.iss !== expected.issuer
    || claims.aud !== expected.audience
    || !TOKEN_ID.test(claims.jti ?? "")
    || !TENANT_ID.test(claims.tid ?? "")
    || !SUBJECT_ID.test(claims.sub ?? "")
    || !Number.isSafeInteger(claims.iat)
    || !Number.isSafeInteger(claims.nbf)
    || !Number.isSafeInteger(claims.exp)
    || claims.nbf !== claims.iat
    || claims.exp <= claims.iat
    || claims.exp - claims.iat > JWT_RBAC_BASELINE_POLICY.maximumTokenTtlSeconds) {
    fail("JWT_CLAIMS_INVALID");
  }
  const roles = normalizedRoles(claims.roles);
  if (claims.iat > now || claims.nbf > now) fail("JWT_NOT_ACTIVE");
  if (claims.exp <= now) fail("JWT_EXPIRED");
  return Object.freeze({ ...claims, roles });
}

function normalizeResource(resource, action) {
  const fields = ["ownerSubjectId", "resourceId", "resourceType", "tenantId"];
  if (!exactFields(resource, fields)
    || !RESOURCE_ID.test(resource.resourceId ?? "")
    || resource.resourceType !== RESOURCE_TYPES[action]
    || !TENANT_ID.test(resource.tenantId ?? "")
    || !SUBJECT_ID.test(resource.ownerSubjectId ?? "")) {
    fail("EVALUATION_RESOURCE_INVALID");
  }
  return Object.freeze({ ...resource });
}

function scopeAllows(scope, context, resource) {
  if (scope === "self" || scope === "owner") {
    return resource.tenantId === context.tenantId && resource.ownerSubjectId === context.subjectId;
  }
  if (scope === "tenant") return resource.tenantId === context.tenantId;
  return false;
}

function denial(eligibility, reasonCode) {
  return Object.freeze({
    modeId: JWT_RBAC_BASELINE_POLICY.modeId,
    authenticationPolicy: JWT_RBAC_BASELINE_POLICY.authenticationPolicy,
    rolePolicy: JWT_RBAC_BASELINE_POLICY.rolePolicy,
    adaptiveTrustUsed: false,
    rbacOnly: true,
    outcome: "deny",
    reasonCode,
    eligibility,
  });
}

export function createJwtRbacEvaluationTokenIssuer({
  privateKey,
  keyId,
  issuer,
  audience,
  clock = () => new Date(),
  idFactory = randomUUID,
} = {}) {
  const signingKey = privateEd25519Key(privateKey);
  if (!KEY_ID.test(keyId ?? "")) throw new TypeError("A canonical JWT key ID is required.");
  const expectedIssuer = text(issuer, "JWT issuer");
  const expectedAudience = text(audience, "JWT audience");
  if (typeof clock !== "function" || typeof idFactory !== "function") throw new TypeError("Clock and token ID factory functions are required.");

  return Object.freeze({
    issue({ tenantId, subjectId, roles, ttlSeconds = JWT_RBAC_BASELINE_POLICY.maximumTokenTtlSeconds } = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !SUBJECT_ID.test(subjectId ?? "")) fail("JWT_SUBJECT_INVALID");
      if (!Array.isArray(roles)) fail("JWT_SUBJECT_INVALID");
      const normalized = normalizedRoles([...roles].sort(), "JWT_SUBJECT_INVALID");
      if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > JWT_RBAC_BASELINE_POLICY.maximumTokenTtlSeconds) {
        fail("JWT_TTL_INVALID");
      }
      const issuedAt = nowSeconds(clock);
      const tokenId = `jwt_${idFactory()}`;
      if (!TOKEN_ID.test(tokenId)) fail("JWT_TOKEN_ID_INVALID");
      const header = Object.freeze({ alg: "EdDSA", kid: keyId, typ: "JWT" });
      const claims = Object.freeze({
        aud: expectedAudience,
        exp: issuedAt + ttlSeconds,
        iat: issuedAt,
        iss: expectedIssuer,
        jti: tokenId,
        nbf: issuedAt,
        roles: normalized,
        sub: subjectId,
        tid: tenantId,
      });
      const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
      const signature = sign(null, Buffer.from(signingInput, "ascii"), signingKey).toString("base64url");
      return Object.freeze({ token: `${signingInput}.${signature}`, claims });
    },
  });
}

export function createJwtRbacEvaluationBaseline({
  publicKey,
  keyId,
  issuer,
  audience,
  clock = () => new Date(),
} = {}) {
  const verificationKey = publicEd25519Key(publicKey);
  if (!KEY_ID.test(keyId ?? "")) throw new TypeError("A canonical JWT key ID is required.");
  const expected = Object.freeze({ issuer: text(issuer, "JWT issuer"), audience: text(audience, "JWT audience") });
  if (typeof clock !== "function") throw new TypeError("A JWT verification clock is required.");

  function verifyToken(token) {
    if (typeof token !== "string" || token.length < 32 || token.length > 4_096) fail("JWT_FORMAT_INVALID");
    const segments = token.split(".");
    if (segments.length !== 3) fail("JWT_FORMAT_INVALID");
    const [encodedHeader, encodedClaims, encodedSignature] = segments;
    const header = decodeJson(encodedHeader, "JWT_HEADER_INVALID");
    if (!exactFields(header, HEADER_FIELDS)
      || header.alg !== "EdDSA"
      || header.typ !== "JWT"
      || header.kid !== keyId) fail("JWT_HEADER_INVALID");
    const signature = Buffer.from(encodedSignature, "base64url");
    if (signature.length !== 64 || signature.toString("base64url") !== encodedSignature) fail("JWT_SIGNATURE_INVALID");
    const signingInput = `${encodedHeader}.${encodedClaims}`;
    if (!verify(null, Buffer.from(signingInput, "ascii"), verificationKey, signature)) fail("JWT_SIGNATURE_INVALID");
    return normalizeClaims(decodeJson(encodedClaims, "JWT_CLAIMS_INVALID"), expected, nowSeconds(clock));
  }

  function authorize({ token, authority, action, resource } = {}) {
    const claims = verifyToken(token);
    const context = resolveTenantContext({
      authentication: {
        source: "trusted-session",
        authenticationId: claims.jti,
        tenantId: claims.tid,
        subjectId: claims.sub,
      },
      authority: { ...authority, roles: claims.roles },
    });
    const eligibility = resolveRoleAction(context, action);
    if (eligibility.disposition === "deny") {
      return denial(eligibility, eligibility.reason === "default-deny" ? "DEFAULT_DENY" : "ROLE_NOT_ELIGIBLE");
    }
    const target = normalizeResource(resource, action);
    if (!scopeAllows(eligibility.scope, context, target)) return denial(eligibility, "RESOURCE_SCOPE_DENIED");
    return Object.freeze({
      modeId: JWT_RBAC_BASELINE_POLICY.modeId,
      authenticationPolicy: JWT_RBAC_BASELINE_POLICY.authenticationPolicy,
      rolePolicy: JWT_RBAC_BASELINE_POLICY.rolePolicy,
      adaptiveTrustUsed: false,
      rbacOnly: true,
      outcome: "allow",
      reasonCode: "RBAC_ROLE_SCOPE_ALLOW",
      tokenId: claims.jti,
      tokenExpiresAt: new Date(claims.exp * 1_000).toISOString(),
      eligibility,
    });
  }

  return Object.freeze({ policy: JWT_RBAC_BASELINE_POLICY, verifyToken, authorize });
}

export function jwtRbacSafeDenial(error) {
  if (!(error instanceof JwtRbacBaselineError)) throw error;
  return JWT_RBAC_SAFE_DENIAL;
}
