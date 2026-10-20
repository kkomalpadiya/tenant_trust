import { createHash, randomUUID } from "node:crypto";
import { TenantContextError, assertNoTenantSwitch } from "@tenant-trust/tenant-context";
import { validateAdaptiveAuthorizationPolicyData } from "./adaptive-authorization-policy.mjs";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const POLICY_VERSION_ID = /^pol_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const POLICY_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const MODULE_PATH = /^[a-z0-9][a-z0-9_./-]{0,247}\.rego$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const ENTRYPOINT = "tenant_trust/authorization/decision";
const MAX_MODULES = 32;
const MAX_MODULE_BYTES = 128 * 1024;
const MAX_BUNDLE_BYTES = 1024 * 1024;
const VALIDATORS = new WeakSet();

const PUBLISH_SQL = `
  SELECT * FROM trust.publish_policy_bundle(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
  )
`;
const ACTIVATE_SQL = "SELECT * FROM trust.activate_policy_bundle($1, $2, $3)";
const HISTORY_SQL = "SELECT * FROM trust.list_policy_bundle_history($1)";
const ACTIVE_SQL = "SELECT * FROM trust.get_active_policy_bundle($1)";

export const POLICY_BUNDLE_LIFECYCLE = Object.freeze({
  schemaVersion: "1.0.0",
  policyName: "access-control",
  entrypoint: ENTRYPOINT,
  canonicalization: "tenant-trust-policy-json-v1",
  validationEngine: "opa",
  regoVersion: "v1",
  maximumModules: MAX_MODULES,
  maximumModuleBytes: MAX_MODULE_BYTES,
  maximumBundleBytes: MAX_BUNDLE_BYTES,
  states: Object.freeze(["published", "active", "superseded"]),
  activation: "atomic-single-active-per-tenant-policy",
});

export const POLICY_BUNDLE_DENIAL = Object.freeze({ statusCode: 403, code: "ACCESS_DENIED" });

export class PolicyBundleError extends Error {
  constructor(reasonCode) {
    super("Policy bundle operation denied.");
    this.name = "PolicyBundleError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new PolicyBundleError(reasonCode);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function requireExactFields(value, fields, reasonCode) {
  if (!isPlainObject(value)) fail(reasonCode);
  const actual = Object.keys(value).sort();
  if (actual.length !== fields.length || actual.some((field, index) => field !== fields[index])) {
    fail(reasonCode);
  }
  return value;
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("BUNDLE_DATA_INVALID");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  fail("BUNDLE_DATA_INVALID");
}

function cloneJson(value) {
  try {
    const canonical = canonicalize(value);
    if (Buffer.byteLength(canonical, "utf8") > MAX_BUNDLE_BYTES) fail("BUNDLE_TOO_LARGE");
    return JSON.parse(canonical);
  } catch (error) {
    if (error instanceof PolicyBundleError) throw error;
    fail("BUNDLE_DATA_INVALID");
  }
}

function trustedContext(value, adminRequired) {
  try {
    const context = assertNoTenantSwitch(value, []);
    if (adminRequired && !context.roles.includes("tenant-admin")) fail("TENANT_ADMIN_REQUIRED");
    return context;
  } catch (error) {
    if (error instanceof TenantContextError) fail("TENANT_CONTEXT_INVALID");
    throw error;
  }
}

function utcNow(clock) {
  let value;
  try {
    value = clock();
  } catch {
    fail("POLICY_TIME_INVALID");
  }
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail("POLICY_TIME_INVALID");
  return value.toISOString();
}

function normalizeModules(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_MODULES) {
    fail("BUNDLE_MODULES_INVALID");
  }
  const modules = value.map((module) => {
    const input = requireExactFields(module, ["path", "source"], "BUNDLE_MODULE_INVALID");
    const path = input.path;
    const source = typeof input.source === "string"
      ? input.source.replace(/\r\n?/gu, "\n")
      : null;
    if (!MODULE_PATH.test(path ?? "")
      || path.startsWith("/")
      || path.split("/").includes("..")
      || source === null
      || Buffer.byteLength(source, "utf8") < 1
      || Buffer.byteLength(source, "utf8") > MAX_MODULE_BYTES
      || source.includes("\u0000")
      || !/^\s*package\s+tenant_trust\.authorization\s*$/mu.test(source)) {
      fail("BUNDLE_MODULE_INVALID");
    }
    return { path, source };
  });
  modules.sort((left, right) => left.path.localeCompare(right.path));
  if (new Set(modules.map(({ path }) => path)).size !== modules.length) {
    fail("BUNDLE_MODULES_INVALID");
  }
  return modules;
}

function normalizePublishRequest(value, tenantId) {
  const input = requireExactFields(
    value,
    ["bundleVersion", "data", "entrypoint", "modules", "policyName", "reasonCode"],
    "PUBLISH_REQUEST_INVALID",
  );
  if (!POLICY_NAME.test(input.policyName ?? "")
    || !Number.isSafeInteger(input.bundleVersion)
    || input.bundleVersion < 1
    || input.entrypoint !== ENTRYPOINT
    || !REASON_CODE.test(input.reasonCode ?? "")) {
    fail("PUBLISH_REQUEST_INVALID");
  }
  const data = cloneJson(input.data);
  return {
    policyName: input.policyName,
    bundleVersion: input.bundleVersion,
    entrypoint: input.entrypoint,
    modules: normalizeModules(input.modules),
    data: input.policyName === POLICY_BUNDLE_LIFECYCLE.policyName
      ? validateAdaptiveAuthorizationPolicyData(data, tenantId)
      : data,
    reasonCode: input.reasonCode,
  };
}

function normalizeValidationReceipt(value, checkedAt) {
  const receipt = requireExactFields(
    value,
    ["engine", "engineVersion", "regoVersion"],
    "BUNDLE_VALIDATION_FAILED",
  );
  if (receipt.engine !== "opa"
    || !SEMVER.test(receipt.engineVersion ?? "")
    || receipt.regoVersion !== "v1") {
    fail("BUNDLE_VALIDATION_FAILED");
  }
  return { ...receipt, checkedAt };
}

export function hashPolicyBundleDocument(document) {
  return createHash("sha256").update(canonicalize(document), "utf8").digest("hex");
}

export function createOpaPolicyBundleValidator({ compile } = {}) {
  if (typeof compile !== "function") throw new TypeError("An OPA bundle compiler is required.");
  const validator = Object.freeze({
    async validate(bundle, { signal } = {}) {
      let receipt;
      try {
        receipt = await compile(deepFreeze(structuredClone(bundle)), { signal });
      } catch {
        fail("BUNDLE_VALIDATION_FAILED");
      }
      return receipt;
    },
  });
  VALIDATORS.add(validator);
  return validator;
}

export function assertOpaPolicyBundleValidator(value) {
  if (!value || typeof value !== "object" || !VALIDATORS.has(value)) {
    throw new TypeError("A branded OPA policy bundle validator is required.");
  }
  return value;
}

function requirePolicyVersionId(idFactory) {
  const value = idFactory();
  if (!POLICY_VERSION_ID.test(value ?? "")) fail("POLICY_VERSION_ID_INVALID");
  return value;
}

function exactUtcOrNull(value) {
  if (value === null) return null;
  if (typeof value !== "string" || !value.endsWith("Z")) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value ? value : false;
}

function validateBundle(value, expectedTenantId) {
  const document = value?.bundleDocument;
  if (!value
    || value.tenantId !== expectedTenantId
    || !TENANT_ID.test(value.tenantId ?? "")
    || !POLICY_VERSION_ID.test(value.policyVersionId ?? "")
    || !POLICY_NAME.test(value.policyName ?? "")
    || !Number.isSafeInteger(value.bundleVersion)
    || value.bundleVersion < 1
    || !/^[0-9a-f]{64}$/u.test(value.bundleHashSha256 ?? "")
    || value.entrypoint !== ENTRYPOINT
    || !new Set(POLICY_BUNDLE_LIFECYCLE.states).has(value.state)
    || !SUBJECT_ID.test(value.publishedBySubjectId ?? "")
    || exactUtcOrNull(value.activatedAt) === false
    || exactUtcOrNull(value.supersededAt) === false
    || exactUtcOrNull(value.createdAt) === false
    || exactUtcOrNull(value.updatedAt) === false
    || typeof value.bundleCanonicalJson !== "string"
    || !isPlainObject(document)
    || document.schemaVersion !== POLICY_BUNDLE_LIFECYCLE.schemaVersion
    || document.tenantId !== value.tenantId
    || document.policyVersionId !== value.policyVersionId
    || document.policyName !== value.policyName
    || document.bundleVersion !== value.bundleVersion
    || document.entrypoint !== value.entrypoint
    || !Array.isArray(document.modules)
    || document.modules.length < 1
    || !isPlainObject(document.data)
    || !isPlainObject(document.validation)
    || document.validation.engine !== value.validationEngine
    || document.validation.engineVersion !== value.validationEngineVersion
    || document.validation.regoVersion !== value.regoVersion
    || document.validation.checkedAt !== value.validatedAt
    || hashPolicyBundleDocument(document) !== value.bundleHashSha256
    || canonicalize(document) !== value.bundleCanonicalJson) {
    fail("POLICY_BUNDLE_RESULT_INVALID");
  }
  return deepFreeze(structuredClone(value));
}

export function createPolicyBundleManagementService({
  repository,
  validator,
  idFactory = () => `pol_${randomUUID()}`,
  clock = () => new Date(),
} = {}) {
  if (!repository
    || typeof repository.publish !== "function"
    || typeof repository.activate !== "function"
    || typeof repository.listHistory !== "function"
    || typeof idFactory !== "function"
    || typeof clock !== "function") {
    throw new TypeError("A complete policy bundle repository, ID factory and clock are required.");
  }
  assertOpaPolicyBundleValidator(validator);

  return Object.freeze({
    policy: POLICY_BUNDLE_LIFECYCLE,

    async publish({ context: contextValue, request, signal } = {}) {
      const context = trustedContext(contextValue, true);
      const normalized = normalizePublishRequest(request, context.tenantId);
      const policyVersionId = requirePolicyVersionId(idFactory);
      const occurredAt = utcNow(clock);
      const candidate = deepFreeze({
        entrypoint: normalized.entrypoint,
        modules: structuredClone(normalized.modules),
        data: structuredClone(normalized.data),
      });
      const validation = normalizeValidationReceipt(
        await validator.validate(candidate, { signal }),
        occurredAt,
      );
      const document = deepFreeze({
        schemaVersion: POLICY_BUNDLE_LIFECYCLE.schemaVersion,
        tenantId: context.tenantId,
        policyVersionId,
        policyName: normalized.policyName,
        bundleVersion: normalized.bundleVersion,
        entrypoint: normalized.entrypoint,
        modules: structuredClone(normalized.modules),
        data: structuredClone(normalized.data),
        validation,
      });
      const bundleCanonicalJson = canonicalize(document);
      const bundleHashSha256 = hashPolicyBundleDocument(document);
      const result = await repository.publish({
        tenantId: context.tenantId,
        actorSubjectId: context.subjectId,
        policyVersionId,
        policyName: normalized.policyName,
        bundleVersion: normalized.bundleVersion,
        bundleHashSha256,
        entrypoint: normalized.entrypoint,
        bundleCanonicalJson,
        validation,
        reasonCode: normalized.reasonCode,
        occurredAt,
      }, { signal });
      const published = validateBundle(result, context.tenantId);
      if (published.state !== "published"
        || published.policyVersionId !== policyVersionId
        || published.bundleVersion !== normalized.bundleVersion
        || published.bundleHashSha256 !== bundleHashSha256
        || published.publishedBySubjectId !== context.subjectId) {
        fail("POLICY_BUNDLE_WRITE_UNCONFIRMED");
      }
      return published;
    },

    async activate({ context: contextValue, request, signal } = {}) {
      const context = trustedContext(contextValue, true);
      const input = requireExactFields(
        request,
        ["policyVersionId", "reasonCode"],
        "ACTIVATION_REQUEST_INVALID",
      );
      if (!POLICY_VERSION_ID.test(input.policyVersionId ?? "")
        || !REASON_CODE.test(input.reasonCode ?? "")) {
        fail("ACTIVATION_REQUEST_INVALID");
      }
      const result = await repository.activate({
        tenantId: context.tenantId,
        actorSubjectId: context.subjectId,
        policyVersionId: input.policyVersionId,
        reasonCode: input.reasonCode,
        occurredAt: utcNow(clock),
      }, { signal });
      const active = validateBundle(result, context.tenantId);
      if (active.state !== "active"
        || active.policyVersionId !== input.policyVersionId
        || active.activatedAt === null
        || active.supersededAt !== null) {
        fail("POLICY_BUNDLE_WRITE_UNCONFIRMED");
      }
      return active;
    },

    async history({ context: contextValue, policyName = POLICY_BUNDLE_LIFECYCLE.policyName, signal } = {}) {
      const context = trustedContext(contextValue, true);
      if (!POLICY_NAME.test(policyName ?? "")) fail("POLICY_NAME_INVALID");
      const rows = await repository.listHistory({
        tenantId: context.tenantId,
        actorSubjectId: context.subjectId,
        policyName,
      }, { signal });
      if (!Array.isArray(rows) || rows.length < 1) fail("POLICY_BUNDLE_HISTORY_INVALID");
      const versions = new Set();
      const history = rows.map((row) => {
        const bundle = validateBundle(row, context.tenantId);
        if (bundle.policyName !== policyName || versions.has(bundle.bundleVersion)) {
          fail("POLICY_BUNDLE_HISTORY_INVALID");
        }
        versions.add(bundle.bundleVersion);
        return bundle;
      });
      if (history.some((bundle, index) => index > 0
        && bundle.bundleVersion >= history[index - 1].bundleVersion)) {
        fail("POLICY_BUNDLE_HISTORY_INVALID");
      }
      return deepFreeze(history);
    },
  });
}

export function createPolicyBundleLookupService({ repository } = {}) {
  if (!repository || typeof repository.getActive !== "function") {
    throw new TypeError("A policy bundle lookup repository is required.");
  }
  return Object.freeze({
    policy: POLICY_BUNDLE_LIFECYCLE,
    async lookupActive({ context: contextValue, policyName = POLICY_BUNDLE_LIFECYCLE.policyName, signal } = {}) {
      const context = trustedContext(contextValue, false);
      if (!POLICY_NAME.test(policyName ?? "")) fail("POLICY_NAME_INVALID");
      const result = await repository.getActive({ tenantId: context.tenantId, policyName }, { signal });
      if (result === null) fail("ACTIVE_POLICY_BUNDLE_MISSING");
      const active = validateBundle(result, context.tenantId);
      if (active.state !== "active" || active.policyName !== policyName) {
        fail("ACTIVE_POLICY_BUNDLE_INVALID");
      }
      return active;
    },
  });
}

function canonicalTimestamp(value) {
  if (value === null || value === undefined) return null;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) fail("POLICY_BUNDLE_RESULT_INVALID");
  return parsed.toISOString();
}

function mapBundle(row) {
  if (!row) return null;
  let bundleDocument;
  try {
    bundleDocument = typeof row.bundle_canonical_json === "string"
      ? JSON.parse(row.bundle_canonical_json)
      : row.bundle_document;
  } catch {
    fail("POLICY_BUNDLE_RESULT_INVALID");
  }
  return {
    tenantId: row.tenant_id,
    policyVersionId: row.policy_version_id,
    policyName: row.policy_name,
    bundleVersion: Number(row.bundle_version),
    bundleHashSha256: row.bundle_hash_sha256,
    entrypoint: row.entrypoint,
    state: row.state,
    replacesPolicyVersionId: row.replaces_policy_version_id ?? null,
    publishedBySubjectId: row.published_by_subject_id,
    bundleDocument,
    bundleCanonicalJson: row.bundle_canonical_json,
    validationEngine: row.validation_engine,
    validationEngineVersion: row.validation_engine_version,
    regoVersion: row.rego_version,
    validatedAt: canonicalTimestamp(row.validated_at),
    activatedAt: canonicalTimestamp(row.activated_at),
    supersededAt: canonicalTimestamp(row.superseded_at),
    createdAt: canonicalTimestamp(row.created_at),
    updatedAt: canonicalTimestamp(row.updated_at),
    latestEventType: row.latest_event_type ?? null,
    latestReasonCode: row.latest_reason_code ?? null,
  };
}

function singleRow(result, reasonCode) {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) fail(reasonCode);
  return result.rows[0];
}

export function createPostgresPolicyBundleRepository({ query } = {}) {
  if (typeof query !== "function") {
    throw new TypeError("A transaction-bound PostgreSQL query function is required.");
  }
  return Object.freeze({
    async publish(record, { signal } = {}) {
      const result = await query(PUBLISH_SQL, [
        record.policyVersionId,
        record.policyName,
        record.bundleVersion,
        record.bundleHashSha256,
        record.entrypoint,
        record.bundleCanonicalJson,
        record.validation.engineVersion,
        record.validation.regoVersion,
        record.reasonCode,
        record.occurredAt,
      ], { signal });
      return mapBundle(singleRow(result, "POLICY_BUNDLE_WRITE_UNCONFIRMED"));
    },
    async activate(record, { signal } = {}) {
      const result = await query(ACTIVATE_SQL, [
        record.policyVersionId,
        record.reasonCode,
        record.occurredAt,
      ], { signal });
      return mapBundle(singleRow(result, "POLICY_BUNDLE_WRITE_UNCONFIRMED"));
    },
    async listHistory(record, { signal } = {}) {
      const result = await query(HISTORY_SQL, [record.policyName], { signal });
      if (!result || !Array.isArray(result.rows)) fail("POLICY_BUNDLE_HISTORY_INVALID");
      return result.rows.map(mapBundle);
    },
    async getActive(record, { signal } = {}) {
      const result = await query(ACTIVE_SQL, [record.policyName], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length > 1) {
        fail("ACTIVE_POLICY_BUNDLE_INVALID");
      }
      return result.rows.length === 0 ? null : mapBundle(result.rows[0]);
    },
  });
}

export function policyBundleSafeDenial(error) {
  if (!(error instanceof PolicyBundleError)) throw error;
  return POLICY_BUNDLE_DENIAL;
}
