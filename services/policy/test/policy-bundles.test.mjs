import assert from "node:assert/strict";
import test from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  POLICY_BUNDLE_LIFECYCLE,
  PolicyBundleError,
  createSlide14PrototypePolicyData,
  createOpaPolicyBundleValidator,
  createPolicyBundleLookupService,
  createPolicyBundleManagementService,
  createPostgresPolicyBundleRepository,
  hashPolicyBundleDocument,
  policyBundleSafeDenial,
} from "../src/index.mjs";

const ids = Object.freeze({
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  admin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  member: "sub_018f1234-5678-7abc-8def-0123456789ab",
  policy1: "pol_018f1234-5678-7abc-8def-0123456789c0",
  policy2: "pol_018f1234-5678-7abc-8def-0123456789c2",
});

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map(
    (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
  ).join(",")}}`;
}

function context({ tenantId = ids.alpha, subjectId = ids.admin, roles = ["tenant-admin"] } = {}) {
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "policy-test", tenantId, subjectId },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId, state: "active", version: 1 },
      membership: { tenantId, subjectId, state: "active", version: 1 },
      roles,
    },
  });
}

const publishRequest = Object.freeze({
  policyName: "access-control",
  bundleVersion: 2,
  entrypoint: "tenant_trust/authorization/decision",
  modules: Object.freeze([Object.freeze({
    path: "tenant_trust/authorization.rego",
    source: "package tenant_trust.authorization\n\ndefault decision := null\n",
  })]),
  data: createSlide14PrototypePolicyData({ tenantId: ids.alpha }),
  reasonCode: "INITIAL_VALIDATED_BUNDLE",
});

function validator(compile = async () => ({
  engine: "opa",
  engineVersion: "1.20.2",
  regoVersion: "v1",
})) {
  return createOpaPolicyBundleValidator({ compile });
}

function mappedBundle(record, overrides = {}) {
  const document = JSON.parse(record.bundleCanonicalJson);
  return {
    tenantId: record.tenantId,
    policyVersionId: record.policyVersionId,
    policyName: record.policyName,
    bundleVersion: record.bundleVersion,
    bundleHashSha256: record.bundleHashSha256,
    entrypoint: record.entrypoint,
    state: "published",
    replacesPolicyVersionId: ids.policy1,
    publishedBySubjectId: record.actorSubjectId,
    bundleDocument: document,
    bundleCanonicalJson: record.bundleCanonicalJson,
    validationEngine: "opa",
    validationEngineVersion: record.validation.engineVersion,
    regoVersion: record.validation.regoVersion,
    validatedAt: record.validation.checkedAt,
    activatedAt: null,
    supersededAt: null,
    createdAt: record.occurredAt,
    updatedAt: record.occurredAt,
    latestEventType: "published",
    latestReasonCode: record.reasonCode,
    ...overrides,
  };
}

function serviceWith(overrides = {}) {
  let published;
  const repository = {
    async publish(record) {
      published = mappedBundle(record);
      return published;
    },
    async activate(record) {
      return {
        ...published,
        state: "active",
        activatedAt: record.occurredAt,
        latestEventType: "activated",
        latestReasonCode: record.reasonCode,
      };
    },
    async listHistory() {
      const oldDocument = {
        ...published.bundleDocument,
        policyVersionId: ids.policy1,
        bundleVersion: 1,
      };
      return [
        { ...published, state: "active", activatedAt: published.createdAt },
        {
          ...published,
          policyVersionId: ids.policy1,
          bundleVersion: 1,
          bundleDocument: oldDocument,
          bundleCanonicalJson: canonicalJson(oldDocument),
          bundleHashSha256: hashPolicyBundleDocument(oldDocument),
          state: "superseded",
        },
      ];
    },
    ...overrides,
  };
  return createPolicyBundleManagementService({
    repository,
    validator: validator(),
    idFactory: () => ids.policy2,
    clock: () => new Date("2026-10-13T09:00:00.000Z"),
  });
}

test("publishes one immutable tenant-bound bundle only after OPA validation", async () => {
  let compiled;
  let persisted;
  const service = createPolicyBundleManagementService({
    validator: validator(async (candidate) => {
      compiled = candidate;
      return { engine: "opa", engineVersion: "1.20.2", regoVersion: "v1" };
    }),
    repository: {
      async publish(record) {
        persisted = record;
        return mappedBundle(record);
      },
      async activate() {},
      async listHistory() {},
    },
    idFactory: () => ids.policy2,
    clock: () => new Date("2026-10-13T09:00:00.000Z"),
  });

  const result = await service.publish({ context: context(), request: publishRequest });

  assert.equal(compiled.entrypoint, POLICY_BUNDLE_LIFECYCLE.entrypoint);
  assert.equal(persisted.tenantId, ids.alpha);
  assert.equal(persisted.actorSubjectId, ids.admin);
  assert.equal(result.policyVersionId, ids.policy2);
  assert.equal(result.bundleVersion, 2);
  assert.equal(hashPolicyBundleDocument(result.bundleDocument), result.bundleHashSha256);
  assert.equal(result.bundleDocument.tenantId, ids.alpha);
  assert.equal(result.bundleDocument.validation.engineVersion, "1.20.2");
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.bundleDocument));
});

test("members and caller-selected authority cannot publish or activate bundles", async () => {
  const service = serviceWith();
  const member = context({ subjectId: ids.member, roles: ["tenant-member"] });
  await assert.rejects(
    service.publish({ context: member, request: publishRequest }),
    (error) => error instanceof PolicyBundleError && error.reasonCode === "TENANT_ADMIN_REQUIRED",
  );
  await assert.rejects(
    service.publish({ context: context(), request: { ...publishRequest, tenantId: ids.beta } }),
    PolicyBundleError,
  );
  await assert.rejects(
    service.activate({
      context: member,
      request: { policyVersionId: ids.policy2, reasonCode: "ACTIVATE_BUNDLE" },
    }),
    PolicyBundleError,
  );
});

test("invalid module shape, paths, entrypoints and failed compilation are rejected before persistence", async () => {
  let writes = 0;
  const repository = {
    publish: async () => { writes += 1; },
    activate: async () => {},
    listHistory: async () => [],
  };
  const requests = [
    { ...publishRequest, entrypoint: "tenant_trust/authz/decision" },
    { ...publishRequest, modules: [{ path: "../escape.rego", source: "package tenant_trust.authorization" }] },
    { ...publishRequest, modules: [{ path: "policy.rego", source: "package other" }] },
    { ...publishRequest, bundleVersion: 0 },
    { ...publishRequest, data: { score: Number.NaN } },
  ];
  const service = createPolicyBundleManagementService({
    repository,
    validator: validator(),
    idFactory: () => ids.policy2,
  });
  for (const request of requests) {
    await assert.rejects(service.publish({ context: context(), request }), PolicyBundleError);
  }
  const compileFailure = createPolicyBundleManagementService({
    repository,
    validator: validator(async () => { throw new Error("rego parse detail"); }),
    idFactory: () => ids.policy2,
  });
  await assert.rejects(
    compileFailure.publish({ context: context(), request: publishRequest }),
    (error) => error instanceof PolicyBundleError && error.reasonCode === "BUNDLE_VALIDATION_FAILED",
  );
  assert.equal(writes, 0);
});

test("activation confirms the exact active version and history remains descending", async () => {
  const service = serviceWith();
  await service.publish({ context: context(), request: publishRequest });
  const active = await service.activate({
    context: context(),
    request: { policyVersionId: ids.policy2, reasonCode: "ACTIVATE_BUNDLE" },
  });
  const history = await service.history({ context: context() });

  assert.equal(active.state, "active");
  assert.equal(active.policyVersionId, ids.policy2);
  assert.deepEqual(history.map(({ bundleVersion }) => bundleVersion), [2, 1]);
  assert.ok(Object.isFrozen(history));
});

test("active lookup is tenant-bound and rejects missing or foreign results", async () => {
  const document = {
    schemaVersion: "1.0.0",
    tenantId: ids.alpha,
    policyVersionId: ids.policy2,
    policyName: "access-control",
    bundleVersion: 2,
    entrypoint: POLICY_BUNDLE_LIFECYCLE.entrypoint,
    modules: [{ path: "policy.rego", source: "package tenant_trust.authorization" }],
    data: {},
    validation: {
      engine: "opa",
      engineVersion: "1.20.2",
      regoVersion: "v1",
      checkedAt: "2026-10-13T09:00:00.000Z",
    },
  };
  const baseRecord = {
    tenantId: ids.alpha,
    policyVersionId: ids.policy2,
    policyName: "access-control",
    bundleVersion: 2,
    bundleHashSha256: hashPolicyBundleDocument(document),
    entrypoint: POLICY_BUNDLE_LIFECYCLE.entrypoint,
    state: "active",
    replacesPolicyVersionId: ids.policy1,
    publishedBySubjectId: ids.admin,
    bundleDocument: document,
    bundleCanonicalJson: canonicalJson(document),
    validationEngine: "opa",
    validationEngineVersion: "1.20.2",
    regoVersion: "v1",
    validatedAt: "2026-10-13T09:00:00.000Z",
    activatedAt: "2026-10-13T09:00:01.000Z",
    supersededAt: null,
    createdAt: "2026-10-13T09:00:00.000Z",
    updatedAt: "2026-10-13T09:00:01.000Z",
  };
  const service = createPolicyBundleLookupService({ repository: { getActive: async () => baseRecord } });
  assert.equal((await service.lookupActive({ context: context() })).tenantId, ids.alpha);

  await assert.rejects(
    createPolicyBundleLookupService({ repository: { getActive: async () => null } })
      .lookupActive({ context: context() }),
    PolicyBundleError,
  );
  await assert.rejects(
    createPolicyBundleLookupService({
      repository: { getActive: async () => ({ ...baseRecord, tenantId: ids.beta }) },
    }).lookupActive({ context: context() }),
    PolicyBundleError,
  );
});

function databaseRow(overrides = {}) {
  const document = {
    schemaVersion: "1.0.0",
    tenantId: ids.alpha,
    policyVersionId: ids.policy2,
    policyName: "access-control",
    bundleVersion: 2,
    entrypoint: POLICY_BUNDLE_LIFECYCLE.entrypoint,
    modules: [{ path: "policy.rego", source: "package tenant_trust.authorization" }],
    data: {},
    validation: {
      engine: "opa",
      engineVersion: "1.20.2",
      regoVersion: "v1",
      checkedAt: "2026-10-13T09:00:00.000Z",
    },
  };
  const canonical = canonicalJson(document);
  return {
    tenant_id: ids.alpha,
    policy_version_id: ids.policy2,
    policy_name: "access-control",
    bundle_version: 2,
    bundle_hash_sha256: hashPolicyBundleDocument(document),
    entrypoint: POLICY_BUNDLE_LIFECYCLE.entrypoint,
    state: "published",
    replaces_policy_version_id: ids.policy1,
    published_by_subject_id: ids.admin,
    bundle_document: document,
    bundle_canonical_json: canonical,
    validation_engine: "opa",
    validation_engine_version: "1.20.2",
    rego_version: "v1",
    validated_at: new Date("2026-10-13T09:00:00.000Z"),
    activated_at: null,
    superseded_at: null,
    created_at: new Date("2026-10-13T09:00:00.000Z"),
    updated_at: new Date("2026-10-13T09:00:00.000Z"),
    ...overrides,
  };
}

test("PostgreSQL adapter calls only constrained lifecycle and lookup functions", async () => {
  const calls = [];
  const repository = createPostgresPolicyBundleRepository({
    query: async (text, values, options) => {
      calls.push({ text, values, options });
      if (text.includes("list_policy_bundle_history")) return { rows: [databaseRow()] };
      if (text.includes("get_active_policy_bundle")) {
        return { rows: [databaseRow({ state: "active", activated_at: new Date("2026-10-13T09:00:01.000Z") })] };
      }
      if (text.includes("activate_policy_bundle")) {
        return { rows: [databaseRow({ state: "active", activated_at: new Date("2026-10-13T09:00:01.000Z") })] };
      }
      return { rows: [databaseRow()] };
    },
  });
  const record = {
    policyVersionId: ids.policy2,
    policyName: "access-control",
    bundleVersion: 2,
    bundleHashSha256: databaseRow().bundle_hash_sha256,
    entrypoint: POLICY_BUNDLE_LIFECYCLE.entrypoint,
    bundleCanonicalJson: databaseRow().bundle_canonical_json,
    validation: { engineVersion: "1.20.2", regoVersion: "v1" },
    reasonCode: "TEST_BUNDLE",
    occurredAt: "2026-10-13T09:00:00.000Z",
  };

  await repository.publish(record);
  await repository.activate(record);
  await repository.listHistory(record);
  await repository.getActive(record);

  assert.equal(calls.length, 4);
  assert.equal(calls[0].values.length, 10);
  assert.deepEqual(calls[1].values, [ids.policy2, "TEST_BUNDLE", record.occurredAt]);
  assert.deepEqual(calls[2].values, ["access-control"]);
  assert.deepEqual(calls[3].values, ["access-control"]);
  assert.equal(policyBundleSafeDenial(new PolicyBundleError("TEST")).code, "ACCESS_DENIED");
  assert.throws(() => policyBundleSafeDenial(new Error("boom")));
});
