import assert from "node:assert/strict";
import test from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  TRUST_SCORE_LOOKUP_POLICY,
  TrustScoreLookupError,
  createPostgresTrustScoreLookupRepository,
  createTrustScoreLookupService,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
});
const hash = "ab".repeat(32);

function context() {
  return resolveTenantContext({
    authentication: {
      source: "mtls-certificate",
      authenticationId: "score-lookup-test",
      tenantId: ids.tenant,
      subjectId: ids.subject,
    },
    authority: {
      tenant: { tenantId: ids.tenant, state: "active", version: 1 },
      subject: { subjectId: ids.subject, state: "active", version: 1 },
      membership: {
        tenantId: ids.tenant,
        subjectId: ids.subject,
        state: "active",
        version: 1,
      },
      roles: ["tenant-member"],
    },
  });
}

function currentResult(overrides = {}) {
  return {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    state: "fresh",
    usableForPolicy: true,
    requiredOutcome: null,
    reasonCode: null,
    policyScore: 68.5,
    policyBand: "medium",
    lastKnownScore: 68.5,
    lastKnownBand: "medium",
    ageSeconds: 10,
    staleAfterSeconds: 3600,
    transitionId: ids.transition,
    updateVersion: 2,
    modelVersion: "1.0.0",
    configurationVersion: 1,
    observedAt: "2026-10-13T08:00:00.000Z",
    evaluatedAt: "2026-10-13T08:00:01.000Z",
    recordedAt: "2026-10-13T08:00:01.001Z",
    explanationHashSha256: hash,
    ...overrides,
  };
}

function missingResult(overrides = {}) {
  return currentResult({
    state: "missing",
    usableForPolicy: false,
    requiredOutcome: "DENY",
    reasonCode: "TRUST_STATE_MISSING",
    policyScore: null,
    policyBand: null,
    lastKnownScore: null,
    lastKnownBand: null,
    ageSeconds: null,
    staleAfterSeconds: null,
    transitionId: null,
    updateVersion: null,
    modelVersion: null,
    configurationVersion: null,
    observedAt: null,
    evaluatedAt: null,
    recordedAt: null,
    explanationHashSha256: null,
    ...overrides,
  });
}

function serviceWith(result) {
  return createTrustScoreLookupService({
    repository: { lookup: async () => result },
  });
}

test("publishes an immutable fail-closed lookup policy", () => {
  assert.equal(TRUST_SCORE_LOOKUP_POLICY.conservativeOutcome, "DENY");
  assert.equal(TRUST_SCORE_LOOKUP_POLICY.staleScoreExposure, "last-known-only");
  assert.ok(Object.isFrozen(TRUST_SCORE_LOOKUP_POLICY));
  assert.ok(Object.isFrozen(TRUST_SCORE_LOOKUP_POLICY.states));
});

test("fresh current state exposes score, band, age and exact versions", async () => {
  const result = await serviceWith(currentResult()).lookup({ context: context() });
  assert.equal(result.state, "fresh");
  assert.equal(result.usableForPolicy, true);
  assert.equal(result.policyScore, 68.5);
  assert.equal(result.ageSeconds, 10);
  assert.equal(result.modelVersion, "1.0.0");
  assert.equal(result.configurationVersion, 1);
  assert.ok(Object.isFrozen(result));
});

test("the exact freshness boundary remains usable", async () => {
  const result = await serviceWith(currentResult({ ageSeconds: 3600 })).lookup({
    context: context(),
  });
  assert.equal(result.state, "fresh");
  assert.equal(result.policyScore, 68.5);
});

test("stale state withholds the policy score and requires denial", async () => {
  const result = await serviceWith(currentResult({
    state: "stale",
    usableForPolicy: false,
    requiredOutcome: "DENY",
    reasonCode: "TRUST_STATE_STALE",
    policyScore: null,
    policyBand: null,
    ageSeconds: 3600.001,
  })).lookup({ context: context() });
  assert.equal(result.policyScore, null);
  assert.equal(result.lastKnownScore, 68.5);
  assert.equal(result.requiredOutcome, "DENY");
});

test("missing state returns no score, age, transition or versions", async () => {
  const result = await serviceWith(missingResult()).lookup({ context: context() });
  assert.equal(result.state, "missing");
  assert.equal(result.policyScore, null);
  assert.equal(result.ageSeconds, null);
  assert.equal(result.transitionId, null);
  assert.equal(result.modelVersion, null);
  assert.equal(result.requiredOutcome, "DENY");
});

test("only a branded tenant context can request a lookup", async () => {
  let called = false;
  const service = createTrustScoreLookupService({
    repository: { lookup: async () => { called = true; return currentResult(); } },
  });
  await assert.rejects(
    () => service.lookup({ context: { tenantId: ids.tenant, subjectId: ids.subject } }),
    (error) => error instanceof TrustScoreLookupError
      && error.reasonCode === "TRUST_CONTEXT_INVALID",
  );
  assert.equal(called, false);
});

test("malformed, cross-bound and falsely usable results fail closed", async () => {
  for (const result of [
    currentResult({ tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac" }),
    currentResult({ ageSeconds: 3600.001 }),
    currentResult({ state: "stale", usableForPolicy: false, requiredOutcome: "DENY",
      reasonCode: "TRUST_STATE_STALE", policyScore: 68.5, policyBand: "medium",
      ageSeconds: 3600.001 }),
    missingResult({ modelVersion: "1.0.0" }),
  ]) {
    await assert.rejects(
      () => serviceWith(result).lookup({ context: context() }),
      (error) => error instanceof TrustScoreLookupError
        && error.reasonCode === "TRUST_LOOKUP_RESULT_INVALID",
    );
  }
});

test("PostgreSQL lookup binds the trusted actor and exposes no score selector", async () => {
  const calls = [];
  const row = {
    tenant_id: ids.tenant,
    subject_id: ids.subject,
    freshness_state: "fresh",
    usable_for_policy: true,
    required_outcome: null,
    reason_code: null,
    policy_score: "68.50",
    policy_band: "medium",
    last_known_score: "68.50",
    last_known_band: "medium",
    age_seconds: "10.000",
    stale_after_seconds: 3600,
    transition_id: ids.transition,
    update_version: "2",
    model_version: "1.0.0",
    configuration_version: 1,
    observed_at: new Date("2026-10-13T08:00:00.000Z"),
    evaluated_at: new Date("2026-10-13T08:00:01.000Z"),
    recorded_at: new Date("2026-10-13T08:00:01.001Z"),
    explanation_hash_sha256: hash,
  };
  const client = {
    async query(input) {
      calls.push(input);
      if (input.text.includes("get_current_actor_trust_score")) return { rows: [row] };
      return { rows: [] };
    },
    release() { calls.push({ text: "RELEASE" }); },
  };
  const repository = createPostgresTrustScoreLookupRepository({
    pool: { async connect() { return client; } },
  });
  const result = await repository.lookup(context());
  assert.equal(result.policyScore, 68.5);
  assert.deepEqual(calls.slice(0, 5).map(({ text }) => text), [
    "BEGIN",
    "SET LOCAL ROLE tenant_trust_app",
    "SELECT identity.set_tenant_actor_context($1::identity.tenant_id, $2::identity.subject_id)",
    "SELECT * FROM trust.get_current_actor_trust_score()",
    "COMMIT",
  ]);
  assert.deepEqual(calls[2].values, [ids.tenant, ids.subject]);
  assert.deepEqual(calls[3].values, []);
});

test("PostgreSQL failures roll back and release the connection", async () => {
  const calls = [];
  const client = {
    async query(input) {
      calls.push(input.text ?? input);
      if ((input.text ?? input).includes("get_current_actor_trust_score")) {
        throw new Error("lookup unavailable");
      }
      return { rows: [] };
    },
    release() { calls.push("RELEASE"); },
  };
  const repository = createPostgresTrustScoreLookupRepository({
    pool: { async connect() { return client; } },
  });
  await assert.rejects(() => repository.lookup(context()), /lookup unavailable/);
  assert.ok(calls.includes("ROLLBACK"));
  assert.equal(calls.at(-1), "RELEASE");
});
