import assert from "node:assert/strict";
import test from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  TRUST_CONFIGURATION_MANAGEMENT_DENIAL,
  TrustConfigurationManagementError,
  createPostgresTrustConfigurationRepository,
  createTrustConfigurationManagementService,
  trustConfigurationManagementSafeDenial,
} from "../src/index.mjs";

const ids = Object.freeze({
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  admin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  member: "sub_018f1234-5678-7abc-8def-0123456789ab",
});

const weights = Object.freeze({
  identity: 0.20,
  device: 0.25,
  behaviour: 0.25,
  certificate: 0.15,
  compliance: 0.15,
});

const draftRequest = Object.freeze({
  modelVersion: "1.1.0",
  initialScore: 62,
  smoothingAlpha: 0.35,
  maximumSourceInfluence: 0.20,
  staleAfterSeconds: 2700,
  weights,
  reasonCode: "MODEL_TUNING",
});

function context({
  tenantId = ids.alpha,
  subjectId = ids.admin,
  roles = ["tenant-admin"],
} = {}) {
  return resolveTenantContext({
    authentication: {
      source: "trusted-session",
      authenticationId: "trust-configuration-test",
      tenantId,
      subjectId,
    },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId, state: "active", version: 1 },
      membership: { tenantId, subjectId, state: "active", version: 1 },
      roles,
    },
  });
}

function configuration({
  tenantId = ids.alpha,
  configurationVersion = 2,
  modelVersion = draftRequest.modelVersion,
  state = "draft",
  initialScore = draftRequest.initialScore,
  smoothingAlpha = draftRequest.smoothingAlpha,
  maximumSourceInfluence = draftRequest.maximumSourceInfluence,
  staleAfterSeconds = draftRequest.staleAfterSeconds,
  configurationWeights = weights,
  createdBySubjectId = ids.admin,
  activatedAt = null,
  supersededAt = null,
  latestEventType = "draft_created",
  latestReasonCode = "MODEL_TUNING",
  latestActorSubjectId = ids.admin,
  previousActiveConfigurationVersion = 1,
  rollbackTargetConfigurationVersion = null,
} = {}) {
  return {
    tenantId,
    configurationVersion,
    modelVersion,
    state,
    initialScore,
    smoothingAlpha,
    maximumSourceInfluence,
    staleAfterSeconds,
    weights: { ...configurationWeights },
    createdBySubjectId,
    activatedAt,
    supersededAt,
    createdAt: "2026-10-07T08:00:00.000Z",
    updatedAt: "2026-10-07T08:00:00.000Z",
    latestEventType,
    latestReasonCode,
    latestActorSubjectId,
    previousActiveConfigurationVersion,
    rollbackTargetConfigurationVersion,
    latestEventAt: latestEventType ? "2026-10-07T08:00:00.000Z" : null,
  };
}

function serviceWith(overrides = {}) {
  return createTrustConfigurationManagementService({
    clock: () => new Date("2026-10-07T08:00:00.000Z"),
    repository: {
      createDraft: async () => configuration(),
      activate: async (record) => configuration({
        configurationVersion: record.configurationVersion,
        state: "active",
        activatedAt: record.occurredAt,
        latestEventType: "activated",
        latestReasonCode: record.reasonCode,
      }),
      rollback: async (record) => configuration({
        configurationVersion: 3,
        modelVersion: "1.0.0",
        state: "active",
        initialScore: 60,
        smoothingAlpha: 0.30,
        maximumSourceInfluence: 0.25,
        staleAfterSeconds: 3600,
        createdBySubjectId: record.actorSubjectId,
        activatedAt: record.occurredAt,
        latestEventType: "rollback_activated",
        latestReasonCode: record.reasonCode,
        previousActiveConfigurationVersion: 2,
        rollbackTargetConfigurationVersion: record.targetConfigurationVersion,
      }),
      listHistory: async () => [
        configuration({
          configurationVersion: 2,
          state: "active",
          activatedAt: "2026-10-07T08:00:00.000Z",
          latestEventType: "activated",
        }),
        configuration({
          configurationVersion: 1,
          modelVersion: "1.0.0",
          state: "superseded",
          initialScore: 60,
          smoothingAlpha: 0.30,
          maximumSourceInfluence: 0.25,
          staleAfterSeconds: 3600,
          activatedAt: "2026-01-01T00:00:00.000Z",
          supersededAt: "2026-10-07T08:00:00.000Z",
          latestEventType: null,
          latestReasonCode: null,
          latestActorSubjectId: null,
          previousActiveConfigurationVersion: null,
        }),
      ],
      ...overrides,
    },
  });
}

test("tenant administrators create validated immutable drafts with server-owned scope", async () => {
  let persisted;
  const service = serviceWith({
    createDraft: async (record) => {
      persisted = record;
      return configuration();
    },
  });
  const result = await service.createDraft({ context: context(), request: draftRequest });

  assert.equal(persisted.tenantId, ids.alpha);
  assert.equal(persisted.actorSubjectId, ids.admin);
  assert.equal(persisted.occurredAt, "2026-10-07T08:00:00.000Z");
  assert.equal(result.configurationVersion, 2);
  assert.equal(result.state, "draft");
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.weights));
});

test("ordinary members cannot create, activate, rollback or read configuration history", async () => {
  const service = serviceWith();
  const memberContext = context({ subjectId: ids.member, roles: ["tenant-member"] });
  for (const operation of [
    () => service.createDraft({ context: memberContext, request: draftRequest }),
    () => service.activate({
      context: memberContext,
      request: { configurationVersion: 2, reasonCode: "ACTIVATE_MODEL" },
    }),
    () => service.rollback({
      context: memberContext,
      request: { targetConfigurationVersion: 1, reasonCode: "RESTORE_BASELINE" },
    }),
    () => service.history({ context: memberContext }),
  ]) {
    await assert.rejects(operation, (error) => error instanceof TrustConfigurationManagementError
      && error.reasonCode === "TENANT_ADMIN_REQUIRED");
  }
});

test("draft validation rejects caller authority, bad ranges and non-unit weights", async () => {
  const service = serviceWith();
  const invalidRequests = [
    { ...draftRequest, tenantId: ids.beta },
    { ...draftRequest, modelVersion: "01.0.0" },
    { ...draftRequest, smoothingAlpha: 0 },
    { ...draftRequest, maximumSourceInfluence: 0 },
    { ...draftRequest, staleAfterSeconds: 0 },
    { ...draftRequest, initialScore: 101 },
    { ...draftRequest, weights: { ...weights, compliance: 0.14 } },
    { ...draftRequest, reasonCode: "bad reason" },
  ];
  for (const request of invalidRequests) {
    await assert.rejects(
      () => service.createDraft({ context: context(), request }),
      (error) => error instanceof TrustConfigurationManagementError,
    );
  }
});

test("activation accepts only a confirmed active version", async () => {
  let persisted;
  const service = serviceWith({
    activate: async (record) => {
      persisted = record;
      return configuration({
        configurationVersion: record.configurationVersion,
        state: "active",
        activatedAt: record.occurredAt,
        latestEventType: "activated",
        latestReasonCode: record.reasonCode,
      });
    },
  });
  const result = await service.activate({
    context: context(),
    request: { configurationVersion: 2, reasonCode: "ACTIVATE_MODEL" },
  });

  assert.equal(persisted.tenantId, ids.alpha);
  assert.equal(persisted.actorSubjectId, ids.admin);
  assert.equal(result.state, "active");
  assert.equal(result.configurationVersion, 2);
});

test("rollback requests a historical target but confirms a new active version", async () => {
  let persisted;
  const service = serviceWith({
    rollback: async (record) => {
      persisted = record;
      return configuration({
        configurationVersion: 4,
        modelVersion: "1.0.0",
        state: "active",
        initialScore: 60,
        smoothingAlpha: 0.30,
        maximumSourceInfluence: 0.25,
        staleAfterSeconds: 3600,
        createdBySubjectId: record.actorSubjectId,
        activatedAt: record.occurredAt,
        latestEventType: "rollback_activated",
        rollbackTargetConfigurationVersion: record.targetConfigurationVersion,
      });
    },
  });
  const result = await service.rollback({
    context: context(),
    request: { targetConfigurationVersion: 1, reasonCode: "RESTORE_BASELINE" },
  });

  assert.equal(persisted.targetConfigurationVersion, 1);
  assert.equal(result.configurationVersion, 4);
  assert.equal(result.state, "active");
  assert.equal(result.createdBySubjectId, ids.admin);
});

test("history is tenant-bound, descending, unique and deeply immutable", async () => {
  const history = await serviceWith().history({ context: context() });

  assert.deepEqual(history.map(({ configurationVersion }) => configurationVersion), [2, 1]);
  assert.ok(Object.isFrozen(history));
  assert.ok(history.every(Object.isFrozen));
  assert.ok(history.every(({ tenantId }) => tenantId === ids.alpha));
});

test("malformed persistence confirmations fail closed", async () => {
  for (const [method, overrides, request] of [
    ["createDraft", { createDraft: async () => configuration({ tenantId: ids.beta }) }, draftRequest],
    ["activate", { activate: async () => configuration({ state: "draft" }) }, {
      configurationVersion: 2, reasonCode: "ACTIVATE_MODEL",
    }],
    ["rollback", { rollback: async () => configuration({ configurationVersion: 1 }) }, {
      targetConfigurationVersion: 1, reasonCode: "RESTORE_BASELINE",
    }],
  ]) {
    await assert.rejects(
      () => serviceWith(overrides)[method]({ context: context(), request }),
      (error) => error instanceof TrustConfigurationManagementError,
    );
  }
});

function databaseRow(overrides = {}) {
  return {
    tenant_id: ids.alpha,
    configuration_version: 2,
    model_version: "1.1.0",
    state: "draft",
    initial_score: "62.00",
    smoothing_alpha: "0.3500",
    maximum_source_influence: "0.2000",
    stale_after_seconds: 2700,
    identity_weight: "0.2000",
    device_weight: "0.2500",
    behaviour_weight: "0.2500",
    certificate_weight: "0.1500",
    compliance_weight: "0.1500",
    created_by_subject_id: ids.admin,
    activated_at: null,
    superseded_at: null,
    created_at: new Date("2026-10-07T08:00:00.000Z"),
    updated_at: new Date("2026-10-07T08:00:00.000Z"),
    latest_event_type: "draft_created",
    latest_reason_code: "MODEL_TUNING",
    latest_actor_subject_id: ids.admin,
    previous_active_configuration_version: 1,
    rollback_target_configuration_version: null,
    latest_event_at: new Date("2026-10-07T08:00:00.000Z"),
    ...overrides,
  };
}

test("PostgreSQL repository uses parameterized lifecycle functions and maps numeric values", async () => {
  const calls = [];
  const repository = createPostgresTrustConfigurationRepository({
    query: async (text, values, options) => {
      calls.push({ text, values, options });
      if (text.includes("list_trust_configuration_history")) {
        return { rows: [databaseRow(), databaseRow({ configuration_version: 1 })] };
      }
      if (text.includes("activate_trust_configuration")) {
        return { rows: [databaseRow({ state: "active", activated_at: new Date("2026-10-07T08:00:00.000Z") })] };
      }
      if (text.includes("rollback_trust_configuration")) {
        return { rows: [databaseRow({ configuration_version: 3, state: "active", activated_at: new Date("2026-10-07T08:00:00.000Z") })] };
      }
      return { rows: [databaseRow()] };
    },
  });
  const record = {
    modelVersion: "1.1.0",
    initialScore: 62,
    smoothingAlpha: 0.35,
    maximumSourceInfluence: 0.20,
    staleAfterSeconds: 2700,
    weights,
    configurationVersion: 2,
    targetConfigurationVersion: 1,
    reasonCode: "MODEL_TUNING",
    occurredAt: "2026-10-07T08:00:00.000Z",
  };

  assert.equal((await repository.createDraft(record)).initialScore, 62);
  assert.equal((await repository.activate(record)).state, "active");
  assert.equal((await repository.rollback(record)).configurationVersion, 3);
  assert.equal((await repository.listHistory(record)).length, 2);
  assert.equal(calls.length, 4);
  assert.equal(calls[0].values.length, 12);
  assert.deepEqual(calls[1].values, [2, "MODEL_TUNING", "2026-10-07T08:00:00.000Z"]);
  assert.deepEqual(calls[2].values, [1, "MODEL_TUNING", "2026-10-07T08:00:00.000Z"]);
  assert.deepEqual(calls[3].values, []);
});

test("repository and safe-denial boundaries reject malformed infrastructure results", async () => {
  const repository = createPostgresTrustConfigurationRepository({
    query: async () => ({ rows: [] }),
  });
  await assert.rejects(
    () => repository.activate({
      configurationVersion: 2,
      reasonCode: "ACTIVATE_MODEL",
      occurredAt: "2026-10-07T08:00:00.000Z",
    }),
    (error) => error instanceof TrustConfigurationManagementError,
  );
  assert.equal(
    trustConfigurationManagementSafeDenial(new TrustConfigurationManagementError("TEST")),
    TRUST_CONFIGURATION_MANAGEMENT_DENIAL,
  );
  assert.throws(() => trustConfigurationManagementSafeDenial(new Error("boom")));
});
