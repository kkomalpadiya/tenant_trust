import assert from "node:assert/strict";
import test from "node:test";

import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  GovernedRecoveryError,
  createGovernedRecoveryService,
  createPostgresGovernedRecoveryRepository,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789a0",
  adminId: "sub_018f1234-5678-7abc-8def-0123456789a1",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789a2",
  certificateId: "crt_018f1234-5678-7abc-8def-0123456789a3",
  transitionId: "trn_018f1234-5678-7abc-8def-0123456789a4",
});

function context(roles = ["tenant-admin"]) {
  return resolveTenantContext({
    authentication: {
      source: "mtls-certificate",
      authenticationId: "recovery-admin-certificate",
      tenantId: ids.tenantId,
      subjectId: ids.adminId,
    },
    authority: {
      tenant: { tenantId: ids.tenantId, state: "active", version: 1 },
      subject: { subjectId: ids.adminId, state: "active", version: 1 },
      membership: {
        tenantId: ids.tenantId,
        subjectId: ids.adminId,
        state: "active",
        version: 1,
      },
      roles,
    },
  });
}

function request(overrides = {}) {
  return {
    requestId: "req_018f1234-5678-7abc-8def-0123456789b0",
    idempotencyKey: "recovery:request:one",
    targetSubjectId: ids.subjectId,
    targetCertificateId: ids.certificateId,
    stepUpProofIdHashSha256: "a".repeat(64),
    sessionIdHashSha256: "b".repeat(64),
    causeResolutionReference: "case:resolved:123",
    ...overrides,
  };
}

function recoveryContext(overrides = {}) {
  return {
    tenantId: ids.tenantId,
    targetSubjectId: ids.subjectId,
    targetCertificateId: ids.certificateId,
    stateVersion: 7,
    trustTransitionId: ids.transitionId,
    currentState: {
      access: "suspended",
      renewal: "blocked",
      targetCertificate: "revoked",
      replacement: "required",
    },
    checkpoint: {
      score: 75,
      band: "high",
      transition: "recovered",
      consecutiveQualifyingEvaluations: 2,
      sourceIds: [
        "src_018f1234-5678-7abc-8def-0123456789c0",
        "src_018f1234-5678-7abc-8def-0123456789c1",
      ],
    },
    activeSevereEvidence: [],
    ...overrides,
  };
}

test("tenant-admin step-up authorization queues the eligible replacement action", async () => {
  let persisted;
  const generated = [
    "018f1234-5678-7abc-8def-0123456789d0",
    "018f1234-5678-7abc-8def-0123456789d1",
    "018f1234-5678-7abc-8def-0123456789d2",
    "018f1234-5678-7abc-8def-0123456789d3",
  ];
  const service = createGovernedRecoveryService({
    idFactory: () => generated.shift(),
    clock: () => new Date("2026-10-22T10:00:00.000Z"),
    repository: {
      loadRecoveryContext: async () => recoveryContext(),
      authorizeRecoveryAction: async (value) => {
        persisted = value;
        return {
          tenantId: ids.tenantId,
          authorizationId: value.authorizationId,
          actionId: value.actionId,
          actionType: value.actionType,
          status: "pending",
          authorizedAt: value.authorizedAt,
          expiresAt: "2026-10-22T10:05:00.000Z",
        };
      },
    },
  });

  const result = await service.authorize({ context: context(), request: request() });
  assert.equal(result.actionType, "issue-replacement-certificate");
  assert.equal(result.targetCertificateReactivated, false);
  assert.equal(persisted.expectedStateVersion, 7);
  assert.equal(persisted.trustTransitionId, ids.transitionId);
  assert.match(persisted.eligibilityHashSha256, /^[0-9a-f]{64}$/u);
});

test("authorization rejects non-admin actors and incomplete recovery evidence", async () => {
  const repository = {
    loadRecoveryContext: async () => recoveryContext({
      checkpoint: {
        ...recoveryContext().checkpoint,
        consecutiveQualifyingEvaluations: 1,
      },
    }),
    authorizeRecoveryAction: async () => assert.fail("ineligible recovery must not persist"),
  };
  await assert.rejects(
    createGovernedRecoveryService({ repository }).authorize({
      context: context(["tenant-member"]),
      request: request(),
    }),
    (error) => error instanceof GovernedRecoveryError
      && error.reasonCode === "RECOVERY_TENANT_ADMIN_REQUIRED",
  );
  await assert.rejects(
    createGovernedRecoveryService({ repository }).authorize({
      context: context(),
      request: request(),
    }),
    (error) => error instanceof GovernedRecoveryError
      && error.reasonCode === "TRUST_RECOVERY_INCOMPLETE",
  );
});

test("PostgreSQL adapter combines durable state with active severe evidence", async () => {
  const calls = [];
  const repository = createPostgresGovernedRecoveryRepository({
    loadActiveSevereEvidence: async (criteria) => {
      assert.equal(criteria.subjectId, ids.subjectId);
      return [];
    },
    query: async (sql, values) => {
      calls.push({ sql, values });
      if (sql.includes("get_security_recovery_context")) {
        return { rows: [{
          tenant_id: ids.tenantId,
          target_subject_id: ids.subjectId,
          target_certificate_id: ids.certificateId,
          state_version: "7",
          access_state: "suspended",
          renewal_state: "blocked",
          target_certificate_state: "revoked",
          replacement_state: "required",
          trust_transition_id: ids.transitionId,
          score: "75.00",
          band: "high",
          transition: "recovered",
          consecutive_qualifying_evaluations: 2,
          source_ids: recoveryContext().checkpoint.sourceIds,
        }] };
      }
      return { rows: [{
        tenant_id: ids.tenantId,
        authorization_id: "rca_018f1234-5678-7abc-8def-0123456789d0",
        action_id: "act_018f1234-5678-7abc-8def-0123456789d1",
        action_type: "issue-replacement-certificate",
        status: "pending",
        authorized_at: "2026-10-22T10:00:00.000Z",
        expires_at: "2026-10-22T10:05:00.000Z",
      }] };
    },
  });
  const loaded = await repository.loadRecoveryContext({
    tenantId: ids.tenantId,
    targetSubjectId: ids.subjectId,
    targetCertificateId: ids.certificateId,
    evaluatedAt: "2026-10-22T10:00:00.000Z",
  });
  assert.equal(loaded.checkpoint.score, 75);
  assert.deepEqual(loaded.activeSevereEvidence, []);
  assert.match(calls[0].sql, /get_security_recovery_context/u);
});
