import assert from "node:assert/strict";
import test from "node:test";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import {
  AccessDeniedError,
  CertificateNotAcceptedError,
  createOpaPolicyDecisionClient,
  createPolicyEnforcementService,
  createPostgresTenantRepository,
  hashPolicyInput,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  targetSubject: "sub_018f1234-5678-7abc-8def-0123456789ac",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ab",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789ab",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
  policy: "pol_018f1234-5678-7abc-8def-0123456789ab",
  decision: "dec_018f1234-5678-7abc-8def-0123456789ab",
  securityAction: "act_018f1234-5678-7abc-8def-0123456789ab",
  record: "res_018f1234-5678-7abc-8def-0123456789b0",
  foreignRecord: "res_018f1234-5678-7abc-8def-0123456789b1",
  operation: "op_018f1234-5678-7abc-8def-0123456789ab",
});
const hash = "ab".repeat(32);
const authentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: `sha256:${hash}`,
  tenantId: ids.tenant,
  subjectId: ids.subject,
  certificate: Object.freeze({
    profileId: "tenant-client-auth-v1",
    issuerId: ids.issuer,
    serialNumber: "01AF".padEnd(32, "0"),
    fingerprintSha256: hash,
    publicKeySha256: "cd".repeat(32),
    notBefore: "2026-10-13T08:00:00.000Z",
    notAfter: "2026-10-13T11:00:00.000Z",
  }),
});
const mode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA);

function trustState() {
  return {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    state: "fresh",
    usableForPolicy: true,
    requiredOutcome: null,
    reasonCode: null,
    policyScore: 100,
    policyBand: "high",
    lastKnownScore: 100,
    lastKnownBand: "high",
    ageSeconds: 1,
    staleAfterSeconds: 300,
    transitionId: ids.transition,
    updateVersion: 12,
    modelVersion: "1.0.0",
    configurationVersion: 3,
    observedAt: "2026-10-13T08:59:30.000Z",
    evaluatedAt: "2026-10-13T08:59:31.000Z",
    recordedAt: "2026-10-13T08:59:31.100Z",
    explanationHashSha256: hash,
  };
}

function policyRequest(index, method = "GET", routeTemplate = "/v1/profile") {
  const suffix = index.toString(16).padStart(12, "0");
  return {
    requestId: `req_018f1234-5678-7abc-8def-${suffix}`,
    correlationId: `cor_018f1234-5678-7abc-8def-${suffix}`,
    requestedAt: "2026-10-13T09:00:00.000Z",
    method,
    routeTemplate,
    sourceNetworkZone: "unknown",
    resourceIdHashSha256: hash,
    ownerSubjectId: null,
  };
}

function outputFor(input, outcome = "ALLOW") {
  const quarantine = outcome === "QUARANTINE"
    ? { required: true, actionType: "restrict-access" }
    : null;
  return {
    schemaVersion: "1.0.0",
    contractId: "opa-decision-output-v1",
    decisionId: ids.decision,
    requestId: input.requestContext.requestId,
    correlationId: input.requestContext.correlationId,
    tenantId: input.tenantContext.tenantId,
    subjectId: input.tenantContext.subjectId,
    outcome,
    reasonCodes: [outcome === "ALLOW"
      ? "ACCESS_ALLOWED"
      : outcome === "QUARANTINE" ? "TRUST_SCORE_QUARANTINE" : "ACCESS_DENIED"],
    evaluatedAt: "2026-10-13T09:00:00.050Z",
    input: { contractId: input.contractId, hashSha256: hashPolicyInput(input) },
    policy: {
      policyVersionId: ids.policy,
      bundleVersion: 1,
      bundleHashSha256: hash,
      decisionPath: "tenant_trust/authorization/decision",
    },
    state: {
      certificateStatusVersion: input.identity.statusVersion,
      tenantVersion: input.tenantContext.versions.tenant,
      subjectVersion: input.tenantContext.versions.subject,
      membershipVersion: input.tenantContext.versions.membership,
      trustTransitionId: input.trust.transitionId,
      trustUpdateVersion: input.trust.updateVersion,
      trustConfigurationVersion: input.trust.configurationVersion,
    },
    obligations: { stepUp: null, quarantine },
  };
}

function createPolicyService(decisions, outcome = "ALLOW") {
  const decisionClient = createOpaPolicyDecisionClient({
    baseUrl: "http://opa.internal:8181",
    fetchImpl: async (_url, options) => {
      const { input } = JSON.parse(options.body);
      decisions.push(input);
      return { ok: true, json: async () => ({ result: outputFor(input, outcome) }) };
    },
  });
  return createPolicyEnforcementService({
    trustScoreLookupService: { lookup: async () => trustState() },
    policyBundleLookupService: { lookupActive: async () => ({
      tenantId: ids.tenant,
      policyVersionId: ids.policy,
      policyName: "access-control",
      bundleVersion: 1,
      bundleHashSha256: hash,
      entrypoint: "tenant_trust/authorization/decision",
      state: "active",
    }) },
    decisionClient,
  });
}

function createPool({
  certificateState = "active",
  stepUpProofAvailable = true,
  quarantineWriteAvailable = true,
} = {}) {
  const calls = [];
  const recordRow = (recordId) => ({
    resource_id: recordId,
    owner_subject_id: ids.subject,
    resource_name: "Tenant record",
    version: 1,
    created_at: "2026-10-13T08:00:00.000Z",
    updated_at: "2026-10-13T08:30:00.000Z",
  });
  const client = {
    async query(input, parameters) {
      const text = typeof input === "string" ? input : input.text;
      const values = typeof input === "string" ? parameters : input.values;
      calls.push({ text, parameters: values });
      if (text.includes("tenant.tenant_id::text,") && text.includes("array_agg")) {
        return { rowCount: 1, rows: [{
          tenant_id: ids.tenant,
          tenant_state: "active",
          tenant_version: 4,
          subject_id: ids.subject,
          subject_state: "active",
          subject_version: 5,
          membership_state: "active",
          membership_version: 6,
          roles: ["tenant-admin"],
        }] };
      }
      if (text.includes("transaction_timestamp() AS status_observed_at")) {
        return { rowCount: 1, rows: [{
          tenant_id: ids.tenant,
          certificate_id: ids.certificate,
          subject_id: ids.subject,
          issuer_id: ids.issuer,
          serial_number: authentication.certificate.serialNumber,
          fingerprint_sha256: hash,
          state: certificateState,
          not_before: authentication.certificate.notBefore,
          not_after: authentication.certificate.notAfter,
          version: certificateState === "active" ? 7 : 8,
          status_observed_at: "2026-10-13T09:00:00.000Z",
        }] };
      }
      if (text.includes("FROM identity.certificates")) {
        return { rowCount: 1, rows: [{ certificate_id: ids.certificate }] };
      }
      if (text.includes("reserve_api_sensitive_operation")) {
        return { rowCount: 1, rows: [{ operation_id: ids.operation, replayed: false }] };
      }
      if (text.includes("consume_step_up_proof")) {
        if (!stepUpProofAvailable) return { rowCount: 0, rows: [] };
        stepUpProofAvailable = false;
        return { rowCount: 1, rows: [{
          proof_id_hash_sha256: values[0],
          tenant_id: ids.tenant,
          subject_id: ids.subject,
          action: values[2],
          session_id_hash_sha256: values[1],
          verified_at: "2026-10-13T08:59:30.000Z",
          expires_at: "2026-10-13T09:04:30.000Z",
        }] };
      }
      if (text.includes("request_quarantine_action")) {
        if (!quarantineWriteAvailable) throw new Error("quarantine action storage unavailable");
        return { rowCount: 1, rows: [{
          action_id: values[0],
          decision_id: values[1],
          correlation_id: values[3],
          action_type: values[6],
          reason_code: values[7],
        }] };
      }
      if (text.includes("tenant.display_name AS tenant_display_name")) {
        return { rowCount: 1, rows: [{
          tenant_display_name: "Tenant Alpha",
          display_name: "Administrator",
          subject_kind: "human",
          member_since: "2026-01-01T00:00:00.000Z",
        }] };
      }
      if (text.includes("FROM app.resources")) {
        const requested = Array.isArray(values[1]) ? values[1] : values[1] ? [values[1]] : [ids.record];
        if (requested.includes(ids.foreignRecord)) return { rowCount: 0, rows: [] };
        const rows = requested.map(recordRow);
        return { rowCount: rows.length, rows };
      }
      if (text.includes("subject.display_name") && text.includes("array_agg")) {
        return { rowCount: 1, rows: [{
          subject_id: ids.targetSubject,
          display_name: "Reviewed user",
          subject_state: "active",
          subject_version: 2,
          membership_state: "active",
          membership_version: 3,
          roles: ["tenant-member"],
        }] };
      }
      return { rowCount: null, rows: [] };
    },
    release() {},
  };
  return { calls, async connect() { return client; } };
}

function repositoryWith(pool, decisions, outcome = "ALLOW") {
  return createPostgresTenantRepository({
    pool,
    authorizationMode: mode,
    policyEnforcementService: createPolicyService(decisions, outcome),
    operationIdFactory: () => ids.operation,
    securityActionIdFactory: () => ids.securityAction,
    clock: () => new Date("2026-10-13T09:00:01.000Z"),
  });
}

test("every protected repository operation requires an OPA ALLOW decision", async () => {
  const decisions = [];
  const repository = repositoryWith(createPool(), decisions);

  await repository.getProfile(authentication, { policyRequest: policyRequest(1) });
  await repository.listRecords(authentication, { policyRequest: policyRequest(2, "GET", "/v1/tenant-records") });
  await repository.getRecord(authentication, ids.record, {
    policyRequest: policyRequest(3, "GET", "/v1/tenant-records/{recordid}"),
  });
  await repository.exportRecords(authentication, [ids.record], {
    idempotencyKey: "idem_018f1234-5678-7abc-8def-0123456789a1",
    policyRequest: policyRequest(4, "POST", "/v1/tenant-records/export"),
  });
  await repository.reviewMembership(authentication, ids.targetSubject, {
    idempotencyKey: "idem_018f1234-5678-7abc-8def-0123456789a2",
    policyRequest: policyRequest(5, "POST", "/v1/admin/membership-reviews"),
  });

  assert.deepEqual(decisions.map(({ action }) => action), [
    "profile:read",
    "record:read",
    "record:read",
    "record:export",
    "tenant:admin",
  ]);
});

test("a revoked certificate cannot reach OPA even with a maximum trust score", async () => {
  const decisions = [];
  const repository = repositoryWith(createPool({ certificateState: "revoked" }), decisions);

  await assert.rejects(
    repository.getProfile(authentication, { policyRequest: policyRequest(6) }),
    CertificateNotAcceptedError,
  );
  assert.equal(decisions.length, 0);
});

test("an OPA ALLOW cannot expose a cross-tenant record hidden by tenant scope", async () => {
  const decisions = [];
  const repository = repositoryWith(createPool(), decisions);

  await assert.rejects(
    repository.getRecord(authentication, ids.foreignRecord, {
      policyRequest: policyRequest(7, "GET", "/v1/tenant-records/{recordid}"),
    }),
    AccessDeniedError,
  );
  assert.equal(decisions.length, 1);
  assert.equal(decisions[0].trust.policyScore, 100);
});

test("DENY remains non-allow and blocks protected data queries", async () => {
  const decisions = [];
  const pool = createPool();
  const repository = repositoryWith(pool, decisions, "DENY");

  await assert.rejects(
    repository.listRecords(authentication, {
      policyRequest: policyRequest(8, "GET", "/v1/tenant-records"),
    }),
    AccessDeniedError,
  );
  assert.equal(pool.calls.some(({ text }) => text.includes("FROM app.resources")), false);
  assert.equal(pool.calls.some(({ text }) => text.includes("request_quarantine_action")), false);
  assert.equal(pool.calls.some(({ text }) => text === "COMMIT"), false);
  assert.equal(pool.calls.some(({ text }) => text === "ROLLBACK"), true);
});

test("QUARANTINE blocks protected data and commits a correlated action request", async () => {
  const decisions = [];
  const pool = createPool();
  const request = policyRequest(11, "GET", "/v1/tenant-records");
  const repository = repositoryWith(pool, decisions, "QUARANTINE");

  await assert.rejects(
    repository.listRecords(authentication, { policyRequest: request }),
    AccessDeniedError,
  );

  assert.equal(pool.calls.some(({ text }) => text.includes("FROM app.resources")), false);
  const actionRequest = pool.calls.find(({ text }) => text.includes("request_quarantine_action"));
  assert.ok(actionRequest);
  assert.deepEqual(actionRequest.parameters, [
    ids.securityAction,
    ids.decision,
    request.requestId,
    request.correlationId,
    ids.certificate,
    "record:read",
    "restrict-access",
    "TRUST_SCORE_QUARANTINE",
    hash,
    ids.transition,
    ids.policy,
    hashPolicyInput(decisions[0]),
    "2026-10-13T09:00:01.000Z",
  ]);
  assert.equal(pool.calls.some(({ text }) => text === "COMMIT"), true);
  assert.equal(pool.calls.some(({ text }) => text === "ROLLBACK"), false);
});

test("QUARANTINE fails closed and rolls back when its action request cannot persist", async () => {
  const decisions = [];
  const pool = createPool({ quarantineWriteAvailable: false });
  const repository = repositoryWith(pool, decisions, "QUARANTINE");

  await assert.rejects(
    repository.listRecords(authentication, {
      policyRequest: policyRequest(12, "GET", "/v1/tenant-records"),
    }),
    /quarantine action storage unavailable/u,
  );

  assert.equal(pool.calls.some(({ text }) => text.includes("FROM app.resources")), false);
  assert.equal(pool.calls.some(({ text }) => text === "COMMIT"), false);
  assert.equal(pool.calls.some(({ text }) => text === "ROLLBACK"), true);
});

test("QUARANTINE is enforced before a sensitive-operation receipt is reserved", async () => {
  const decisions = [];
  const pool = createPool();
  const repository = repositoryWith(pool, decisions, "QUARANTINE");

  await assert.rejects(
    repository.exportRecords(authentication, [ids.record], {
      idempotencyKey: "idem_018f1234-5678-7abc-8def-0123456789a5",
      policyRequest: policyRequest(13, "POST", "/v1/tenant-records/export"),
    }),
    AccessDeniedError,
  );

  assert.equal(pool.calls.some(({ text }) => text.includes("request_quarantine_action")), true);
  assert.equal(pool.calls.some(({ text }) => text.includes("reserve_api_sensitive_operation")), false);
  assert.equal(pool.calls.some(({ text }) => text.includes("FROM app.resources")), false);
});

test("a sensitive operation consumes its tenant, subject, action and session-bound proof once", async () => {
  const decisions = [];
  const pool = createPool();
  const repository = repositoryWith(pool, decisions);
  const presentation = {
    proofId: "sup_018f1234-5678-7abc-8def-0123456789a1",
    sessionId: "sus_018f1234-5678-7abc-8def-0123456789a2",
  };

  await repository.exportRecords(authentication, [ids.record], {
    idempotencyKey: "idem_018f1234-5678-7abc-8def-0123456789a3",
    policyRequest: { ...policyRequest(9, "POST", "/v1/tenant-records/export"), stepUpPresentation: presentation },
  });
  await assert.rejects(
    repository.exportRecords(authentication, [ids.record], {
      idempotencyKey: "idem_018f1234-5678-7abc-8def-0123456789a4",
      policyRequest: { ...policyRequest(10, "POST", "/v1/tenant-records/export"), stepUpPresentation: presentation },
    }),
    AccessDeniedError,
  );

  assert.equal(decisions.length, 1);
  assert.equal(decisions[0].requestContext.stepUp.status, "valid");
  assert.equal(decisions[0].requestContext.stepUp.tenantId, ids.tenant);
  assert.equal(decisions[0].requestContext.stepUp.subjectId, ids.subject);
  assert.equal(decisions[0].requestContext.stepUp.action, "record:export");
  assert.match(decisions[0].requestContext.stepUp.sessionIdHashSha256, /^[0-9a-f]{64}$/u);
});
