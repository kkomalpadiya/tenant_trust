import assert from "node:assert/strict";
import test from "node:test";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import {
  EVIDENCE_INGESTION_POLICY,
  createEvidenceIngestionService,
  createInMemoryEvidenceReplayGuard,
} from "@tenant-trust/evidence";
import { generateDeterministicDemoEvidenceSet } from "@tenant-trust/evidence-simulators";
import {
  REQUEST_SAFEGUARD_POLICY,
  REQUEST_STATE_POLICY,
  createRequestAuditRecorder,
  createTenantTrustApi,
} from "../src/index.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
const fixture = generateDeterministicDemoEvidenceSet();

function replayGuard() {
  return createInMemoryEvidenceReplayGuard({
    clock: () => new Date("2026-10-05T08:00:30.000Z"),
  });
}

function repository() {
  return {
    authorizationMode,
    requestSafeguardPolicy: REQUEST_SAFEGUARD_POLICY,
    requestStatePolicy: REQUEST_STATE_POLICY,
    async getProfile() { return {}; },
    async listRecords() { return []; },
    async getRecord() { return {}; },
    async exportRecords() { return {}; },
    async reviewMembership() { return {}; },
  };
}

function verificationContext() {
  const envelope = fixture.envelopes[0];
  const enrollment = fixture.enrollments[0];
  return {
    tenantId: envelope.tenantId,
    subjectId: envelope.subjectId,
    sourceId: envelope.sourceId,
    evidenceType: envelope.evidenceType,
    sourceSynthetic: true,
    maximumAgeSeconds: 300,
    sourceState: "active",
    verificationAlgorithm: "Ed25519",
    keyId: enrollment.keyId,
    keyState: "active",
    keyVersion: 1,
    publicKeyBase64Url: enrollment.publicKeyBase64Url,
    publicKeySha256: enrollment.publicKeySha256,
    keyEnrolledAt: "2026-01-01T00:00:00.000Z",
  };
}

function createApi(evidenceIngestionService) {
  return createTenantTrustApi({
    identityResolver: { async resolve() { throw new Error("human identity resolver must not run"); } },
    repository: repository(),
    requestAuditRecorder: createRequestAuditRecorder({ async write() {} }),
    evidenceIngestionService,
  });
}

test("evidence endpoint accepts a verified source envelope without transport identity headers", async (t) => {
  const service = createEvidenceIngestionService({
    applyReplayGuard: replayGuard(),
    async resolveVerificationContext() { return verificationContext(); },
  });
  const api = createApi(service);
  t.after(() => api.close());
  const response = await api.inject({
    method: "POST",
    url: "/v1/evidence",
    payload: fixture.envelopes[0],
  });
  assert.equal(response.statusCode, 202);
  assert.equal(response.json().evidence.status, "accepted");
  assert.equal(response.json().evidence.eventId, fixture.envelopes[0].eventId);
  assert.match(response.headers["x-request-id"], /^req_/u);
  assert.match(response.headers["x-correlation-id"], /^cor_/u);
  assert.equal(response.headers["cache-control"], "no-store");
});

test("schema failures, verification denials and query controls have bounded responses", async (t) => {
  const service = createEvidenceIngestionService({
    applyReplayGuard: replayGuard(),
    async resolveVerificationContext() { return verificationContext(); },
  });
  const api = createApi(service);
  t.after(() => api.close());

  const invalid = await api.inject({
    method: "POST",
    url: "/v1/evidence",
    payload: { ...fixture.envelopes[0], tenantId: "forged" },
  });
  assert.equal(invalid.statusCode, 400);
  assert.deepEqual(invalid.json(), { error: { code: "INVALID_REQUEST" } });

  const tampered = structuredClone(fixture.envelopes[0]);
  tampered.payload.identityState = "disabled";
  const rejected = await api.inject({ method: "POST", url: "/v1/evidence", payload: tampered });
  assert.equal(rejected.statusCode, 422);
  assert.deepEqual(rejected.json(), { error: { code: "EVIDENCE_REJECTED" } });

  const missingContextApi = createApi(createEvidenceIngestionService({
    applyReplayGuard: replayGuard(),
    async resolveVerificationContext() { return null; },
  }));
  t.after(() => missingContextApi.close());
  const missing = await missingContextApi.inject({
    method: "POST",
    url: "/v1/evidence",
    payload: fixture.envelopes[0],
  });
  assert.equal(missing.statusCode, 422);
  assert.deepEqual(missing.json(), rejected.json());

  const query = await api.inject({
    method: "POST",
    url: "/v1/evidence?tenantId=tnt_018f1234-5678-7abc-8def-0123456789ac",
    payload: fixture.envelopes[0],
  });
  assert.equal(query.statusCode, 400);
  assert.deepEqual(query.json(), { error: { code: "INVALID_REQUEST" } });
});

test("raw envelopes over the fixed route limit are rejected before ingestion", async (t) => {
  let touched = false;
  const api = createApi(createEvidenceIngestionService({
    applyReplayGuard: replayGuard(),
    async resolveVerificationContext() {
      touched = true;
      return verificationContext();
    },
  }));
  t.after(() => api.close());
  const response = await api.inject({
    method: "POST",
    url: "/v1/evidence",
    payload: { filler: "x".repeat(EVIDENCE_INGESTION_POLICY.maximumEnvelopeBytes + 1) },
  });
  assert.equal(response.statusCode, 413);
  assert.deepEqual(response.json(), { error: { code: "REQUEST_TOO_LARGE" } });
  assert.equal(touched, false);
});

test("replayed evidence receives the same bounded rejection as other verification denials", async (t) => {
  const service = createEvidenceIngestionService({
    applyReplayGuard: replayGuard(),
    async resolveVerificationContext() { return verificationContext(); },
  });
  const api = createApi(service);
  t.after(() => api.close());

  const accepted = await api.inject({
    method: "POST",
    url: "/v1/evidence",
    payload: fixture.envelopes[0],
  });
  const replayed = await api.inject({
    method: "POST",
    url: "/v1/evidence",
    payload: fixture.envelopes[0],
  });
  assert.equal(accepted.statusCode, 202);
  assert.equal(replayed.statusCode, 422);
  assert.deepEqual(replayed.json(), { error: { code: "EVIDENCE_REJECTED" } });
});

test("the API rejects an unbranded evidence service", () => {
  assert.throws(
    () => createTenantTrustApi({
      identityResolver: { async resolve() {} },
      repository: repository(),
      requestAuditRecorder: createRequestAuditRecorder({ async write() {} }),
      evidenceIngestionService: {
        policy: EVIDENCE_INGESTION_POLICY,
        async ingest() {},
      },
    }),
    /branded evidence ingestion service/u,
  );
});
