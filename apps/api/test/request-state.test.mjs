import assert from "node:assert/strict";
import test from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  CertificateNotAcceptedError,
  REQUEST_STATE_POLICY,
  RequestStateUnavailableError,
  createRequestStateRevalidator,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789b4",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789d0",
});
const fingerprint = "ab".repeat(32);
const authentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: `sha256:${fingerprint}`,
  tenantId: ids.tenant,
  subjectId: ids.subject,
  certificate: Object.freeze({
    profileId: "tenant-client-auth-v1",
    issuerId: ids.issuer,
    serialNumber: "01".padEnd(32, "0"),
    fingerprintSha256: fingerprint,
    publicKeySha256: "cd".repeat(32),
    notBefore: "2026-09-15T09:00:00.000Z",
    notAfter: "2026-09-15T11:00:00.000Z",
  }),
});
const context = resolveTenantContext({
  authentication,
  authority: {
    tenant: { tenantId: ids.tenant, state: "active", version: 1 },
    subject: { subjectId: ids.subject, state: "active", version: 1 },
    membership: { tenantId: ids.tenant, subjectId: ids.subject, state: "active", version: 1 },
    roles: ["tenant-member"],
  },
});

function statusRow(overrides = {}) {
  return {
    tenant_id: ids.tenant,
    certificate_id: ids.certificate,
    subject_id: ids.subject,
    issuer_id: ids.issuer,
    serial_number: authentication.certificate.serialNumber,
    fingerprint_sha256: fingerprint,
    state: "active",
    not_before: authentication.certificate.notBefore,
    not_after: authentication.certificate.notAfter,
    version: 2,
    status_observed_at: "2026-09-15T10:00:00.000Z",
    ...overrides,
  };
}

function clientFor(row = statusRow(), discoveryRows = [{ certificate_id: ids.certificate }]) {
  const calls = [];
  return {
    calls,
    async query(input, values) {
      calls.push({ input, values });
      if (typeof input === "string") return { rowCount: discoveryRows.length, rows: discoveryRows };
      return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
    },
  };
}

test("request state policy fixes a five-second no-cache revalidation boundary", () => {
  assert.deepEqual(REQUEST_STATE_POLICY, {
    schemaVersion: "1.0.0",
    mechanism: "authoritative-per-request-state-v1",
    maximumStateAgeSeconds: 5,
    futureClockSkewSeconds: 2,
    crossRequestAllowCache: false,
    revalidation: "every-protected-request",
  });
});

test("an exact active certificate creates a branded state bound to authority versions", async () => {
  const client = clientFor();
  const revalidator = createRequestStateRevalidator({
    clock: () => new Date("2026-09-15T10:00:01.000Z"),
  });
  const state = await revalidator.validate({ client, authentication, context });

  assert.equal(state.certificateId, ids.certificate);
  assert.equal(state.certificateStatusVersion, 2);
  assert.deepEqual(state.authorityVersions, { tenant: 1, subject: 1, membership: 1 });
  assert.equal(state.validUntil, "2026-09-15T10:00:05.000Z");
  assert.equal(client.calls.length, 2);
  assert.deepEqual(client.calls[0].values.slice(0, 2), [ids.tenant, ids.subject]);
  assert.deepEqual(client.calls[1].input.values.slice(0, 2), [ids.tenant, ids.certificate]);
});

test("unknown and revoked certificates are non-cacheable authentication denials", async () => {
  const revalidator = createRequestStateRevalidator({
    clock: () => new Date("2026-09-15T10:00:01.000Z"),
  });
  await assert.rejects(
    revalidator.validate({ client: clientFor(null, []), authentication, context }),
    CertificateNotAcceptedError,
  );
  await assert.rejects(
    revalidator.validate({ client: clientFor(statusRow({ state: "revoked" })), authentication, context }),
    CertificateNotAcceptedError,
  );
});

test("stale authoritative state and an elapsed request boundary fail unavailable", async () => {
  const stale = createRequestStateRevalidator({
    clock: () => new Date("2026-09-15T10:00:06.000Z"),
  });
  await assert.rejects(
    stale.validate({ client: clientFor(), authentication, context }),
    RequestStateUnavailableError,
  );

  let now = new Date("2026-09-15T10:00:01.000Z");
  const revalidator = createRequestStateRevalidator({ clock: () => now });
  const state = await revalidator.validate({ client: clientFor(), authentication, context });
  now = new Date("2026-09-15T10:00:05.000Z");
  assert.throws(() => revalidator.assertFresh(state), RequestStateUnavailableError);
});

test("certificate metadata and authentication ID must be gateway-bound before database access", async () => {
  const client = clientFor();
  const revalidator = createRequestStateRevalidator();
  await assert.rejects(
    revalidator.validate({
      client,
      context,
      authentication: { ...authentication, authenticationId: "sha256:forged" },
    }),
    CertificateNotAcceptedError,
  );
  assert.equal(client.calls.length, 0);
});
