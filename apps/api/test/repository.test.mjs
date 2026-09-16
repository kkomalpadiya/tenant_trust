import assert from "node:assert/strict";
import test from "node:test";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import {
  AccessDeniedError,
  CertificateNotAcceptedError,
  createPostgresTenantRepository,
} from "../src/index.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);

const fingerprint = "aa".repeat(32);
const authentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: `sha256:${fingerprint}`,
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificate: Object.freeze({
    profileId: "tenant-client-auth-v1",
    issuerId: "iss_018f1234-5678-7abc-8def-0123456789b4",
    serialNumber: "01".padEnd(32, "0"),
    fingerprintSha256: fingerprint,
    publicKeySha256: "bb".repeat(32),
    notBefore: "2026-09-15T09:00:00.000Z",
    notAfter: "2026-09-15T11:00:00.000Z",
  }),
});
const certificateId = "crt_018f1234-5678-7abc-8def-0123456789d0";
const fixedClock = () => new Date("2026-09-15T10:00:01.000Z");

const authorityRow = {
  tenant_id: authentication.tenantId,
  tenant_state: "active",
  tenant_version: "2",
  subject_id: authentication.subjectId,
  subject_state: "active",
  subject_version: "3",
  membership_state: "active",
  membership_version: "4",
  roles: ["tenant-member"],
};

function createPool(queryResult) {
  const calls = [];
  let released = false;
  const client = {
    async query(input, parameters) {
      const text = typeof input === "string" ? input : input.text;
      const values = typeof input === "string" ? parameters : input.values;
      parameters = values;
      calls.push({ text, parameters });
      if (text.includes("array_agg")) return { rowCount: 1, rows: [authorityRow] };
      if (text.includes("transaction_timestamp() AS status_observed_at")) {
        return { rowCount: 1, rows: [{
          tenant_id: authentication.tenantId,
          certificate_id: certificateId,
          subject_id: authentication.subjectId,
          issuer_id: authentication.certificate.issuerId,
          serial_number: authentication.certificate.serialNumber,
          fingerprint_sha256: authentication.certificate.fingerprintSha256,
          state: "active",
          not_before: authentication.certificate.notBefore,
          not_after: authentication.certificate.notAfter,
          version: 1,
          status_observed_at: "2026-09-15T10:00:00.000Z",
        }] };
      }
      if (text.includes("FROM identity.certificates")) {
        return { rowCount: 1, rows: [{ certificate_id: certificateId }] };
      }
      if (text.includes("FROM app.resources")) return queryResult(text, parameters);
      return { rowCount: null, rows: [] };
    },
    release() {
      released = true;
    },
  };
  return {
    calls,
    get released() {
      return released;
    },
    async connect() {
      return client;
    },
  };
}

test("record queries bind the authenticated actor and preserve explicit tenant scope", async () => {
  const pool = createPool((_text, parameters) => ({
    rowCount: 1,
    rows: [{
      resource_id: parameters[1],
      owner_subject_id: authentication.subjectId,
      resource_name: "Alpha member record",
      version: "1",
      created_at: new Date("2026-01-01T00:00:00.000Z"),
      updated_at: new Date("2026-01-02T00:00:00.000Z"),
    }],
  }));
  const repository = createPostgresTenantRepository({ pool, authorizationMode, clock: fixedClock });

  const record = await repository.getRecord(
    authentication,
    "res_018f1234-5678-7abc-8def-0123456789b0",
  );

  assert.equal(record.name, "Alpha member record");
  assert.equal(record.version, 1);
  assert.equal(pool.calls[0].text, "BEGIN");
  assert.equal(pool.calls[1].text, "SET LOCAL ROLE tenant_trust_app");
  assert.deepEqual(pool.calls[2].parameters, [authentication.tenantId, authentication.subjectId]);
  const recordQuery = pool.calls.find(({ text }) => text.includes("FROM app.resources"));
  assert.deepEqual(recordQuery.parameters, [
    authentication.tenantId,
    "res_018f1234-5678-7abc-8def-0123456789b0",
  ]);
  assert.match(recordQuery.text, /WHERE tenant_id = \$1/u);
  assert.ok(pool.calls.findIndex(({ text }) => text.includes("transaction_timestamp() AS status_observed_at"))
    < pool.calls.findIndex(({ text }) => text.includes("FROM app.resources")));
  assert.equal(pool.calls.at(-1).text, "COMMIT");
  assert.equal(pool.released, true);
});

test("an invisible record rolls back and returns one access-denied type", async () => {
  const pool = createPool(() => ({ rowCount: 0, rows: [] }));
  const repository = createPostgresTenantRepository({ pool, authorizationMode, clock: fixedClock });

  await assert.rejects(
    repository.getRecord(authentication, "res_018f1234-5678-7abc-8def-0123456789b2"),
    AccessDeniedError,
  );
  assert.equal(pool.calls.at(-1).text, "ROLLBACK");
  assert.equal(pool.released, true);
});

test("database privilege denial is normalized and never commits", async () => {
  const calls = [];
  let released = false;
  const pool = {
    async connect() {
      return {
        async query(text) {
          calls.push(text);
          if (text.startsWith("SELECT identity.set_tenant_actor_context")) {
            const error = new Error("Tenant actor context denied.");
            error.code = "42501";
            throw error;
          }
          return { rowCount: null, rows: [] };
        },
        release() {
          released = true;
        },
      };
    },
  };
  const repository = createPostgresTenantRepository({ pool, authorizationMode, clock: fixedClock });

  await assert.rejects(repository.listRecords(authentication), AccessDeniedError);
  assert.deepEqual(calls, [
    "BEGIN",
    "SET LOCAL ROLE tenant_trust_app",
    "SELECT identity.set_tenant_actor_context($1::identity.tenant_id, $2::identity.subject_id)",
    "ROLLBACK",
  ]);
  assert.equal(released, true);
});

test("non-certificate or malformed authentication is denied before a connection is acquired", async () => {
  let connected = false;
  const repository = createPostgresTenantRepository({
    authorizationMode,
    pool: {
      async connect() {
        connected = true;
        throw new Error("must not connect");
      },
    },
  });

  await assert.rejects(
    repository.getProfile({ ...authentication, source: "header" }),
    AccessDeniedError,
  );
  await assert.rejects(
    repository.getProfile({ ...authentication, tenantId: "not-a-tenant" }),
    AccessDeniedError,
  );
  await assert.rejects(
    repository.getProfile({ ...authentication, certificate: undefined }),
    CertificateNotAcceptedError,
  );
  assert.equal(connected, false);
});

test("one repository and pooled connection recheck certificate, tenant and membership state on every request", async () => {
  let certificateState = "active";
  let tenantState = "active";
  let membershipState = "active";
  let connections = 0;
  const client = {
    async query(input, parameters) {
      const text = typeof input === "string" ? input : input.text;
      const values = typeof input === "string" ? parameters : input.values;
      if (text.includes("array_agg")) {
        return { rowCount: 1, rows: [{
          ...authorityRow,
          tenant_state: tenantState,
          membership_state: membershipState,
        }] };
      }
      if (text.includes("transaction_timestamp() AS status_observed_at")) {
        return { rowCount: 1, rows: [{
          tenant_id: authentication.tenantId,
          certificate_id: certificateId,
          subject_id: authentication.subjectId,
          issuer_id: authentication.certificate.issuerId,
          serial_number: authentication.certificate.serialNumber,
          fingerprint_sha256: authentication.certificate.fingerprintSha256,
          state: certificateState,
          not_before: authentication.certificate.notBefore,
          not_after: authentication.certificate.notAfter,
          version: certificateState === "active" ? 1 : 2,
          status_observed_at: "2026-09-15T10:00:00.000Z",
        }] };
      }
      if (text.includes("FROM identity.certificates")) {
        assert.deepEqual(values.slice(0, 2), [authentication.tenantId, authentication.subjectId]);
        return { rowCount: 1, rows: [{ certificate_id: certificateId }] };
      }
      if (text.includes("tenant.display_name AS tenant_display_name")) {
        return { rowCount: 1, rows: [{
          tenant_display_name: "Tenant Alpha",
          display_name: "Alice",
          subject_kind: "human",
          member_since: new Date("2026-01-01T00:00:00.000Z"),
        }] };
      }
      return { rowCount: null, rows: [] };
    },
    release() {},
  };
  const pool = {
    async connect() {
      connections += 1;
      return client;
    },
  };
  const repository = createPostgresTenantRepository({ pool, authorizationMode, clock: fixedClock });

  assert.equal((await repository.getProfile(authentication)).tenantId, authentication.tenantId);
  certificateState = "revoked";
  await assert.rejects(repository.getProfile(authentication), CertificateNotAcceptedError);
  certificateState = "active";
  membershipState = "suspended";
  await assert.rejects(repository.getProfile(authentication), AccessDeniedError);
  membershipState = "active";
  tenantState = "suspended";
  await assert.rejects(repository.getProfile(authentication), AccessDeniedError);
  assert.equal(connections, 4);
});

test("repository construction requires explicit branded mode selection", () => {
  const pool = { async connect() { throw new Error("must not connect"); } };
  assert.throws(
    () => createPostgresTenantRepository({ pool }),
    /explicit supported authorization mode/u,
  );
  assert.throws(
    () => createPostgresTenantRepository({ pool, authorizationMode: { ...authorizationMode } }),
    /explicit supported authorization mode/u,
  );
});
