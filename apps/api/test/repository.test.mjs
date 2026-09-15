import assert from "node:assert/strict";
import test from "node:test";
import { AccessDeniedError, createPostgresTenantRepository } from "../src/index.mjs";

const authentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: "sha256:alpha",
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
});

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
    async query(text, parameters) {
      calls.push({ text, parameters });
      if (text.includes("array_agg")) return { rowCount: 1, rows: [authorityRow] };
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
  const repository = createPostgresTenantRepository({ pool });

  const record = await repository.getRecord(
    authentication,
    "res_018f1234-5678-7abc-8def-0123456789b0",
  );

  assert.equal(record.name, "Alpha member record");
  assert.equal(record.version, 1);
  assert.equal(pool.calls[0].text, "BEGIN");
  assert.equal(pool.calls[1].text, "SET LOCAL ROLE tenant_trust_app");
  assert.deepEqual(pool.calls[2].parameters, [authentication.tenantId, authentication.subjectId]);
  assert.deepEqual(pool.calls[4].parameters, [
    authentication.tenantId,
    "res_018f1234-5678-7abc-8def-0123456789b0",
  ]);
  assert.match(pool.calls[4].text, /WHERE tenant_id = \$1/u);
  assert.equal(pool.calls.at(-1).text, "COMMIT");
  assert.equal(pool.released, true);
});

test("an invisible record rolls back and returns one access-denied type", async () => {
  const pool = createPool(() => ({ rowCount: 0, rows: [] }));
  const repository = createPostgresTenantRepository({ pool });

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
  const repository = createPostgresTenantRepository({ pool });

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
  assert.equal(connected, false);
});
