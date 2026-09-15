import assert from "node:assert/strict";
import test from "node:test";
import { AccessDeniedError, createPostgresTenantRepository } from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  admin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  member: "sub_018f1234-5678-7abc-8def-0123456789ab",
  recordA: "res_018f1234-5678-7abc-8def-0123456789b0",
  recordB: "res_018f1234-5678-7abc-8def-0123456789b1",
  operation: "op_018f1234-5678-4abc-8def-0123456789b4",
});

function authentication(subjectId = ids.admin) {
  return Object.freeze({
    source: "mtls-certificate",
    authenticationId: `sha256:${subjectId}`,
    tenantId: ids.tenant,
    subjectId,
  });
}

function authorityRow(subjectId, roles) {
  return {
    tenant_id: ids.tenant,
    tenant_state: "active",
    tenant_version: "2",
    subject_id: subjectId,
    subject_state: "active",
    subject_version: "3",
    membership_state: "active",
    membership_version: "4",
    roles,
  };
}

function recordRow(resourceId, ownerSubjectId = ids.member) {
  return {
    resource_id: resourceId,
    owner_subject_id: ownerSubjectId,
    resource_name: `Record ${resourceId.at(-1)}`,
    version: "1",
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-02T00:00:00.000Z"),
  };
}

function createPool({ roles = ["tenant-admin"], resourceRows = [], membershipRows = [] } = {}) {
  const calls = [];
  let released = false;
  const client = {
    async query(text, parameters) {
      calls.push({ text, parameters });
      if (text.includes("FROM identity.tenants AS tenant")) {
        return { rowCount: 1, rows: [authorityRow(parameters[1], roles)] };
      }
      if (text.includes("FROM app.resources")) {
        return { rowCount: resourceRows.length, rows: resourceRows };
      }
      if (text.includes("FROM identity.tenant_memberships AS membership")) {
        return { rowCount: membershipRows.length, rows: membershipRows };
      }
      return { rowCount: null, rows: [] };
    },
    release() { released = true; },
  };
  return {
    calls,
    get released() { return released; },
    async connect() { return client; },
  };
}

function createAuthorizedRepository(pool, observe = () => {}) {
  return createPostgresTenantRepository({
    pool,
    operationIdFactory: () => ids.operation,
    sensitiveOperationAuthorizer: async (request) => {
      observe(request);
      return true;
    },
  });
}

test("tenant-admin export is bounded, tenant-qualified and carries a server operation ID", async () => {
  let authorizationRequest;
  const pool = createPool({ resourceRows: [recordRow(ids.recordA), recordRow(ids.recordB, ids.admin)] });
  const repository = createAuthorizedRepository(pool, (request) => { authorizationRequest = request; });

  const result = await repository.exportRecords(authentication(), [ids.recordA, ids.recordB]);

  assert.equal(result.operation.operationId, ids.operation);
  assert.equal(result.operation.action, "record:export");
  assert.equal(result.operation.tenantId, ids.tenant);
  assert.equal(result.operation.requestedBy, ids.admin);
  assert.equal(result.operation.recordCount, 2);
  assert.deepEqual(result.records.map(({ recordId }) => recordId), [ids.recordA, ids.recordB]);
  assert.equal(authorizationRequest.context.tenantId, ids.tenant);
  assert.deepEqual(authorizationRequest.context.roles, ["tenant-admin"]);
  assert.equal(authorizationRequest.eligibility.disposition, "requires-controls");
  assert.deepEqual(authorizationRequest.attributes, { requestedRecordCount: 2 });

  const exportQuery = pool.calls.find(({ text }) => text.includes("FROM app.resources"));
  assert.deepEqual(exportQuery.parameters, [ids.tenant, [ids.recordA, ids.recordB]]);
  assert.match(exportQuery.text, /tenant_id = \$1::identity\.tenant_id/u);
  assert.match(exportQuery.text, /ANY\(\$2::app\.resource_id\[\]\)/u);
  assert.equal(pool.calls.at(-1).text, "COMMIT");
  assert.equal(pool.released, true);
});

test("export is all-or-nothing when any requested record is not visible", async () => {
  const pool = createPool({ resourceRows: [recordRow(ids.recordA)] });
  const repository = createAuthorizedRepository(pool);

  await assert.rejects(
    repository.exportRecords(authentication(), [ids.recordA, ids.recordB]),
    AccessDeniedError,
  );
  assert.equal(pool.calls.at(-1).text, "ROLLBACK");
});

test("tenant members and missing control decisions are denied before sensitive data queries", async () => {
  let authorizerCalls = 0;
  const memberPool = createPool({ roles: ["tenant-member"], resourceRows: [recordRow(ids.recordA)] });
  const memberRepository = createPostgresTenantRepository({
    pool: memberPool,
    operationIdFactory: () => ids.operation,
    sensitiveOperationAuthorizer: async () => {
      authorizerCalls += 1;
      return true;
    },
  });
  await assert.rejects(
    memberRepository.exportRecords(authentication(ids.member), [ids.recordA]),
    AccessDeniedError,
  );
  assert.equal(authorizerCalls, 0);
  assert.equal(memberPool.calls.some(({ text }) => text.includes("FROM app.resources")), false);

  const defaultDenyPool = createPool({ resourceRows: [recordRow(ids.recordA)] });
  const defaultDenyRepository = createPostgresTenantRepository({
    pool: defaultDenyPool,
    operationIdFactory: () => ids.operation,
  });
  await assert.rejects(
    defaultDenyRepository.exportRecords(authentication(), [ids.recordA]),
    AccessDeniedError,
  );
  assert.equal(defaultDenyPool.calls.some(({ text }) => text.includes("FROM app.resources")), false);
});

test("membership review is tenant-admin-only and queries one tenant-qualified subject", async () => {
  let authorizationRequest;
  const membershipRow = {
    subject_id: ids.member,
    display_name: "Alpha Member",
    subject_state: "active",
    subject_version: "3",
    membership_state: "active",
    membership_version: "4",
    roles: ["tenant-member"],
  };
  const pool = createPool({ membershipRows: [membershipRow] });
  const repository = createAuthorizedRepository(pool, (request) => { authorizationRequest = request; });

  const result = await repository.reviewMembership(authentication(), ids.member);

  assert.equal(result.operation.operationId, ids.operation);
  assert.equal(result.operation.action, "tenant:admin");
  assert.equal(result.operation.targetSubjectId, ids.member);
  assert.deepEqual(result.membership, {
    subjectId: ids.member,
    displayName: "Alpha Member",
    subjectState: "active",
    subjectVersion: 3,
    membershipState: "active",
    membershipVersion: 4,
    roles: ["tenant-member"],
  });
  assert.deepEqual(authorizationRequest.attributes, { targetSubjectId: ids.member });
  const reviewQuery = pool.calls.find(({ text }) => text.includes("FROM identity.tenant_memberships AS membership"));
  assert.deepEqual(reviewQuery.parameters, [ids.tenant, ids.member]);
  assert.match(reviewQuery.text, /membership\.tenant_id = \$1::identity\.tenant_id/u);
});

test("foreign, absent and malformed admin targets fail closed", async () => {
  const pool = createPool();
  const repository = createAuthorizedRepository(pool);
  await assert.rejects(repository.reviewMembership(authentication(), ids.member), AccessDeniedError);
  assert.equal(pool.calls.at(-1).text, "ROLLBACK");

  let connected = false;
  const disconnectedRepository = createPostgresTenantRepository({
    pool: { async connect() { connected = true; throw new Error("must not connect"); } },
  });
  await assert.rejects(disconnectedRepository.reviewMembership(authentication(), "not-a-subject"), TypeError);
  await assert.rejects(disconnectedRepository.exportRecords(authentication(), []), TypeError);
  await assert.rejects(disconnectedRepository.exportRecords(authentication(), [ids.recordA, ids.recordA]), TypeError);
  assert.equal(connected, false);
});
