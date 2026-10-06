import assert from "node:assert/strict";
import { test } from "node:test";
import {
  TrustStateStorageError,
  createPostgresTrustStateRepository,
  normalizeTrustStateWrite,
} from "../src/index.mjs";

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
};

const readIdentity = {
  tenantId: ids.tenant,
  subjectId: ids.subject,
};

const evidenceReferences = [
  ["identity", "d0", "e0"],
  ["device", "d1", "e1"],
  ["behaviour", "d2", "e2"],
  ["certificate", "d3", "e3"],
  ["compliance", "d4", "e4"],
].map(([evidenceType, evidenceSuffix, eventSuffix]) => ({
  evidenceId: `evd_018f1234-5678-7abc-8def-0123456789${evidenceSuffix}`,
  sourceEventId: `evt_018f1234-5678-7abc-8def-0123456789${eventSuffix}`,
  evidenceType,
}));

const write = {
  tenantId: ids.tenant,
  subjectId: ids.subject,
  expectedPreviousVersion: 0,
  modelVersion: "1.0.0",
  configurationVersion: 1,
  components: {
    identity: 91,
    device: 82.5,
    behaviour: 76,
    certificate: 100,
    compliance: 88,
  },
  observedAt: "2026-10-06T08:00:00.000Z",
  evidenceReferences,
};

function row(overrides = {}) {
  return {
    tenant_id: ids.tenant,
    subject_id: ids.subject,
    update_version: "1",
    model_version: "1.0.0",
    configuration_version: "1",
    identity_component: "91.00",
    device_component: "82.50",
    behaviour_component: "76.00",
    certificate_component: "100.00",
    compliance_component: "88.00",
    observed_at: "2026-10-06T08:00:00.000Z",
    recorded_at: "2026-10-06T08:00:01.000Z",
    evidence_references: evidenceReferences,
    ...overrides,
  };
}

function poolWith(handler) {
  const calls = [];
  let released = false;
  const client = {
    async query(configuration) {
      calls.push(configuration);
      return handler(configuration, calls.length);
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

test("normalizes one immutable complete state write in canonical component order", () => {
  const normalized = normalizeTrustStateWrite({
    ...write,
    evidenceReferences: [...evidenceReferences].reverse(),
  });
  assert.deepEqual(normalized.components, write.components);
  assert.deepEqual(
    normalized.evidenceReferences.map(({ evidenceType }) => evidenceType),
    ["identity", "device", "behaviour", "certificate", "compliance"],
  );
  assert.ok(Object.isFrozen(normalized));
  assert.ok(Object.isFrozen(normalized.components));
  assert.ok(Object.isFrozen(normalized.evidenceReferences));
  assert.ok(normalized.evidenceReferences.every(Object.isFrozen));
});

test("rejects forged identity fields, partial components and noncanonical observation times", () => {
  const invalid = [
    { ...write, tenantId: "tnt_other" },
    { ...write, subjectId: "sub_other" },
    { ...write, expectedPreviousVersion: -1 },
    { ...write, modelVersion: "v1" },
    { ...write, configurationVersion: 0 },
    { ...write, components: { ...write.components, identity: 101 } },
    { ...write, components: Object.fromEntries(Object.entries(write.components).slice(0, -1)) },
    { ...write, observedAt: "2026-10-06 08:00:00" },
    { ...write, tenantId: ids.tenant, unexpected: true },
  ];
  for (const candidate of invalid) {
    assert.throws(
      () => normalizeTrustStateWrite(candidate),
      (error) => error instanceof TrustStateStorageError,
    );
  }
});

test("requires five unique type-bound evidence and source-event references", () => {
  const invalid = [
    { ...write, evidenceReferences: evidenceReferences.slice(0, -1) },
    { ...write, evidenceReferences: [...evidenceReferences, evidenceReferences[0]] },
    { ...write, evidenceReferences: evidenceReferences.map((entry, index) => (
      index === 4 ? { ...entry, evidenceType: "identity" } : entry
    )) },
    { ...write, evidenceReferences: evidenceReferences.map((entry, index) => (
      index === 4 ? { ...entry, evidenceId: evidenceReferences[0].evidenceId } : entry
    )) },
    { ...write, evidenceReferences: evidenceReferences.map((entry, index) => (
      index === 4 ? { ...entry, sourceEventId: evidenceReferences[0].sourceEventId } : entry
    )) },
    { ...write, evidenceReferences: evidenceReferences.map((entry, index) => (
      index === 0 ? { ...entry, tenantId: ids.tenant } : entry
    )) },
  ];
  for (const candidate of invalid) {
    assert.throws(
      () => normalizeTrustStateWrite(candidate),
      (error) => error instanceof TrustStateStorageError,
    );
  }
});

test("stores through one parameterized least-privilege transaction and confirms the next version", async () => {
  const pool = poolWith(async ({ text }) => {
    if (text.includes("store_subject_trust_state")) return { rows: [row()] };
    return { rows: [] };
  });
  const repository = createPostgresTrustStateRepository({ pool });
  const stored = await repository.store(write);

  assert.deepEqual(stored, {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    updateVersion: 1,
    modelVersion: "1.0.0",
    configurationVersion: 1,
    observedAt: "2026-10-06T08:00:00.000Z",
    recordedAt: "2026-10-06T08:00:01.000Z",
  });
  assert.deepEqual(pool.calls.map(({ text }) => text.trim()), [
    "BEGIN",
    "SET LOCAL ROLE tenant_trust_trust_engine",
    pool.calls[2].text.trim(),
    "COMMIT",
  ]);
  assert.match(pool.calls[2].text, /store_subject_trust_state/u);
  assert.deepEqual(pool.calls[2].values.slice(0, 5), [ids.tenant, ids.subject, 0, "1.0.0", 1]);
  assert.deepEqual(pool.calls[2].values.slice(5, 11), [91, 82.5, 76, 100, 88, write.observedAt]);
  assert.deepEqual(JSON.parse(pool.calls[2].values[11]), evidenceReferences);
  assert.equal(pool.released, true);
});

test("rejects an unconfirmed or mismatched durable version", async () => {
  for (const persisted of [null, row({ update_version: "2" }), row({ tenant_id: "tnt_018f1234-5678-7abc-8def-0123456789ac" })]) {
    const pool = poolWith(async ({ text }) => {
      if (text.includes("store_subject_trust_state")) return { rows: persisted ? [persisted] : [] };
      return { rows: [] };
    });
    const repository = createPostgresTrustStateRepository({ pool });
    await assert.rejects(
      repository.store(write),
      (error) => error instanceof TrustStateStorageError
        && error.reasonCode === "TRUST_STATE_WRITE_UNCONFIRMED",
    );
  }
});

test("reads current and historical versions as immutable normalized state", async () => {
  const pool = poolWith(async ({ text }) => {
    if (text.includes("get_current_subject_trust_state")) return { rows: [row()] };
    if (text.includes("get_subject_trust_state_version")) return { rows: [row()] };
    return { rows: [] };
  });
  const repository = createPostgresTrustStateRepository({ pool });
  const current = await repository.getCurrent(readIdentity);
  const historical = await repository.getVersion({ ...readIdentity, updateVersion: 1 });

  assert.deepEqual(current, historical);
  assert.deepEqual(current.components, write.components);
  assert.deepEqual(current.evidenceReferences, evidenceReferences);
  assert.ok(Object.isFrozen(current));
  assert.ok(Object.isFrozen(current.components));
  assert.ok(Object.isFrozen(current.evidenceReferences));
  assert.equal(pool.calls.filter(({ text }) => text.includes("SET LOCAL ROLE")).length, 2);
});

test("returns null for an absent state and rejects malformed read identities", async () => {
  const pool = poolWith(async () => ({ rows: [] }));
  const repository = createPostgresTrustStateRepository({ pool });
  assert.equal(await repository.getCurrent(readIdentity), null);
  assert.equal(await repository.getVersion({ ...readIdentity, updateVersion: 1 }), null);
  await assert.rejects(repository.getCurrent({ tenantId: ids.tenant, subjectId: "sub_other" }), TrustStateStorageError);
  await assert.rejects(repository.getVersion({ ...readIdentity, updateVersion: 0 }), TrustStateStorageError);
});

test("rolls back and releases the connection when PostgreSQL persistence fails", async () => {
  const failure = new Error("write failed");
  const pool = poolWith(async ({ text }) => {
    if (text.includes("store_subject_trust_state")) throw failure;
    return { rows: [] };
  });
  const repository = createPostgresTrustStateRepository({ pool });
  await assert.rejects(repository.store(write), failure);
  assert.equal(pool.calls.at(-1).text, "ROLLBACK");
  assert.equal(pool.released, true);
});
