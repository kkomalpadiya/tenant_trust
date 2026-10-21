const assert = require("node:assert/strict");
const { test } = require("node:test");
const { TenantTrustAuditContract } = require("../dist/audit-contract.js");

const hash = (character) => character.repeat(64);
const baseValue = {
  canonicalizationProfile: "tenant-trust-audit-commitment-json-v1",
  commitmentHashSha256: hash("b"),
  digestAlgorithm: "sha256",
  eventKeyHashSha256: hash("a"),
  recordType: "trust-transition",
  schemaVersion: "1.0.0",
};

function context({
  channelId = "tt-audit-alpha-v1",
  mspId = "PlatformAuditMSP",
  role = "audit-writer",
  state = new Map(),
} = {}) {
  const puts = [];
  const events = [];
  return {
    state,
    puts,
    events,
    ctx: {
      clientIdentity: {
        getMSPID: () => mspId,
        assertAttributeValue: (name, value) => name === "tenantTrust.role" && value === role,
      },
      stub: {
        getChannelID: () => channelId,
        getState: async (key) => state.get(key) ?? Buffer.alloc(0),
        putState: async (key, value) => {
          const copy = Buffer.from(value);
          state.set(key, copy);
          puts.push([key, copy]);
        },
        setEvent: (name, value) => events.push([name, Buffer.from(value)]),
      },
    },
  };
}

test("creates one commitment plus an opaque event anchor atomically", async () => {
  const fixture = context();
  const contract = new TenantTrustAuditContract();
  const result = JSON.parse(await contract.CommitCommitment(fixture.ctx, JSON.stringify(baseValue)));
  const ledgerKey = `audit~trust-transition~${hash("a")}`;

  assert.deepEqual(result, { ledgerKey, status: "created" });
  assert.equal(fixture.puts.length, 2);
  assert.equal(fixture.state.get(ledgerKey).toString("utf8"), JSON.stringify(baseValue));
  assert.equal(fixture.state.get(`event~${hash("a")}`).toString("utf8"), ledgerKey);
  assert.equal(fixture.events.length, 1);
  assert.equal(fixture.events[0][0], "AuditCommitmentCreated");
  assert.equal(fixture.events[0][1].toString("utf8").includes("tnt_"), false);
});

test("accepts an exact retry without another write or event", async () => {
  const fixture = context();
  const contract = new TenantTrustAuditContract();
  await contract.CommitCommitment(fixture.ctx, JSON.stringify(baseValue));
  fixture.puts.length = 0;
  fixture.events.length = 0;

  const result = JSON.parse(await contract.CommitCommitment(fixture.ctx, JSON.stringify(baseValue)));
  assert.equal(result.status, "duplicate");
  assert.equal(fixture.puts.length, 0);
  assert.equal(fixture.events.length, 0);
});

test("rejects changed bytes at an existing commitment key", async () => {
  const fixture = context();
  const contract = new TenantTrustAuditContract();
  await contract.CommitCommitment(fixture.ctx, JSON.stringify(baseValue));
  await assert.rejects(
    contract.CommitCommitment(fixture.ctx, JSON.stringify({ ...baseValue, commitmentHashSha256: hash("c") })),
    /CONFLICTING_COMMITMENT/,
  );
});

test("rejects reuse of one opaque event key under another record type", async () => {
  const fixture = context();
  const contract = new TenantTrustAuditContract();
  await contract.CommitCommitment(fixture.ctx, JSON.stringify(baseValue));
  await assert.rejects(
    contract.CommitCommitment(fixture.ctx, JSON.stringify({ ...baseValue, recordType: "access-decision" })),
    /CONFLICTING_EVENT_ANCHOR/,
  );
});

test("rejects partial state instead of repairing an untrusted anchor", async () => {
  const state = new Map([[`event~${hash("a")}`, Buffer.from(`audit~trust-transition~${hash("a")}`)]]);
  const fixture = context({ state });
  await assert.rejects(
    new TenantTrustAuditContract().CommitCommitment(fixture.ctx, JSON.stringify(baseValue)),
    /INCONSISTENT_STATE/,
  );
});

test("accepts only the exact public commitment schema", async () => {
  const contract = new TenantTrustAuditContract();
  await assert.rejects(
    contract.CommitCommitment(context().ctx, JSON.stringify({ ...baseValue, tenantId: "tnt_private" })),
    /unapproved public fields/,
  );
  await assert.rejects(
    contract.CommitCommitment(context().ctx, JSON.stringify({ ...baseValue, eventKeyHashSha256: hash("A") })),
    /invalid eventKeyHashSha256/,
  );
  await assert.rejects(contract.CommitCommitment(context().ctx, "not-json"), /valid JSON/);
});

test("only the platform audit writer can submit on configured channels", async () => {
  const contract = new TenantTrustAuditContract();
  await assert.rejects(
    contract.CommitCommitment(context({ role: "audit-verifier" }).ctx, JSON.stringify(baseValue)),
    /FORBIDDEN/,
  );
  await assert.rejects(
    contract.CommitCommitment(context({ mspId: "TenantAlphaAuditMSP", role: "tenant-auditor" }).ctx, JSON.stringify(baseValue)),
    /FORBIDDEN/,
  );
  await assert.rejects(
    contract.CommitCommitment(context({ channelId: "shared-channel" }).ctx, JSON.stringify(baseValue)),
    /UNSUPPORTED_CHANNEL/,
  );
});

test("platform verifier and the matching tenant auditor can read", async () => {
  const state = new Map([[`audit~trust-transition~${hash("a")}`, Buffer.from(JSON.stringify(baseValue))]]);
  const contract = new TenantTrustAuditContract();
  const platform = context({ role: "audit-verifier", state });
  const alpha = context({ mspId: "TenantAlphaAuditMSP", role: "tenant-auditor", state });

  assert.equal(await contract.ReadCommitment(platform.ctx, "trust-transition", hash("a")), JSON.stringify(baseValue));
  assert.equal(await contract.ReadCommitment(alpha.ctx, "trust-transition", hash("a")), JSON.stringify(baseValue));
});

test("query authorization is channel-bound and fails closed", async () => {
  const contract = new TenantTrustAuditContract();
  await assert.rejects(
    contract.ReadCommitment(context({ mspId: "TenantBetaAuditMSP", role: "tenant-auditor" }).ctx, "trust-transition", hash("a")),
    /FORBIDDEN/,
  );
  await assert.rejects(
    contract.ReadCommitment(context({ role: "audit-writer" }).ctx, "trust-transition", hash("a")),
    /FORBIDDEN/,
  );
  await assert.rejects(
    contract.ReadCommitment(context({ role: "audit-verifier" }).ctx, "trust-transition", hash("a")),
    /COMMITMENT_NOT_FOUND/,
  );
});
