import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const topologyPath = path.join(repositoryRoot, "config", "fabric-topology.json");
const designPath = path.join(
  repositoryRoot,
  "docs",
  "architecture",
  "fabric-topology-and-audit-permissions.md",
);
const seedPath = path.join(repositoryRoot, "database", "seeds", "001_demo_identities.sql");

const topology = JSON.parse(await readFile(topologyPath, "utf8"));
const design = await readFile(designPath, "utf8");
const identitySeed = await readFile(seedPath, "utf8");

function unique(values, label) {
  assert.equal(new Set(values).size, values.length, `${label} must be unique`);
}

function exactMembers(actual, expected, label) {
  assert.deepEqual(
    [...actual].sort(),
    [...expected].sort(),
    `${label} must contain exactly the selected members`,
  );
}

function exactPermission(actual, expected, label) {
  const normalize = (entries) => entries.map(({ mspId, role }) => `${mspId}:${role}`).sort();
  assert.deepEqual(normalize(actual), normalize(expected), `${label} has an unexpected identity`);
}

assert.equal(topology.schemaVersion, "1.0.0");
assert.equal(topology.networkName, "tenant-trust-audit");
assert.equal(topology.channelParticipationApi, true);
assert.equal(topology.systemChannel, false);
assert.equal(topology.stateDatabase, "goleveldb");
assert.equal(topology.chaincode.name, "tenant-trust-audit");
assert.equal(topology.chaincode.identityRoleAttribute, "tenantTrust.role");

assert.equal(topology.identityBoundary.authority, "fabric-ca");
assert.equal(topology.identityBoundary.oneEnrollmentAuthorityPerMsp, true);
assert.equal(topology.identityBoundary.reusesSaasPki, false);
assert.equal(topology.identityBoundary.commitGeneratedMaterial, false);
assert.equal(topology.identityBoundary.generatedMaterialLocation, "runtime/fabric");

assert.equal(topology.ordering.consensus, "etcdraft");
assert.equal(topology.ordering.mspId, "TenantTrustOrdererMSP");
assert.equal(topology.ordering.localNodeCount, 1);
assert.ok(topology.ordering.productionMinimumNodeCount >= 3);
assert.equal(topology.ordering.highAvailabilityClaimed, false);
assert.equal(topology.ordering.nodes.length, topology.ordering.localNodeCount);

assert.equal(topology.peerOrganizations.length, 3);
assert.equal(topology.tenants.length, 2);
assert.equal(topology.channels.length, topology.tenants.length);

const organizationsByMsp = new Map(
  topology.peerOrganizations.map((organization) => [organization.mspId, organization]),
);
const tenantsById = new Map(topology.tenants.map((tenant) => [tenant.tenantId, tenant]));
const channelsByName = new Map(topology.channels.map((channel) => [channel.name, channel]));

unique(
  [topology.ordering.mspId, ...topology.peerOrganizations.map(({ mspId }) => mspId)],
  "MSP IDs",
);
unique(
  [
    ...topology.ordering.nodes,
    ...topology.peerOrganizations.flatMap(({ peers }) => peers),
  ],
  "Fabric node names",
);
unique(topology.tenants.map(({ tenantId }) => tenantId), "tenant IDs");
unique(topology.tenants.map(({ channel }) => channel), "tenant channel mappings");
unique(topology.channels.map(({ name }) => name), "channel names");

assert.deepEqual(
  organizationsByMsp.get("PlatformAuditMSP")?.roles,
  ["audit-writer", "audit-verifier", "audit-commit-listener"],
);
assert.equal(organizationsByMsp.get("PlatformAuditMSP")?.peers.length, 1);

for (const tenant of topology.tenants) {
  assert.match(
    tenant.tenantId,
    /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
  );
  assert.ok(identitySeed.includes(`'${tenant.tenantId}'`), `${tenant.tenantId} must exist in the demo seed`);
  assert.ok(organizationsByMsp.has(tenant.mspId), `${tenant.mspId} must be a peer organization`);

  const tenantOrganization = organizationsByMsp.get(tenant.mspId);
  assert.deepEqual(tenantOrganization.roles, ["tenant-auditor"]);
  assert.equal(tenantOrganization.peers.length, 1);

  const channel = channelsByName.get(tenant.channel);
  assert.ok(channel, `${tenant.channel} must exist`);
  assert.equal(channel.tenantId, tenant.tenantId);
  assert.equal(channel.ordererMspId, topology.ordering.mspId);
  exactMembers(
    channel.peerMspIds,
    ["PlatformAuditMSP", tenant.mspId],
    `${channel.name} peer membership`,
  );

  for (const otherTenant of topology.tenants) {
    if (otherTenant.tenantId !== tenant.tenantId) {
      assert.ok(
        !channel.peerMspIds.includes(otherTenant.mspId),
        `${channel.name} must exclude ${otherTenant.mspId}`,
      );
    }
  }

  const expectedPeerPolicy = `AND('PlatformAuditMSP.peer','${tenant.mspId}.peer')`;
  const expectedAdminPolicy = `AND('PlatformAuditMSP.admin','${tenant.mspId}.admin')`;
  const expectedMemberPolicy = `OR('PlatformAuditMSP.member','${tenant.mspId}.member')`;
  assert.equal(channel.policies.endorsement, expectedPeerPolicy);
  assert.equal(channel.policies.lifecycleEndorsement, expectedPeerPolicy);
  assert.equal(channel.policies.admins, expectedAdminPolicy);
  assert.equal(channel.policies.readers, expectedMemberPolicy);
  assert.equal(channel.policies.writers, expectedMemberPolicy);

  exactPermission(
    channel.permissions.submitCommitment,
    [{ mspId: "PlatformAuditMSP", role: "audit-writer" }],
    `${channel.name} submit permission`,
  );
  exactPermission(
    channel.permissions.queryCommitment,
    [
      { mspId: "PlatformAuditMSP", role: "audit-verifier" },
      { mspId: tenant.mspId, role: "tenant-auditor" },
    ],
    `${channel.name} query permission`,
  );
  exactPermission(
    channel.permissions.listenForCommits,
    [
      { mspId: "PlatformAuditMSP", role: "audit-commit-listener" },
      { mspId: tenant.mspId, role: "tenant-auditor" },
    ],
    `${channel.name} commit-listener permission`,
  );

  assert.equal(channel.publicState, "commitments-only");
  assert.deepEqual(channel.privateDataCollections, []);
  exactMembers(
    channel.anchorPeers,
    [organizationsByMsp.get("PlatformAuditMSP").peers[0], tenantOrganization.peers[0]],
    `${channel.name} anchor peers`,
  );

  for (const requiredName of [channel.name, tenant.mspId]) {
    assert.ok(design.includes(requiredName), `design must explain ${requiredName}`);
  }
}

assert.equal(topology.dataBoundary.rawEvidenceOnChain, false);
assert.equal(topology.dataBoundary.detailedApplicationStateOnChain, false);
assert.equal(topology.dataBoundary.plainTenantIdOnChain, false);
assert.equal(topology.dataBoundary.plainSubjectOrResourceIdOnChain, false);
assert.equal(topology.dataBoundary.commitmentPreimagesOffChain, true);
assert.equal(topology.dataBoundary.crossTenantSharedApplicationChannel, false);

for (const role of ["audit-writer", "audit-verifier", "audit-commit-listener", "tenant-auditor"]) {
  assert.ok(design.includes(`\`${role}\``), `design must explain ${role}`);
}

assert.equal(tenantsById.size, 2);
console.log(
  `Fabric topology verified: ${topology.peerOrganizations.length} peer organizations, `
  + `${topology.ordering.localNodeCount} local Raft orderer and ${topology.channels.length} isolated tenant channels.`,
);
