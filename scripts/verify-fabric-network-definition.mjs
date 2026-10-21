import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const toolchain = JSON.parse(readFileSync(new URL("../config/toolchain.json", import.meta.url), "utf8"));
const environmentExample = readFileSync(new URL("../.env.example", import.meta.url), "utf8");
const compose = readFileSync(new URL("../infra/fabric/compose.yaml", import.meta.url), "utf8");
const bootstrap = readFileSync(new URL("../infra/fabric/bootstrap-identities.sh", import.meta.url), "utf8");
const channelConfig = readFileSync(new URL("../infra/fabric/configtx.yaml", import.meta.url), "utf8");

const expectedImages = new Map([
  ["FABRIC_PEER_IMAGE", `hyperledger/fabric-peer:${toolchain.fabric}@sha256:09ee75042de9983bfde31ca88a5bf033386351f10a990e4c48264ee50172dee0`],
  ["FABRIC_ORDERER_IMAGE", `hyperledger/fabric-orderer:${toolchain.fabric}@sha256:e322c57331d37e0a35ffae3cb3d3265a0e852211c0f801f2514cc15b964ffc93`],
  ["FABRIC_TOOLS_IMAGE", `hyperledger/fabric-tools:${toolchain.fabric}@sha256:1d163b2513453637c2eb8ffe00bfb367f6edb2fb824604818f30646f552c9f42`],
  ["FABRIC_CA_IMAGE", "hyperledger/fabric-ca:1.5.17@sha256:fac0c4a70afc2fe6ae291ffb3c6d27db87ac638ecf5b5418841c7363588e568a"],
]);

const parsedExample = new Map(
  environmentExample
    .split(/\r?\n/u)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
);

for (const [key, expected] of expectedImages) {
  assert.equal(parsedExample.get(key), expected, `${key} must keep the reviewed tag and digest together`);
  assert.match(compose, new RegExp(`\\$\\{${key}\\}`), `${key} must be consumed by the Fabric Compose file`);
}

for (const service of [
  "ca-orderer",
  "ca-platform",
  "ca-alpha",
  "ca-beta",
  "orderer0.audit.tenant-trust.test",
  "peer0.platform.audit.tenant-trust.test",
  "peer0.alpha.audit.tenant-trust.test",
  "peer0.beta.audit.tenant-trust.test",
]) {
  assert.match(compose, new RegExp(`^  ${service.replaceAll(".", "\\.")}:`, "mu"), `missing Fabric service ${service}`);
}

assert.doesNotMatch(compose, /docker\.sock|runtime\/pki|step-ca/iu, "Fabric must not receive the Docker socket or SaaS PKI material");
assert.match(compose, /\.\.\/\.\.\/runtime\/fabric:/u, "generated Fabric material must remain under ignored runtime/fabric storage");
assert.match(bootstrap, /tenantTrust\.role=audit-writer:ecert/u);
assert.match(bootstrap, /tenantTrust\.role=audit-verifier:ecert/u);
assert.match(bootstrap, /tenantTrust\.role=audit-commit-listener:ecert/u);
assert.equal((bootstrap.match(/tenantTrust\.role=tenant-auditor:ecert/gu) ?? []).length, 1, "tenant auditor role must be registered through the shared tenant-org function");
assert.match(channelConfig, /TenantAlphaAuditChannel:[\s\S]*PlatformAuditOrg[\s\S]*TenantAlphaAuditOrg/u);
assert.match(channelConfig, /TenantBetaAuditChannel:[\s\S]*PlatformAuditOrg[\s\S]*TenantBetaAuditOrg/u);

const trackedRuntime = spawnSync("git", ["ls-files", "runtime", "**/peerOrganizations", "**/ordererOrganizations", "**/channel-artifacts"], {
  cwd: root,
  encoding: "utf8",
  windowsHide: true,
});
assert.equal(trackedRuntime.status, 0, trackedRuntime.stderr);
assert.equal(trackedRuntime.stdout.trim(), "", "generated Fabric identities or channel artifacts must not be tracked");

console.log("Fabric network definition verification passed: reviewed image digests, four independent Fabric CAs, isolated runtime identities, three peers/orderer, and two tenant-specific channel profiles are present.");
