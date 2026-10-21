import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const composeArgs = ["compose", "--env-file", ".env", "-f", "infra/fabric/compose.yaml"];
const action = process.argv[2];

if (!new Set(["up", "verify", "down", "status"]).has(action)) {
  console.error("Usage: node scripts/fabric-network.mjs <up|verify|down|status>");
  process.exit(2);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, ...(options.env ?? {}) },
    stdio: options.capture ? "pipe" : "inherit",
    timeout: options.timeout ?? 300_000,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    if (options.capture) {
      process.stderr.write(result.stdout ?? "");
      process.stderr.write(result.stderr ?? "");
    }
    throw result.error ?? new Error(`${command} ${args.join(" ")} exited with ${result.status}`);
  }
  return (result.stdout ?? "").trim();
}

function compose(...args) {
  return run("docker", [...composeArgs, ...args]);
}

function composeWithEnvironment(environment, ...args) {
  return run("docker", [...composeArgs, ...args], { env: environment });
}

function ensureRuntimeDirectories() {
  for (const relative of [
    "runtime/fabric/ca/orderer",
    "runtime/fabric/ca/platform",
    "runtime/fabric/ca/alpha",
    "runtime/fabric/ca/beta",
    "runtime/fabric/organizations",
    "runtime/fabric/channel-artifacts",
  ]) {
    mkdirSync(new URL(`../${relative}/`, import.meta.url), { recursive: true });
  }
}

function assertLocalSecrets() {
  const environment = readFileSync(new URL("../.env", import.meta.url), "utf8");
  const required = [
    "FABRIC_CA_ORDERER_ADMIN_PASSWORD",
    "FABRIC_CA_PLATFORM_ADMIN_PASSWORD",
    "FABRIC_CA_ALPHA_ADMIN_PASSWORD",
    "FABRIC_CA_BETA_ADMIN_PASSWORD",
    "FABRIC_ORDERER_SECRET",
    "FABRIC_PLATFORM_PEER_SECRET",
    "FABRIC_ALPHA_PEER_SECRET",
    "FABRIC_BETA_PEER_SECRET",
  ];
  for (const key of required) {
    const match = environment.match(new RegExp(`^${key}=(.+)$`, "mu"));
    if (!match || match[1].includes("replace-with")) throw new Error(`${key} is missing a generated local value; run npm run infra:init`);
  }
}

function showMemoryWarning() {
  const info = JSON.parse(run("docker", ["info", "--format", "{{json .}}"], { capture: true, timeout: 30_000 }));
  const gib = Number(info.MemTotal) / 1024 ** 3;
  if (gib < 5.5) {
    console.warn(`WARN Docker exposes ${gib.toFixed(1)} GiB; the established Fabric profile requires 5.5 GiB. This isolated start will be attempted, but increase WSL/Docker to 6 GB before combined core-plus-Fabric work.`);
  }
}

function verifyDefinition() {
  run(process.execPath, ["scripts/verify-fabric-network-definition.mjs"]);
  run(process.execPath, ["scripts/verify-fabric-topology.mjs"]);
}

function readChaincodePackageId() {
  const packageId = readFileSync(new URL("../runtime/fabric/chaincode/tenant-trust-audit.package-id", import.meta.url), "utf8").trim();
  if (!/^tenant-trust-audit_0\.1\.0:[0-9a-f]{64}$/u.test(packageId)) {
    throw new Error("The generated audit chaincode package ID is missing or malformed.");
  }
  return packageId;
}

function deployAuditChaincode() {
  compose("--profile", "tools", "run", "--rm", "chaincode-deploy");
  const packageId = readChaincodePackageId();
  const environment = { FABRIC_AUDIT_CHAINCODE_PACKAGE_ID: packageId };
  composeWithEnvironment(environment, "build", "audit-chaincode-platform");
  composeWithEnvironment(
    environment,
    "up", "-d", "--wait",
    "audit-chaincode-platform",
    "audit-chaincode-alpha",
    "audit-chaincode-beta",
  );
}

function verifyAuditChaincode() {
  const packageId = readChaincodePackageId();
  composeWithEnvironment(
    { FABRIC_AUDIT_CHAINCODE_PACKAGE_ID: packageId },
    "--profile", "tools", "run", "--rm", "chaincode-verify",
  );
}

try {
  if (action === "down") {
    compose("down", "--remove-orphans");
    console.log("Stopped the Fabric network while preserving CA identities, channel artifacts and ledger volumes.");
  } else if (action === "status") {
    compose("ps");
  } else if (action === "verify") {
    verifyDefinition();
    assertLocalSecrets();
    compose("--profile", "tools", "run", "--rm", "network-verify");
    verifyAuditChaincode();
  } else {
    verifyDefinition();
    showMemoryWarning();
    run(process.execPath, ["scripts/init-local-env.mjs"]);
    assertLocalSecrets();
    ensureRuntimeDirectories();
    compose("up", "-d", "--wait", "ca-orderer", "ca-platform", "ca-alpha", "ca-beta");
    compose("--profile", "tools", "run", "--rm", "ca-bootstrap");
    compose("up", "-d", "--wait", "orderer0.audit.tenant-trust.test", "peer0.platform.audit.tenant-trust.test", "peer0.alpha.audit.tenant-trust.test", "peer0.beta.audit.tenant-trust.test");
    compose("--profile", "tools", "run", "--rm", "channel-bootstrap");
    deployAuditChaincode();
    compose("--profile", "tools", "run", "--rm", "network-verify");
    verifyAuditChaincode();
    console.log("Tenant Trust Fabric network is running with both tenant audit channels joined.");
  }
} catch (error) {
  console.error(error.message);
  console.error("Inspect service state with npm run fabric:status and container logs with docker compose --env-file .env -f infra/fabric/compose.yaml logs.");
  process.exitCode = 1;
}
