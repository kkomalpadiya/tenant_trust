import { spawnSync } from "node:child_process";
import { composeArgs, repositoryRoot } from "./lib/foundation-context.mjs";

const childEnvironment = { ...process.env };
const services = ["postgres", "redis", "nats", "step-ca", "opa"];

function run(command, args, label, { quiet = false, shell = false } = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: childEnvironment,
    maxBuffer: 16 * 1024 * 1024,
    shell,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
  if (!quiet) {
    if (result.stdout.trim()) console.log(result.stdout.trim());
    if (result.stderr.trim()) console.error(result.stderr.trim());
  }
}

function runNpm(args, label) {
  if (process.env.npm_execpath) {
    run(process.execPath, [process.env.npm_execpath, ...args], label);
  } else {
    run("npm", args, label, { shell: process.platform === "win32" });
  }
}

function compose(args, label, options) {
  run("docker", [...composeArgs, ...args], label, options);
}

async function waitForHealthy(service, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  let lastState = "container not created";
  while (Date.now() < deadline) {
    const container = spawnSync("docker", [...composeArgs, "ps", "-q", service], {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: childEnvironment,
    });
    const containerId = container.stdout.trim();
    if (container.status === 0 && containerId) {
      const state = spawnSync("docker", [
        "inspect",
        "--format",
        "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
        containerId,
      ], { encoding: "utf8" });
      lastState = state.stdout.trim() || state.stderr.trim();
      if (state.status === 0 && lastState === "healthy") {
        console.log(`PASS ${service} is healthy`);
        return;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error(`${service} did not become healthy within ${timeoutMs / 1_000} seconds; last state: ${lastState}`);
}

run(process.execPath, ["scripts/check-environment.mjs", "--profile=core"], "core environment check");
compose(["config", "--quiet"], "Compose configuration validation", { quiet: true });
console.log("PASS Compose configuration is valid");

for (const service of services) await waitForHealthy(service);

runNpm(["test"], "repository tests");
run(process.execPath, ["scripts/verify-tenant-isolation-phase.mjs"], "tenant isolation phase verification");
compose(["--profile", "tools", "run", "--rm", "opa-test"], "OPA policy tests");
run(process.execPath, ["scripts/check-core-services.mjs"], "core service checks");
run(process.execPath, ["scripts/verify-event-delivery.mjs"], "event delivery verification");
run(process.execPath, ["scripts/verify-security-services.mjs"], "security service verification");
runNpm(["audit", "--audit-level=high"], "dependency audit");

console.log("Foundation verification passed.");
