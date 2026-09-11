import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

function compose(args, label) {
  const result = spawnSync("docker", [...composeArgs, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout).trim();
    throw new Error(`${label} failed${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout.trim();
}

const health = compose([
  "exec", "-T", "step-ca", "step", "ca", "health",
  "--ca-url", "https://localhost:9000",
  "--root", "/home/step/certs/root_ca.crt",
], "step-ca health check");
assert.equal(health, "ok");
console.log("PASS step-ca reports healthy over its trusted TLS endpoint");

const rootPem = compose(
  ["exec", "-T", "step-ca", "cat", "/home/step/certs/root_ca.crt"],
  "read local root certificate",
);
const intermediatePem = compose(
  ["exec", "-T", "step-ca", "cat", "/home/step/certs/intermediate_ca.crt"],
  "read local intermediate certificate",
);
const root = new X509Certificate(rootPem);
const intermediate = new X509Certificate(intermediatePem);
assert.equal(root.ca, true);
assert.equal(intermediate.ca, true);
assert.equal(root.subject, root.issuer);
assert.equal(intermediate.issuer, root.subject);
assert.equal(intermediate.verify(root.publicKey), true);
assert.notEqual(intermediate.fingerprint256, root.fingerprint256);
console.log("PASS the online intermediate has a distinct key and verifies under the local root");

const issuance = compose(
  ["exec", "-T", "step-ca", "/bin/sh", "/scripts/verify-issuance.sh"],
  "temporary certificate issuance",
);
assert.match(issuance, /Issued and verified a temporary certificate/u);
console.log("PASS step-ca issued and verified a temporary certificate without retaining its private key");

const opaBaseUrl = `http://127.0.0.1:${environment.OPA_HOST_PORT}`;
const opaHealth = await fetch(`${opaBaseUrl}/health`);
assert.equal(opaHealth.status, 200);
assert.deepEqual(await opaHealth.json(), {});
console.log("PASS OPA reports healthy");

const policyResponse = await fetch(`${opaBaseUrl}/v1/data/tenant_trust/bootstrap/service`);
assert.equal(policyResponse.status, 200);
const policyResult = await policyResponse.json();
assert.deepEqual(policyResult.result, { ready: true, policy_api_version: "v1" });
console.log("PASS OPA loaded and evaluated the repository bootstrap policy");
