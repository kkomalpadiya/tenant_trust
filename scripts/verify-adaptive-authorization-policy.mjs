import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  createOpaPolicyDecisionClient,
  hashPolicyInput,
} from "../apps/api/src/index.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const input = JSON.parse(readFileSync(
  new URL("../tests/fixtures/policy/slide14-profile-read.json", import.meta.url),
  "utf8",
));

const evaluation = spawnSync("docker", [
  "compose",
  "--env-file", ".env",
  "-f", "infra/compose/compose.yaml",
  "--profile", "tools",
  "run", "--rm", "--no-deps",
  "--entrypoint", "/opa",
  "opa-test",
  "eval",
  "--stdin-input",
  "--format", "json",
  "--data", "/policies",
  "data.tenant_trust.authorization.decision",
], {
  cwd: projectRoot,
  encoding: "utf8",
  input: JSON.stringify(input),
});

if (evaluation.error) throw evaluation.error;
assert.equal(evaluation.status, 0, evaluation.stderr || evaluation.stdout);

const document = JSON.parse(evaluation.stdout);
const decision = document.result?.[0]?.expressions?.[0]?.value;
assert.ok(decision, "OPA did not return an authorization decision");

const client = createOpaPolicyDecisionClient({
  baseUrl: "http://opa.verify.internal:8181",
  fetchImpl: async () => ({
    ok: true,
    json: async () => ({ result: decision }),
  }),
});
const validated = await client.decide(input);

assert.equal(validated.outcome, "ALLOW");
assert.deepEqual(validated.reasonCodes, ["POLICY_ALLOW"]);
assert.equal(validated.input.hashSha256, hashPolicyInput(input));
assert.equal(validated.policy.decisionPath, "tenant_trust/authorization/decision");
assert.equal(validated.state.trustUpdateVersion, input.trust.updateVersion);
assert.deepEqual(validated.obligations, { stepUp: null, quarantine: null });

console.log("PASS OPA evaluates the slide-14 profile-read boundary through the real decision entrypoint");
console.log("PASS the emitted decision satisfies the API output schema and every request/state binding");
console.log("PASS OPA and the API produce the same canonical SHA-256 input digest");
