import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { buildTrustTransitionExplanation } from "@tenant-trust/trust";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

const schemasRoot = resolve(repositoryRoot, "packages/contracts/schemas");
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(JSON.parse(readFileSync(resolve(schemasRoot, "common.schema.json"), "utf8")));
const validateTrustEvent = ajv.compile(
  JSON.parse(readFileSync(resolve(schemasRoot, "events/trust-event.schema.json"), "utf8")),
);

const components = [
  ["identity", 80, 0.20],
  ["device", 60, 0.25],
  ["behaviour", 70, 0.25],
  ["certificate", 100, 0.15],
  ["compliance", 90, 0.15],
];
const evidenceReferences = components.map(([evidenceType], index) => {
  const suffix = String(index + 1).padStart(12, "0");
  return {
    evidenceType,
    evidenceId: `evd_018f1234-5678-7abc-8def-${suffix}`,
    sourceEventId: `evt_018f1234-5678-7abc-8def-${suffix}`,
  };
});
const explanation = buildTrustTransitionExplanation({
  transitionId: "trn_018f1234-5678-7abc-8def-0123456789f0",
  eventId: "evt_018f1234-5678-7abc-8def-0123456789f0",
  producer: { service: "trust-engine", instanceId: "verification-1" },
  evaluatedAt: "2026-10-12T08:00:01.000Z",
  input: {
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
    updateVersion: 1,
    correlationId: "cor_018f1234-5678-7abc-8def-0123456789f0",
    causationId: evidenceReferences[4].sourceEventId,
    components: Object.fromEntries(components.map(([id, value]) => [id, value])),
    evidenceReferences,
    configuration: {
      configurationVersion: 1,
      modelVersion: "1.0.0",
      initialScore: 60,
      smoothingAlpha: 0.5,
      staleAfterSeconds: 3600,
      weights: Object.fromEntries(components.map(([id, , weight]) => [id, weight])),
    },
    observedAt: "2026-10-12T08:00:00.000Z",
    source: {
      sourceId: "src_018f1234-5678-7abc-8def-0123456789ab",
      maximumInfluence: 0.25,
      corroboratingSourceIds: [],
    },
    criticalEvidence: null,
  },
  previousTransition: null,
});

assert.equal(
  validateTrustEvent(explanation.event),
  true,
  `generated trust event violates its contract: ${ajv.errorsText(validateTrustEvent.errors)}`,
);
console.log("PASS generated trust.updated.v1 event matches the shared contract");

const stateFixture = readFileSync(
  resolve(repositoryRoot, "database/tests/verify-trust-state-storage.sql"),
  "utf8",
);
const transitionVerification = readFileSync(
  resolve(repositoryRoot, "database/tests/verify-trust-transition-explanations.sql"),
  "utf8",
);
const rollbackMarker = "\nROLLBACK;";
assert.equal(stateFixture.lastIndexOf(rollbackMarker) >= 0, true, "trust-state fixture rollback marker is missing");
const verificationSql = stateFixture.replace(
  rollbackMarker,
  `\n${transitionVerification}\nROLLBACK;`,
);

const result = spawnSync(
  "docker",
  [
    ...composeArgs,
    "exec",
    "-T",
    "postgres",
    "psql",
    "-X",
    "-v",
    "ON_ERROR_STOP=1",
    "-U",
    environment.POSTGRES_USER,
    "-d",
    environment.POSTGRES_DB,
  ],
  {
    cwd: repositoryRoot,
    encoding: "utf8",
    input: verificationSql,
    maxBuffer: 4 * 1024 * 1024,
  },
);

if (result.status !== 0) {
  const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
  throw new Error(`Trust-transition explanation verification failed${detail ? `:\n${detail}` : ""}`);
}

if (result.stdout.trim()) console.log(result.stdout.trim());
if (result.stderr.trim()) console.error(result.stderr.trim());
console.log("Trust-transition explanation verification passed without retaining test changes.");
