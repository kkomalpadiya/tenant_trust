import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import {
  AUTHORIZATION_MODE_IDS,
  RESOURCE_SENSITIVITY,
  evaluateAuthorizationMode,
  selectAuthorizationMode,
} from "@tenant-trust/authorization";
import { buildAuditCommitment } from "@tenant-trust/contracts/audit-commitments";
import {
  EVALUATION_COMPARISON_SCOPE,
  EVALUATION_REFERENCE_HOST,
  EVALUATION_RESOURCES,
  EVALUATION_SAMPLE_PLAN,
  EVALUATION_SUBJECTS,
  EVALUATION_WORKLOAD,
  JWT_RBAC_BASELINE_MODE_ID,
  PERFORMANCE_REPORT_ID,
  createJwtRbacEvaluationBaseline,
  createJwtRbacEvaluationTokenIssuer,
  summarizeLatency,
  summarizeRate,
  summarizeRecovery,
  summarizeResourceUse,
  validatePerformanceCoverage,
} from "../packages/evaluation/src/index.mjs";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import { calculateWeightedTrustScore } from "../services/trust/src/index.mjs";
import { connectFabricAuditGatewayFromEnvironment } from "../apps/api/src/fabric-audit-gateway.mjs";
import { createOpaPolicyDecisionClient } from "../apps/api/src/policy-enforcement.mjs";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const WARMUP_REPETITIONS = EVALUATION_SAMPLE_PLAN.evaluation.warmupRepetitionsPerScenarioModeLoad;
const MEASURED_REPETITIONS = EVALUATION_SAMPLE_PLAN.evaluation.measuredRepetitionsPerScenarioModeLoad;
const CONCURRENCY_LEVELS = EVALUATION_SAMPLE_PLAN.evaluation.concurrencyLevels;
const LEDGER_WARMUPS = 5;
const LEDGER_MEASUREMENTS = 30;
const RECOVERY_REPETITIONS = 3;
const ALPHA_CHANNEL = "tt-audit-alpha-v1";
const FIXED_CAUSATION_ID = "evt_018f1234-5678-7abc-8def-0123456789dc";
const modeIds = EVALUATION_COMPARISON_SCOPE.modes.map(({ modeId }) => modeId);
const subjects = new Map(EVALUATION_SUBJECTS.map((subject) => [subject.subjectId, subject]));
const pkiMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
const adaptiveMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA);

function milliseconds(start, end = process.hrtime.bigint()) {
  return Number(end - start) / 1_000_000;
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function authorityFor(subject) {
  return {
    tenant: { tenantId: subject.tenantId, state: "active", version: 4 },
    subject: { subjectId: subject.subjectId, state: "active", version: 3 },
    membership: { tenantId: subject.tenantId, subjectId: subject.subjectId, state: "active", version: 6 },
    roles: [subject.role],
  };
}

function pkiAuthenticationFor(subject) {
  return {
    source: "mtls-certificate",
    authenticationId: `sha256:${sha256(subject.subjectId)}`,
    tenantId: subject.tenantId,
    subjectId: subject.subjectId,
  };
}

function scopeAllows(eligibility, context, resource) {
  if (eligibility.scope === "self" || eligibility.scope === "owner") {
    return resource.tenantId === context.tenantId && resource.ownerSubjectId === context.subjectId;
  }
  if (eligibility.scope === "tenant") return resource.tenantId === context.tenantId;
  return false;
}

function makePolicyInput(baseInput, workloadCase, subject, context, eligibility, score) {
  const resource = EVALUATION_RESOURCES[workloadCase.resourceKey];
  const requestUuid = randomUUID();
  const input = structuredClone(baseInput);
  input.identity.authenticationId = pkiAuthenticationFor(subject).authenticationId;
  input.identity.tenantId = subject.tenantId;
  input.identity.subjectId = subject.subjectId;
  input.tenantContext.tenantId = context.tenantId;
  input.tenantContext.subjectId = context.subjectId;
  input.tenantContext.roles = [...context.roles];
  input.tenantContext.versions = { ...context.versions };
  input.action = workloadCase.action;
  input.resource = {
    tenantId: resource.tenantId,
    resourceType: resource.resourceType,
    resourceIdHashSha256: sha256(resource.resourceId),
    sensitivity: RESOURCE_SENSITIVITY[workloadCase.action],
    scope: eligibility.scope,
    ownerSubjectId: resource.ownerSubjectId,
  };
  input.trust.tenantId = context.tenantId;
  input.trust.subjectId = context.subjectId;
  input.trust.policyScore = score;
  input.trust.lastKnownScore = score;
  input.trust.policyBand = score >= 75 ? "high" : score >= 50 ? "medium" : "low";
  input.trust.lastKnownBand = input.trust.policyBand;
  input.requestContext.requestId = `req_${requestUuid}`;
  input.requestContext.correlationId = `cor_${requestUuid}`;
  input.requestContext.method = new Set(["record:write", "record:export", "tenant:admin"]).has(workloadCase.action)
    ? "POST"
    : "GET";
  input.requestContext.routeTemplate = `/v1/evaluation/${workloadCase.action.replace(":", "-")}`;
  return input;
}

async function runBounded(items, concurrency, execute) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await execute(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

function createDecisionAdapters(baseInput) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const common = {
    keyId: "evaluation-performance-key-v1",
    issuer: "tenant-trust-evaluation",
    audience: "tenant-trust-api",
  };
  const issuer = createJwtRbacEvaluationTokenIssuer({ privateKey, ...common });
  const jwt = createJwtRbacEvaluationBaseline({ publicKey, ...common });
  const tokens = new Map(EVALUATION_SUBJECTS.map((subject) => [subject.subjectId, issuer.issue({
    tenantId: subject.tenantId,
    subjectId: subject.subjectId,
    roles: [subject.role],
  }).token]));
  const opa = createOpaPolicyDecisionClient({
    baseUrl: `http://127.0.0.1:${environment.OPA_HOST_PORT}`,
    timeoutMilliseconds: 1_500,
  });

  return Object.freeze({
    async execute(modeId, workloadCase) {
      const subject = subjects.get(workloadCase.actorSubjectId);
      const resource = EVALUATION_RESOURCES[workloadCase.resourceKey];
      const authority = authorityFor(subject);
      const totalStarted = process.hrtime.bigint();
      const authStarted = totalStarted;
      let authentication;
      let context;
      if (modeId === JWT_RBAC_BASELINE_MODE_ID) {
        authentication = jwt.authenticate(tokens.get(subject.subjectId));
      } else {
        context = resolveTenantContext({ authentication: pkiAuthenticationFor(subject), authority });
      }
      const authFinished = process.hrtime.bigint();

      let trustResult;
      const trustStarted = authFinished;
      if (modeId === AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA) {
        trustResult = calculateWeightedTrustScore({
          identity: 95,
          device: 92,
          behaviour: 90,
          certificate: 100,
          compliance: 94,
        });
      }
      const trustFinished = process.hrtime.bigint();

      const authorizationStarted = trustFinished;
      let outcome;
      if (modeId === JWT_RBAC_BASELINE_MODE_ID) {
        outcome = jwt.authorizeAuthenticated({
          authentication,
          authority,
          action: workloadCase.action,
          resource,
        }).outcome;
      } else if (modeId === AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE) {
        const decision = evaluateAuthorizationMode(pkiMode, context, workloadCase.action);
        outcome = decision.outcome === "deny" || !scopeAllows(decision.eligibility, context, resource) ? "deny" : "allow";
      } else {
        const eligibility = evaluateAuthorizationMode(adaptiveMode, context, workloadCase.action).eligibility;
        outcome = (await opa.decide(makePolicyInput(
          baseInput,
          workloadCase,
          subject,
          context,
          eligibility,
          trustResult.score,
        ))).outcome.toLowerCase();
      }
      assert.ok(["allow", "deny", "step_up", "quarantine"].includes(outcome));
      const finished = process.hrtime.bigint();
      return {
        authenticationMilliseconds: milliseconds(authStarted, authFinished),
        trustMilliseconds: modeId === AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA
          ? milliseconds(trustStarted, trustFinished)
          : null,
        authorizationMilliseconds: milliseconds(authorizationStarted, finished),
        endToEndMilliseconds: milliseconds(totalStarted, finished),
      };
    },
  });
}

async function measureDecisionBlocks() {
  const baseInput = JSON.parse(await readFile(
    new URL("../tests/fixtures/policy/slide14-profile-read.json", import.meta.url),
    "utf8",
  ));
  const adapters = createDecisionAdapters(baseInput);
  const blocks = [];
  for (let loadIndex = 0; loadIndex < CONCURRENCY_LEVELS.length; loadIndex += 1) {
    const concurrency = CONCURRENCY_LEVELS[loadIndex];
    const order = EVALUATION_SAMPLE_PLAN.evaluation.modeOrderRotation[loadIndex];
    for (const modeId of order) {
      for (let repetition = 0; repetition < WARMUP_REPETITIONS; repetition += 1) {
        await runBounded(EVALUATION_WORKLOAD, concurrency, (entry) => adapters.execute(modeId, entry));
      }

      const observations = [];
      const rates = [];
      const rssStartBytes = process.memoryUsage().rss;
      let rssPeakBytes = rssStartBytes;
      const sampler = setInterval(() => {
        rssPeakBytes = Math.max(rssPeakBytes, process.memoryUsage().rss);
      }, 5);
      sampler.unref?.();
      const cpuStart = process.cpuUsage();
      for (let repetition = 0; repetition < MEASURED_REPETITIONS; repetition += 1) {
        const repetitionStarted = process.hrtime.bigint();
        observations.push(...await runBounded(
          EVALUATION_WORKLOAD,
          concurrency,
          (entry) => adapters.execute(modeId, entry),
        ));
        const elapsedSeconds = milliseconds(repetitionStarted) / 1_000;
        rates.push(EVALUATION_WORKLOAD.length / elapsedSeconds);
      }
      const cpu = process.cpuUsage(cpuStart);
      clearInterval(sampler);
      const rssEndBytes = process.memoryUsage().rss;
      rssPeakBytes = Math.max(rssPeakBytes, rssEndBytes);
      blocks.push({
        modeId,
        concurrency,
        warmupDecisionCount: WARMUP_REPETITIONS * EVALUATION_WORKLOAD.length,
        measuredDecisionCount: observations.length,
        latencyMilliseconds: {
          authentication: summarizeLatency(observations.map((entry) => entry.authenticationMilliseconds)),
          trustComputation: modeId === AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA
            ? summarizeLatency(observations.map((entry) => entry.trustMilliseconds))
            : null,
          authorization: summarizeLatency(observations.map((entry) => entry.authorizationMilliseconds)),
          endToEnd: summarizeLatency(observations.map((entry) => entry.endToEndMilliseconds)),
        },
        throughputRequestsPerSecond: summarizeRate(rates),
        resources: summarizeResourceUse({
          cpuMicroseconds: cpu.user + cpu.system,
          decisionCount: observations.length,
          rssStartBytes,
          rssEndBytes,
          rssPeakBytes,
        }),
      });
    }
  }
  validatePerformanceCoverage(blocks, {
    modeIds,
    concurrencyLevels: CONCURRENCY_LEVELS,
    measuredDecisionsPerBlock: MEASURED_REPETITIONS * EVALUATION_WORKLOAD.length,
  });
  return blocks;
}

function accessDecisionEvent(index, sampleKind) {
  const now = new Date();
  const eventId = `evt_${randomUUID()}`;
  const decisionId = `dec_${randomUUID()}`;
  return {
    schemaVersion: "1.0.0",
    eventId,
    eventType: "access.decided.v1",
    tenantId: EVALUATION_SUBJECTS[0].tenantId,
    subjectId: EVALUATION_SUBJECTS[0].subjectId,
    aggregateId: decisionId,
    correlationId: `cor_${randomUUID()}`,
    causationId: FIXED_CAUSATION_ID,
    idempotencyKey: `performance-ledger:${sampleKind}:${index}:${decisionId}`,
    occurredAt: now.toISOString(),
    recordedAt: new Date(now.getTime() + 1).toISOString(),
    producer: { service: "evaluation", instanceId: "performance-recovery-measurer" },
    payload: {
      decisionId,
      requestId: `req_${randomUUID()}`,
      certificateId: "crt_018f1234-5678-7abc-8def-0123456789d1",
      trustTransitionId: "trn_018f1234-5678-7abc-8def-0123456789d4",
      trustScore: 94,
      policyVersionId: "pol_018f1234-5678-7abc-8def-0123456789d5",
      operation: "profile:read",
      resourceType: "subject-profile",
      resourceIdHashSha256: sha256(`${sampleKind}:${index}:${decisionId}`),
      outcome: "ALLOW",
      reasonCodes: ["POLICY_ALLOW"],
      stepUpProofIdHashSha256: null,
    },
  };
}

async function measureLedgerCommitDelay() {
  const gateway = await connectFabricAuditGatewayFromEnvironment({
    environment: { ...process.env, ...environment },
    repositoryRoot,
  });
  const samples = [];
  try {
    for (let index = 0; index < LEDGER_WARMUPS + LEDGER_MEASUREMENTS; index += 1) {
      const sampleKind = index < LEDGER_WARMUPS ? "warmup" : "measured";
      const commitment = buildAuditCommitment({
        channelName: ALPHA_CHANNEL,
        event: accessDecisionEvent(index, sampleKind),
      });
      const started = process.hrtime.bigint();
      const submission = await gateway.submitCommitment({
        tenantId: EVALUATION_SUBJECTS[0].tenantId,
        ledgerValue: commitment.ledgerValue,
      });
      const status = await submission.waitForCommit();
      assert.equal(status.successful, true);
      if (sampleKind === "measured") samples.push(milliseconds(started));
    }
  } finally {
    gateway.close();
  }
  return {
    warmupCount: LEDGER_WARMUPS,
    measuredCount: LEDGER_MEASUREMENTS,
    latencyMilliseconds: summarizeLatency(samples),
    definition: "Gateway submit start through successful Fabric commit status; excluded from request decision latency.",
  };
}

function measureOutageRecovery() {
  const samples = [];
  for (let repetition = 0; repetition < RECOVERY_REPETITIONS; repetition += 1) {
    const result = spawnSync(process.execPath, ["scripts/verify-fabric-outage-recovery.mjs"], {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: process.env,
      maxBuffer: 16 * 1024 * 1024,
      timeout: 180_000,
    });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`Outage recovery repetition ${repetition + 1} failed:\n${result.stderr || result.stdout}`);
    const match = /MEASURE fabric-outage-recovery-time-ms ([0-9.]+)/u.exec(result.stdout);
    if (!match) throw new Error("Outage recovery verifier did not emit its recovery measurement.");
    samples.push(Number(match[1]));
  }
  return {
    repetitions: RECOVERY_REPETITIONS,
    recoveryTimeMilliseconds: summarizeRecovery(samples),
    definition: "Alpha peer restart command through healthy state, exact outbox retry and successful ledger commit.",
    authorizationContinuityVerified: true,
    gapFreeReconciliationVerified: true,
  };
}

const decisionBlocks = await measureDecisionBlocks();
const ledger = await measureLedgerCommitDelay();
const outageRecovery = measureOutageRecovery();
const report = {
  reportId: PERFORMANCE_REPORT_ID,
  generatedAt: new Date().toISOString(),
  protocolId: "tenant-trust-evaluation-protocol-v1",
  workloadId: EVALUATION_COMPARISON_SCOPE.workloadId,
  referenceHost: EVALUATION_REFERENCE_HOST,
  samplePlan: {
    modes: modeIds,
    concurrencyLevels: CONCURRENCY_LEVELS,
    warmupRepetitionsPerModeLoad: WARMUP_REPETITIONS,
    measuredRepetitionsPerModeLoad: MEASURED_REPETITIONS,
    workloadCasesPerRepetition: EVALUATION_WORKLOAD.length,
    totalMeasuredAuthorizationDecisions: decisionBlocks.reduce((total, block) => total + block.measuredDecisionCount, 0),
  },
  decisionBlocks,
  ledger,
  outageRecovery,
  resourceScope: "CPU and RSS cover the Node.js measurement process; OPA, Docker and Fabric container CPU/RSS are excluded.",
  limitations: [
    "PKI authentication measures validation of the already trusted mTLS adapter result and tenant context, not TLS handshake or certificate-chain verification at the reverse proxy.",
    "The proposed authorization stage includes schema validation, loopback HTTP and live OPA evaluation; trust computation is reported separately.",
    "Concurrency 32 is a cap; one 14-case replay therefore has at most 14 simultaneous requests.",
    "Results describe this single-host prototype run and are not production service-level objectives.",
  ],
};

console.log(JSON.stringify(report, null, 2));
