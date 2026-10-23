import { createHash, randomUUID } from "node:crypto";
import { assertNoTenantSwitch, TenantContextError } from "@tenant-trust/tenant-context";

const AUTHORIZATION_ID = /^rca_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ACTION_ID = /^act_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DECISION_ID = /^dec_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const REQUEST_ID = /^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CERTIFICATE_ID = /^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TRANSITION_ID = /^trn_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDEMPOTENCY_KEY = /^[a-z0-9][a-z0-9._:/-]{7,159}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const EXTERNAL_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$/u;
const RECOVERY_ACTIONS = new Set(["restore-access", "issue-replacement-certificate"]);
const REQUEST_KEYS = new Set([
  "causeResolutionReference",
  "idempotencyKey",
  "requestId",
  "sessionIdHashSha256",
  "stepUpProofIdHashSha256",
  "targetCertificateId",
  "targetSubjectId",
]);
const SQL = Object.freeze({
  loadContext: "SELECT * FROM orchestration.get_security_recovery_context($1,$2)",
  authorize: "SELECT * FROM orchestration.authorize_security_recovery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
});

export const GOVERNED_RECOVERY_POLICY = Object.freeze({
  authorizedRole: "tenant-admin",
  stepUpAction: "tenant:admin",
  authorizationLifetimeSeconds: 300,
  currentTrustMaximumAgeSeconds: 300,
  idempotencyScope: "tenant-actor-recovery-request",
  replacementRule: "fresh-distinct-certificate-only",
  targetCertificateReactivationAllowed: false,
});

export class GovernedRecoveryError extends Error {
  constructor(reasonCode, options) {
    super("The governed recovery request was denied.", options);
    this.name = "GovernedRecoveryError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new GovernedRecoveryError(reasonCode, cause === undefined ? undefined : { cause });
}

function exactObject(value, keys) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function iso(value, reasonCode = "RECOVERY_TIME_INVALID") {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) fail(reasonCode);
  return date.toISOString();
}

function generated(prefix, pattern, idFactory) {
  const value = `${prefix}_${idFactory()}`;
  if (!pattern.test(value)) fail("RECOVERY_GENERATED_ID_INVALID");
  return value;
}

function trustedAdminContext(context) {
  let trusted;
  try {
    trusted = assertNoTenantSwitch(context, []);
  } catch (error) {
    if (error instanceof TenantContextError) fail("RECOVERY_TENANT_CONTEXT_INVALID", error);
    throw error;
  }
  if (!trusted.roles.includes(GOVERNED_RECOVERY_POLICY.authorizedRole)) {
    fail("RECOVERY_TENANT_ADMIN_REQUIRED");
  }
  return trusted;
}

function normalizeRequest(request) {
  if (!exactObject(request, REQUEST_KEYS)
    || !REQUEST_ID.test(request.requestId ?? "")
    || !IDEMPOTENCY_KEY.test(request.idempotencyKey ?? "")
    || !SUBJECT_ID.test(request.targetSubjectId ?? "")
    || !CERTIFICATE_ID.test(request.targetCertificateId ?? "")
    || !SHA256.test(request.stepUpProofIdHashSha256 ?? "")
    || !SHA256.test(request.sessionIdHashSha256 ?? "")
    || (request.causeResolutionReference !== null
      && !EXTERNAL_REFERENCE.test(request.causeResolutionReference ?? ""))) {
    fail("RECOVERY_REQUEST_INVALID");
  }
  return Object.freeze({ ...request });
}

function validateLoadedContext(value, target) {
  if (!value || value.tenantId !== target.tenantId
    || value.targetSubjectId !== target.subjectId
    || value.targetCertificateId !== target.certificateId
    || !TRANSITION_ID.test(value.trustTransitionId ?? "")
    || !Number.isSafeInteger(value.stateVersion)
    || value.stateVersion < 1
    || !value.currentState
    || !value.checkpoint
    || !Array.isArray(value.activeSevereEvidence)) {
    fail("RECOVERY_CONTEXT_INVALID");
  }
  return value;
}

function eligibilityHash({ target, context, evaluation, causeResolutionReference }) {
  const document = {
    schemaVersion: "1.0.0",
    tenantId: target.tenantId,
    targetSubjectId: target.subjectId,
    targetCertificateId: target.certificateId,
    trustTransitionId: context.trustTransitionId,
    stateVersion: context.stateVersion,
    currentState: context.currentState,
    checkpoint: evaluation.checkpoint,
    activeSevereEvidenceIds: context.activeSevereEvidence
      .map(({ evidenceId }) => evidenceId)
      .sort(),
    actionType: evaluation.nextActionType,
    reasonCode: evaluation.reasonCode,
    causeResolutionReference,
    targetCertificateReactivated: false,
  };
  return createHash("sha256").update(JSON.stringify(document), "utf8").digest("hex");
}

function mapAuthorization(row) {
  const result = Object.freeze({
    tenantId: row?.tenant_id,
    authorizationId: row?.authorization_id,
    actionId: row?.action_id,
    actionType: row?.action_type,
    status: row?.status,
    authorizedAt: row?.authorized_at ? iso(row.authorized_at) : null,
    expiresAt: row?.expires_at ? iso(row.expires_at) : null,
  });
  if (!TENANT_ID.test(result.tenantId ?? "")
    || !AUTHORIZATION_ID.test(result.authorizationId ?? "")
    || !ACTION_ID.test(result.actionId ?? "")
    || !RECOVERY_ACTIONS.has(result.actionType)
    || !["pending", "failed", "executing", "succeeded"].includes(result.status)
    || result.authorizedAt === null
    || result.expiresAt === null) {
    fail("RECOVERY_AUTHORIZATION_CONFIRMATION_INVALID");
  }
  return result;
}

export function createPostgresGovernedRecoveryRepository({
  query,
  loadActiveSevereEvidence,
} = {}) {
  if (typeof query !== "function" || typeof loadActiveSevereEvidence !== "function") {
    throw new TypeError("A PostgreSQL query function and active severe-evidence loader are required.");
  }
  return Object.freeze({
    async loadRecoveryContext({ tenantId, targetSubjectId, targetCertificateId, evaluatedAt }, options = {}) {
      if (!TENANT_ID.test(tenantId ?? "")
        || !SUBJECT_ID.test(targetSubjectId ?? "")
        || !CERTIFICATE_ID.test(targetCertificateId ?? "")) {
        fail("RECOVERY_TARGET_INVALID");
      }
      const result = await query(SQL.loadContext, [targetSubjectId, targetCertificateId], options);
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
        fail("RECOVERY_CONTEXT_UNAVAILABLE");
      }
      const row = result.rows[0];
      const activeSevereEvidence = await loadActiveSevereEvidence({
        tenantId,
        subjectId: targetSubjectId,
        evaluatedAt,
      }, options);
      if (!Array.isArray(activeSevereEvidence)) fail("RECOVERY_EVIDENCE_INVALID");
      return Object.freeze({
        tenantId: row.tenant_id,
        targetSubjectId: row.target_subject_id,
        targetCertificateId: row.target_certificate_id,
        stateVersion: Number(row.state_version),
        trustTransitionId: row.trust_transition_id,
        currentState: Object.freeze({
          access: row.access_state,
          renewal: row.renewal_state,
          targetCertificate: row.target_certificate_state,
          replacement: row.replacement_state,
        }),
        checkpoint: Object.freeze({
          score: Number(row.score),
          band: row.band,
          transition: row.transition,
          consecutiveQualifyingEvaluations: Number(row.consecutive_qualifying_evaluations),
          sourceIds: Object.freeze([...(row.source_ids ?? [])]),
        }),
        activeSevereEvidence: Object.freeze(activeSevereEvidence.map((entry) => Object.freeze({ ...entry }))),
      });
    },

    async authorizeRecoveryAction(value, options = {}) {
      const result = await query(SQL.authorize, [
        value.authorizationId,
        value.actionId,
        value.decisionId,
        value.requestId,
        value.correlationId,
        value.idempotencyKey,
        value.targetSubjectId,
        value.targetCertificateId,
        value.actionType,
        value.trustTransitionId,
        value.expectedStateVersion,
        value.reasonCode,
        value.eligibilityHashSha256,
        value.stepUpProofIdHashSha256,
        value.sessionIdHashSha256,
        value.causeResolutionReference,
        value.authorizedAt,
      ], options);
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
        fail("RECOVERY_AUTHORIZATION_CONFIRMATION_INVALID");
      }
      return mapAuthorization(result.rows[0]);
    },
  });
}

export function createGovernedRecoveryService({
  repository,
  evaluateRecovery,
  idFactory = randomUUID,
  clock = () => new Date(),
} = {}) {
  if (!repository
    || typeof repository.loadRecoveryContext !== "function"
    || typeof repository.authorizeRecoveryAction !== "function"
    || typeof evaluateRecovery !== "function"
    || typeof idFactory !== "function"
    || typeof clock !== "function") {
    throw new TypeError("A recovery repository, evaluator, ID factory and clock are required.");
  }
  return Object.freeze({
    async authorize({ context, request }, options = {}) {
      const actor = trustedAdminContext(context);
      const normalized = normalizeRequest(request);
      const evaluatedAt = iso(clock());
      const target = Object.freeze({
        tenantId: actor.tenantId,
        subjectId: normalized.targetSubjectId,
        certificateId: normalized.targetCertificateId,
      });
      const loaded = validateLoadedContext(await repository.loadRecoveryContext({
        tenantId: target.tenantId,
        targetSubjectId: target.subjectId,
        targetCertificateId: target.certificateId,
        evaluatedAt,
      }, options), target);
      const evaluation = evaluateRecovery({
        target: { tenantId: target.tenantId, subjectId: target.subjectId },
        currentState: loaded.currentState,
        checkpoint: loaded.checkpoint,
        activeSevereEvidence: loaded.activeSevereEvidence,
        evaluatedAt,
        severeCauseResolved: normalized.causeResolutionReference !== null,
      });
      if (!evaluation.eligible || !RECOVERY_ACTIONS.has(evaluation.nextActionType)) {
        fail(evaluation.reasonCode ?? "RECOVERY_NOT_ELIGIBLE");
      }
      if (loaded.currentState.targetCertificate === "revoked"
        && normalized.causeResolutionReference === null) {
        fail("SEVERE_CAUSE_UNRESOLVED");
      }
      const authorization = await repository.authorizeRecoveryAction({
        authorizationId: generated("rca", AUTHORIZATION_ID, idFactory),
        actionId: generated("act", ACTION_ID, idFactory),
        decisionId: generated("dec", DECISION_ID, idFactory),
        correlationId: generated("cor", CORRELATION_ID, idFactory),
        requestId: normalized.requestId,
        idempotencyKey: normalized.idempotencyKey,
        targetSubjectId: target.subjectId,
        targetCertificateId: target.certificateId,
        actionType: evaluation.nextActionType,
        trustTransitionId: loaded.trustTransitionId,
        expectedStateVersion: loaded.stateVersion,
        reasonCode: evaluation.reasonCode,
        eligibilityHashSha256: eligibilityHash({
          target,
          context: loaded,
          evaluation,
          causeResolutionReference: normalized.causeResolutionReference,
        }),
        stepUpProofIdHashSha256: normalized.stepUpProofIdHashSha256,
        sessionIdHashSha256: normalized.sessionIdHashSha256,
        causeResolutionReference: normalized.causeResolutionReference,
        authorizedAt: evaluatedAt,
      }, options);
      if (authorization.tenantId !== actor.tenantId
        || authorization.actionType !== evaluation.nextActionType) {
        fail("RECOVERY_AUTHORIZATION_CONFIRMATION_INVALID");
      }
      return Object.freeze({
        ...authorization,
        reasonCode: evaluation.reasonCode,
        targetCertificateReactivated: false,
      });
    },
  });
}
