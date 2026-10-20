import { randomUUID } from "node:crypto";
import {
  AUTHORIZATION_MODE_IDS,
  AuthorizationError,
  assertAuthorizationMode,
  evaluateAuthorizationMode,
} from "@tenant-trust/authorization";
import { TenantContextError, resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  REQUEST_STATE_POLICY,
  assertPresentedCertificate,
  createRequestStateRevalidator,
} from "./request-state.mjs";
import {
  IdempotencyConflictError,
  REQUEST_SAFEGUARD_POLICY,
  RequestTimeoutError,
  hashSensitiveIdempotencyKey,
  hashSensitiveRequest,
  normalizeSensitiveIdempotencyKey,
} from "./request-safeguards.mjs";
import {
  POLICY_ENFORCEMENT_POLICY,
  assertPolicyEnforcementService,
} from "./policy-enforcement.mjs";
import {
  STEP_UP_POLICY,
  StepUpAuthenticationError,
  createStepUpChallengeMaterial,
  createStepUpProofMaterial,
  hashStepUpValue,
  normalizeStepUpPresentation,
  verifyStepUpChallengeSignature,
} from "./step-up-authentication.mjs";

const RESOURCE_ID = /^res_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const OPERATION_ID = /^op_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SECURITY_ACTION_ID = /^act_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_EXPORT_RECORDS = 25;

export class AccessDeniedError extends Error {
  constructor() {
    super("Access denied.");
    this.name = "AccessDeniedError";
  }
}

export class QuarantineEnforcedError extends AccessDeniedError {
  constructor() {
    super();
    this.name = "QuarantineEnforcedError";
  }
}

function asSafeVersion(value) {
  const version = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(version) && version > 0 ? version : value;
}

function asIsoTimestamp(value) {
  const timestamp = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(timestamp.getTime())) throw new TypeError("Database returned an invalid timestamp.");
  return timestamp.toISOString();
}

function mapAuthority(row) {
  return {
    tenant: {
      tenantId: row.tenant_id,
      state: row.tenant_state,
      version: asSafeVersion(row.tenant_version),
    },
    subject: {
      subjectId: row.subject_id,
      state: row.subject_state,
      version: asSafeVersion(row.subject_version),
    },
    membership: {
      tenantId: row.tenant_id,
      subjectId: row.subject_id,
      state: row.membership_state,
      version: asSafeVersion(row.membership_version),
    },
    roles: row.roles,
  };
}

function mapRecord(row) {
  return Object.freeze({
    recordId: row.resource_id,
    ownerSubjectId: row.owner_subject_id,
    name: row.resource_name,
    version: asSafeVersion(row.version),
    createdAt: asIsoTimestamp(row.created_at),
    updatedAt: asIsoTimestamp(row.updated_at),
  });
}

function defaultOperationIdFactory() {
  return `op_${randomUUID()}`;
}

function defaultSecurityActionIdFactory() {
  return `act_${randomUUID()}`;
}

async function defaultSensitiveOperationAuthorizer() {
  throw new AccessDeniedError();
}

function normalizeRecordIds(recordIds) {
  if (!Array.isArray(recordIds)
    || recordIds.length < 1
    || recordIds.length > MAX_EXPORT_RECORDS
    || recordIds.some((recordId) => !RESOURCE_ID.test(recordId ?? ""))
    || new Set(recordIds).size !== recordIds.length) {
    throw new TypeError("A bounded list of unique record IDs is required.");
  }
  return Object.freeze([...recordIds]);
}

function createOperationId(operationIdFactory) {
  const operationId = operationIdFactory();
  if (!OPERATION_ID.test(operationId ?? "")) {
    throw new TypeError("The operation ID factory returned an invalid ID.");
  }
  return operationId;
}

function createSecurityActionId(securityActionIdFactory) {
  const actionId = securityActionIdFactory();
  if (!SECURITY_ACTION_ID.test(actionId ?? "")) {
    throw new TypeError("The security action ID factory returned an invalid ID.");
  }
  return actionId;
}

function operationMetadata(context, operationId, action, replayed, attributes = {}) {
  return Object.freeze({
    operationId,
    action,
    tenantId: context.tenantId,
    requestedBy: context.subjectId,
    idempotentReplay: replayed,
    ...attributes,
  });
}

function assertCertificateAuthentication(authentication) {
  if (!authentication
    || typeof authentication !== "object"
    || Array.isArray(authentication)
    || authentication.source !== "mtls-certificate"
    || typeof authentication.authenticationId !== "string"
    || authentication.authenticationId.length < 1
    || authentication.authenticationId.length > 255
    || !TENANT_ID.test(authentication.tenantId ?? "")
    || !SUBJECT_ID.test(authentication.subjectId ?? "")) {
    throw new AccessDeniedError();
  }
  assertPresentedCertificate(authentication);
}

async function rollbackQuietly(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // The original failure remains authoritative and is mapped by the API boundary.
  }
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw new RequestTimeoutError();
}

function isTimeoutError(error, signal) {
  return signal?.aborted
    || error?.code === "57014"
    || error?.code === "ABORT_ERR"
    || error?.name === "AbortError";
}

export function createPostgresTenantRepository({
  pool,
  authorizationMode,
  policyEnforcementService,
  contextResolver = resolveTenantContext,
  sensitiveOperationAuthorizer = defaultSensitiveOperationAuthorizer,
  operationIdFactory = defaultOperationIdFactory,
  securityActionIdFactory = defaultSecurityActionIdFactory,
  clock = () => new Date(),
} = {}) {
  if (!pool || typeof pool.connect !== "function") throw new TypeError("A PostgreSQL pool is required.");
  let selectedAuthorizationMode;
  try {
    selectedAuthorizationMode = assertAuthorizationMode(authorizationMode);
  } catch (error) {
    if (!(error instanceof AuthorizationError)) throw error;
    throw new TypeError("An explicit supported authorization mode is required.");
  }
  const policyModeSelected = selectedAuthorizationMode.modeId === AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA;
  if (policyModeSelected) {
    assertPolicyEnforcementService(policyEnforcementService);
  } else if (policyEnforcementService !== undefined) {
    throw new TypeError("Policy enforcement is only valid in adaptive authorization mode.");
  }
  if (typeof contextResolver !== "function") throw new TypeError("A tenant context resolver is required.");
  if (typeof sensitiveOperationAuthorizer !== "function") {
    throw new TypeError("A sensitive operation authorizer must be a function.");
  }
  if (typeof operationIdFactory !== "function") throw new TypeError("An operation ID factory is required.");
  if (typeof securityActionIdFactory !== "function") {
    throw new TypeError("A security action ID factory is required.");
  }
  if (typeof clock !== "function") throw new TypeError("A trusted request-state clock is required.");
  const requestStateRevalidator = createRequestStateRevalidator({ clock });

  function evaluateOperation(context, action) {
    try {
      return evaluateAuthorizationMode(selectedAuthorizationMode, context, action);
    } catch (error) {
      if (error instanceof AuthorizationError) throw new AccessDeniedError();
      throw error;
    }
  }

  function authorizeBaselineOperation(context, action) {
    const authorization = evaluateOperation(context, action);
    if (authorization.outcome !== "allow") throw new AccessDeniedError();
    return authorization;
  }

  async function authorizeSensitiveOperation(context, action, operationId, attributes, signal) {
    const authorization = evaluateOperation(context, action);
    const { eligibility } = authorization;
    if (authorization.outcome !== "requires-controls"
      || eligibility.role !== "tenant-admin"
      || eligibility.scope !== "tenant") {
      throw new AccessDeniedError();
    }

    const authorized = await sensitiveOperationAuthorizer(Object.freeze({
      operationId,
      action,
      context,
      authorization,
      eligibility,
      attributes: Object.freeze({ ...attributes }),
      signal,
    }));
    if (authorized !== true) throw new AccessDeniedError();
  }

  async function authorizeProtectedOperation({
    query,
    authentication,
    context,
    requestState,
    action,
    policyRequest,
    operationId = null,
    attributes = {},
    sensitive = false,
    signal,
  }) {
    if (!policyModeSelected) {
      if (sensitive) {
        await authorizeSensitiveOperation(context, action, operationId, attributes, signal);
        return;
      }
      authorizeBaselineOperation(context, action);
      return;
    }

    const authorization = evaluateOperation(context, action);
    if (authorization.outcome !== "policy-required") throw new AccessDeniedError();
    let stepUp = null;
    if (sensitive) {
      const presentation = normalizeStepUpPresentation(policyRequest?.stepUpPresentation);
      if (presentation) {
        const consumedAt = asIsoTimestamp(clock());
        const consumed = await query(
          `SELECT proof_id_hash_sha256, tenant_id::text, subject_id::text, action,
             session_id_hash_sha256, verified_at, expires_at
           FROM audit.consume_step_up_proof($1, $2, $3, $4, $5)`,
          [
            hashStepUpValue(presentation.proofId),
            hashStepUpValue(presentation.sessionId),
            action,
            policyRequest.requestId,
            consumedAt,
          ],
        );
        if (consumed.rowCount !== 1) throw new AccessDeniedError();
        const row = consumed.rows[0];
        stepUp = Object.freeze({
          status: "valid",
          proofIdHashSha256: row.proof_id_hash_sha256,
          tenantId: row.tenant_id,
          subjectId: row.subject_id,
          action: row.action,
          sessionIdHashSha256: row.session_id_hash_sha256,
          verifiedAt: asIsoTimestamp(row.verified_at),
          expiresAt: asIsoTimestamp(row.expires_at),
        });
      }
    }
    const evaluation = await policyEnforcementService.decide({
      authentication,
      context,
      requestState,
      authorization,
      action,
      policyRequest: { ...policyRequest, stepUp },
      signal,
    });
    if (evaluation.decision.outcome === "QUARANTINE") {
      const actionId = createSecurityActionId(securityActionIdFactory);
      const quarantine = evaluation.decision.obligations.quarantine;
      const requestedAt = asIsoTimestamp(clock());
      const requested = await query(
        `SELECT (audit.request_quarantine_action(
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
         )).*`,
        [
          actionId,
          evaluation.decision.decisionId,
          policyRequest.requestId,
          policyRequest.correlationId,
          requestState.certificateId,
          action,
          quarantine.actionType,
          evaluation.decision.reasonCodes[0],
          evaluation.input.resource.resourceIdHashSha256,
          evaluation.input.trust.transitionId,
          evaluation.policyBundle.policyVersionId,
          evaluation.inputHash,
          requestedAt,
        ],
      );
      if (requested.rowCount !== 1) throw new AccessDeniedError();
      throw new QuarantineEnforcedError();
    }
    if (evaluation.decision.outcome !== POLICY_ENFORCEMENT_POLICY.onlyAllowingOutcome) {
      throw new AccessDeniedError();
    }
  }

  async function withTenantContext(authentication, operation, { signal } = {}) {
    assertCertificateAuthentication(authentication);
    throwIfAborted(signal);
    const client = await pool.connect();
    let transactionStarted = false;
    try {
      throwIfAborted(signal);
      const query = (text, values = []) => {
        throwIfAborted(signal);
        return client.query({ text, values, signal });
      };
      await query("BEGIN");
      transactionStarted = true;
      await query("SET LOCAL ROLE tenant_trust_app");
      await query(
        `SELECT
           set_config('statement_timeout', $1, true),
           set_config('lock_timeout', $2, true),
           set_config('idle_in_transaction_session_timeout', $3, true)`,
        [
          `${REQUEST_SAFEGUARD_POLICY.databaseStatementTimeoutMilliseconds}ms`,
          `${REQUEST_SAFEGUARD_POLICY.databaseLockTimeoutMilliseconds}ms`,
          `${REQUEST_SAFEGUARD_POLICY.requestTimeoutMilliseconds}ms`,
        ],
      );
      await query(
        "SELECT identity.set_tenant_actor_context($1::identity.tenant_id, $2::identity.subject_id)",
        [authentication.tenantId, authentication.subjectId],
      );

      const authorityResult = await query(
        `SELECT
           tenant.tenant_id::text,
           tenant.state::text AS tenant_state,
           tenant.version AS tenant_version,
           subject.subject_id::text,
           subject.state::text AS subject_state,
           subject.version AS subject_version,
           membership.state::text AS membership_state,
           membership.version AS membership_version,
           array_agg(role_assignment.role_name::text ORDER BY role_assignment.role_name::text) AS roles
         FROM identity.tenants AS tenant
         JOIN identity.tenant_memberships AS membership
           ON membership.tenant_id = tenant.tenant_id
         JOIN identity.subjects AS subject
           ON subject.subject_id = membership.subject_id
         JOIN identity.tenant_role_assignments AS role_assignment
           ON role_assignment.tenant_id = membership.tenant_id
          AND role_assignment.subject_id = membership.subject_id
         WHERE tenant.tenant_id = $1::identity.tenant_id
           AND subject.subject_id = $2::identity.subject_id
         GROUP BY tenant.tenant_id, tenant.state, tenant.version,
                  subject.subject_id, subject.state, subject.version,
                  membership.state, membership.version`,
        [authentication.tenantId, authentication.subjectId],
      );
      if (authorityResult.rowCount !== 1) throw new AccessDeniedError();

      const context = contextResolver({
        authentication,
        authority: mapAuthority(authorityResult.rows[0]),
      });
      const transactionClient = Object.freeze({
        query(input, values) {
          if (typeof input === "object" && input !== null) {
            return query(input.text, input.values);
          }
          return query(input, values);
        },
      });
      const requestState = await requestStateRevalidator.validate({
        client: transactionClient,
        authentication,
        context,
      });
      const queryProtected = async (text, parameters) => {
        throwIfAborted(signal);
        requestStateRevalidator.assertFresh(requestState);
        return query(text, parameters);
      };
      const result = await operation(queryProtected, context, requestState, signal);
      throwIfAborted(signal);
      await query("COMMIT");
      return result;
    } catch (error) {
      if (transactionStarted && error instanceof QuarantineEnforcedError && !signal?.aborted) {
        try {
          await client.query("COMMIT");
          transactionStarted = false;
        } catch (commitError) {
          await rollbackQuietly(client);
          transactionStarted = false;
          if (isTimeoutError(commitError, signal)) throw new RequestTimeoutError();
          throw commitError;
        }
        throw error;
      }
      if (transactionStarted) await rollbackQuietly(client);
      if (isTimeoutError(error, signal)) throw new RequestTimeoutError();
      if (error?.code === "P0001" && error?.message === "SENSITIVE_OPERATION_IDEMPOTENCY_CONFLICT") {
        throw new IdempotencyConflictError();
      }
      if (error?.code === "P0001" && error?.message === "QUARANTINE_ACTION_IDEMPOTENCY_CONFLICT") {
        throw new AccessDeniedError();
      }
      if (error?.code === "42501") throw new AccessDeniedError();
      if (error instanceof StepUpAuthenticationError) throw new AccessDeniedError();
      if (error instanceof TenantContextError) throw new AccessDeniedError();
      throw error;
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    authorizationMode: selectedAuthorizationMode,
    policyEnforcementPolicy: policyModeSelected ? POLICY_ENFORCEMENT_POLICY : null,
    requestStatePolicy: REQUEST_STATE_POLICY,
    requestSafeguardPolicy: REQUEST_SAFEGUARD_POLICY,

    async issueStepUpChallenge(authentication, action, factorId, { signal } = {}) {
      return withTenantContext(authentication, async (query, context) => {
        const authorization = evaluateOperation(context, action);
        if (authorization.outcome !== "policy-required") throw new AccessDeniedError();
        const material = createStepUpChallengeMaterial({
          tenantId: context.tenantId,
          subjectId: context.subjectId,
          action,
          factorId,
          now: clock(),
        });
        const result = await query(
          `SELECT (audit.issue_step_up_challenge($1, $2, $3, $4, $5, $6, $7)).*`,
          [material.challengeId, material.factorId, material.action, material.nonceBase64url,
            material.sessionIdHashSha256, material.issuedAt, material.expiresAt],
        );
        if (result.rowCount !== 1) throw new AccessDeniedError();
        return Object.freeze({
          challengeId: material.challengeId,
          factorId: material.factorId,
          algorithm: STEP_UP_POLICY.algorithm,
          action: material.action,
          nonceBase64url: material.nonceBase64url,
          sessionId: material.sessionId,
          issuedAt: material.issuedAt,
          expiresAt: material.expiresAt,
        });
      }, { signal });
    },

    async verifyStepUpChallenge(authentication, challengeId, signatureBase64url, { signal } = {}) {
      return withTenantContext(authentication, async (query, context) => {
        const result = await query(
          `SELECT tenant_id::text, subject_id::text, challenge_id::text, factor_id::text,
             action, nonce_base64url, session_id_hash_sha256, issued_at, expires_at,
             public_key_base64url::text
           FROM audit.get_step_up_challenge($1)`,
          [challengeId],
        );
        if (result.rowCount !== 1) throw new AccessDeniedError();
        const row = result.rows[0];
        const challenge = Object.freeze({
          tenantId: row.tenant_id,
          subjectId: row.subject_id,
          challengeId: row.challenge_id,
          factorId: row.factor_id,
          action: row.action,
          nonceBase64url: row.nonce_base64url,
          sessionIdHashSha256: row.session_id_hash_sha256,
          issuedAt: asIsoTimestamp(row.issued_at),
          expiresAt: asIsoTimestamp(row.expires_at),
        });
        if (challenge.tenantId !== context.tenantId || challenge.subjectId !== context.subjectId) {
          throw new AccessDeniedError();
        }
        verifyStepUpChallengeSignature({
          challenge,
          publicKeyBase64url: row.public_key_base64url,
          signatureBase64url,
        });
        const proof = createStepUpProofMaterial({ now: clock() });
        const completed = await query(
          `SELECT (audit.complete_step_up_challenge($1, $2, $3, $4)).*`,
          [challengeId, proof.proofIdHashSha256, proof.verifiedAt, proof.expiresAt],
        );
        if (completed.rowCount !== 1) throw new AccessDeniedError();
        return Object.freeze({
          proofId: proof.proofId,
          action: challenge.action,
          verifiedAt: proof.verifiedAt,
          expiresAt: proof.expiresAt,
        });
      }, { signal });
    },

    async getProfile(authentication, { policyRequest, signal } = {}) {
      return withTenantContext(authentication, async (query, context, requestState) => {
        await authorizeProtectedOperation({
          query,
          authentication,
          context,
          requestState,
          action: "profile:read",
          policyRequest,
          signal,
        });
        const result = await query(
          `SELECT
             tenant.tenant_id::text,
             tenant.display_name AS tenant_display_name,
             subject.subject_id::text,
             subject.display_name,
             subject.subject_kind::text,
             membership.created_at AS member_since
           FROM identity.tenants AS tenant
           JOIN identity.tenant_memberships AS membership
             ON membership.tenant_id = tenant.tenant_id
           JOIN identity.subjects AS subject
             ON subject.subject_id = membership.subject_id
           WHERE tenant.tenant_id = $1::identity.tenant_id
             AND subject.subject_id = $2::identity.subject_id`,
          [context.tenantId, context.subjectId],
        );
        if (result.rowCount !== 1) throw new AccessDeniedError();
        const row = result.rows[0];
        return Object.freeze({
          tenantId: context.tenantId,
          tenantDisplayName: row.tenant_display_name,
          subjectId: context.subjectId,
          displayName: row.display_name,
          subjectKind: row.subject_kind,
          roles: context.roles,
          memberSince: asIsoTimestamp(row.member_since),
          authorityVersions: context.versions,
        });
      }, { signal });
    },

    async listRecords(authentication, { policyRequest, signal } = {}) {
      return withTenantContext(authentication, async (query, context, requestState) => {
        await authorizeProtectedOperation({
          query,
          authentication,
          context,
          requestState,
          action: "record:read",
          policyRequest,
          signal,
        });
        const result = await query(
          `SELECT resource_id::text, owner_subject_id::text, resource_name, version, created_at, updated_at
           FROM app.resources
           WHERE tenant_id = $1::identity.tenant_id
           ORDER BY resource_id
           LIMIT 100`,
          [context.tenantId],
        );
        return Object.freeze(result.rows.map(mapRecord));
      }, { signal });
    },

    async getRecord(authentication, recordId, { policyRequest, signal } = {}) {
      if (!RESOURCE_ID.test(recordId ?? "")) throw new TypeError("A valid record ID is required.");
      return withTenantContext(authentication, async (query, context, requestState) => {
        await authorizeProtectedOperation({
          query,
          authentication,
          context,
          requestState,
          action: "record:read",
          policyRequest,
          signal,
        });
        const result = await query(
          `SELECT resource_id::text, owner_subject_id::text, resource_name, version, created_at, updated_at
           FROM app.resources
           WHERE tenant_id = $1::identity.tenant_id
             AND resource_id = $2::app.resource_id`,
          [context.tenantId, recordId],
        );
        if (result.rowCount !== 1) throw new AccessDeniedError();
        return mapRecord(result.rows[0]);
      }, { signal });
    },

    async exportRecords(authentication, recordIds, { idempotencyKey, policyRequest, signal } = {}) {
      const requestedRecordIds = normalizeRecordIds(recordIds);
      const normalizedIdempotencyKey = normalizeSensitiveIdempotencyKey(idempotencyKey);
      const keyHash = hashSensitiveIdempotencyKey(normalizedIdempotencyKey);
      const requestHash = hashSensitiveRequest("record:export", requestedRecordIds);
      return withTenantContext(authentication, async (query, context, requestState, operationSignal) => {
        if (policyModeSelected) {
          await authorizeProtectedOperation({
            query,
            authentication,
            context,
            requestState,
            action: "record:export",
            policyRequest,
            attributes: { requestedRecordCount: requestedRecordIds.length },
            sensitive: true,
            signal: operationSignal,
          });
        }
        const candidateOperationId = createOperationId(operationIdFactory);
        const reservation = await query(
          `SELECT operation_id, replayed
           FROM audit.reserve_api_sensitive_operation($1, $2, $3, $4, $5, $6)`,
          [context.tenantId, context.subjectId, "record:export", keyHash, requestHash, candidateOperationId],
        );
        if (reservation.rowCount !== 1 || !OPERATION_ID.test(reservation.rows[0].operation_id ?? "")
          || typeof reservation.rows[0].replayed !== "boolean") {
          throw new TypeError("The sensitive-operation receipt was invalid.");
        }
        const operationId = reservation.rows[0].operation_id;
        if (!policyModeSelected) {
          await authorizeProtectedOperation({
            query,
            authentication,
            context,
            requestState,
            action: "record:export",
            policyRequest,
            operationId,
            attributes: { requestedRecordCount: requestedRecordIds.length },
            sensitive: true,
            signal: operationSignal,
          });
        }

        const result = await query(
          `SELECT resource_id::text, owner_subject_id::text, resource_name, version, created_at, updated_at
           FROM app.resources
           WHERE tenant_id = $1::identity.tenant_id
             AND resource_id = ANY($2::app.resource_id[])
           ORDER BY resource_id`,
          [context.tenantId, requestedRecordIds],
        );
        if (result.rowCount !== requestedRecordIds.length) throw new AccessDeniedError();
        const records = Object.freeze(result.rows.map(mapRecord));
        return Object.freeze({
          operation: operationMetadata(context, operationId, "record:export", reservation.rows[0].replayed, {
            authorizationModeId: selectedAuthorizationMode.modeId,
            recordCount: records.length,
          }),
          records,
        });
      }, { signal });
    },

    async reviewMembership(authentication, subjectId, { idempotencyKey, policyRequest, signal } = {}) {
      if (!SUBJECT_ID.test(subjectId ?? "")) throw new TypeError("A valid subject ID is required.");
      const normalizedIdempotencyKey = normalizeSensitiveIdempotencyKey(idempotencyKey);
      const keyHash = hashSensitiveIdempotencyKey(normalizedIdempotencyKey);
      const requestHash = hashSensitiveRequest("tenant:admin", [subjectId]);
      return withTenantContext(authentication, async (query, context, requestState, operationSignal) => {
        if (policyModeSelected) {
          await authorizeProtectedOperation({
            query,
            authentication,
            context,
            requestState,
            action: "tenant:admin",
            policyRequest,
            attributes: { targetSubjectId: subjectId },
            sensitive: true,
            signal: operationSignal,
          });
        }
        const candidateOperationId = createOperationId(operationIdFactory);
        const reservation = await query(
          `SELECT operation_id, replayed
           FROM audit.reserve_api_sensitive_operation($1, $2, $3, $4, $5, $6)`,
          [context.tenantId, context.subjectId, "tenant:admin", keyHash, requestHash, candidateOperationId],
        );
        if (reservation.rowCount !== 1 || !OPERATION_ID.test(reservation.rows[0].operation_id ?? "")
          || typeof reservation.rows[0].replayed !== "boolean") {
          throw new TypeError("The sensitive-operation receipt was invalid.");
        }
        const operationId = reservation.rows[0].operation_id;
        if (!policyModeSelected) {
          await authorizeProtectedOperation({
            query,
            authentication,
            context,
            requestState,
            action: "tenant:admin",
            policyRequest,
            operationId,
            attributes: { targetSubjectId: subjectId },
            sensitive: true,
            signal: operationSignal,
          });
        }

        const result = await query(
          `SELECT
             subject.subject_id::text,
             subject.display_name,
             subject.state::text AS subject_state,
             subject.version AS subject_version,
             membership.state::text AS membership_state,
             membership.version AS membership_version,
             array_agg(role_assignment.role_name::text ORDER BY role_assignment.role_name::text) AS roles
           FROM identity.tenant_memberships AS membership
           JOIN identity.subjects AS subject
             ON subject.subject_id = membership.subject_id
           JOIN identity.tenant_role_assignments AS role_assignment
             ON role_assignment.tenant_id = membership.tenant_id
            AND role_assignment.subject_id = membership.subject_id
           WHERE membership.tenant_id = $1::identity.tenant_id
             AND membership.subject_id = $2::identity.subject_id
           GROUP BY subject.subject_id, subject.display_name, subject.state, subject.version,
                    membership.state, membership.version`,
          [context.tenantId, subjectId],
        );
        if (result.rowCount !== 1) throw new AccessDeniedError();
        const row = result.rows[0];
        return Object.freeze({
          operation: operationMetadata(context, operationId, "tenant:admin", reservation.rows[0].replayed, {
            authorizationModeId: selectedAuthorizationMode.modeId,
            targetSubjectId: subjectId,
          }),
          membership: Object.freeze({
            subjectId: row.subject_id,
            displayName: row.display_name,
            subjectState: row.subject_state,
            subjectVersion: asSafeVersion(row.subject_version),
            membershipState: row.membership_state,
            membershipVersion: asSafeVersion(row.membership_version),
            roles: Object.freeze([...row.roles]),
          }),
        });
      }, { signal });
    },
  });
}
