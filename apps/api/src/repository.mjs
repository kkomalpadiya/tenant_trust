import { randomUUID } from "node:crypto";
import {
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

const RESOURCE_ID = /^res_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const OPERATION_ID = /^op_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_EXPORT_RECORDS = 25;

export class AccessDeniedError extends Error {
  constructor() {
    super("Access denied.");
    this.name = "AccessDeniedError";
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
  contextResolver = resolveTenantContext,
  sensitiveOperationAuthorizer = defaultSensitiveOperationAuthorizer,
  operationIdFactory = defaultOperationIdFactory,
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
  if (typeof contextResolver !== "function") throw new TypeError("A tenant context resolver is required.");
  if (typeof sensitiveOperationAuthorizer !== "function") {
    throw new TypeError("A sensitive operation authorizer must be a function.");
  }
  if (typeof operationIdFactory !== "function") throw new TypeError("An operation ID factory is required.");
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
      const result = await operation(queryProtected, context, signal);
      throwIfAborted(signal);
      await query("COMMIT");
      return result;
    } catch (error) {
      if (transactionStarted) await rollbackQuietly(client);
      if (isTimeoutError(error, signal)) throw new RequestTimeoutError();
      if (error?.code === "P0001" && error?.message === "SENSITIVE_OPERATION_IDEMPOTENCY_CONFLICT") {
        throw new IdempotencyConflictError();
      }
      if (error?.code === "42501") throw new AccessDeniedError();
      if (error instanceof TenantContextError) throw new AccessDeniedError();
      throw error;
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    authorizationMode: selectedAuthorizationMode,
    requestStatePolicy: REQUEST_STATE_POLICY,
    requestSafeguardPolicy: REQUEST_SAFEGUARD_POLICY,

    async getProfile(authentication, { signal } = {}) {
      return withTenantContext(authentication, async (query, context) => {
        authorizeBaselineOperation(context, "profile:read");
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

    async listRecords(authentication, { signal } = {}) {
      return withTenantContext(authentication, async (query, context) => {
        authorizeBaselineOperation(context, "record:read");
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

    async getRecord(authentication, recordId, { signal } = {}) {
      if (!RESOURCE_ID.test(recordId ?? "")) throw new TypeError("A valid record ID is required.");
      return withTenantContext(authentication, async (query, context) => {
        authorizeBaselineOperation(context, "record:read");
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

    async exportRecords(authentication, recordIds, { idempotencyKey, signal } = {}) {
      const requestedRecordIds = normalizeRecordIds(recordIds);
      const normalizedIdempotencyKey = normalizeSensitiveIdempotencyKey(idempotencyKey);
      const keyHash = hashSensitiveIdempotencyKey(normalizedIdempotencyKey);
      const requestHash = hashSensitiveRequest("record:export", requestedRecordIds);
      return withTenantContext(authentication, async (query, context, operationSignal) => {
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
        await authorizeSensitiveOperation(context, "record:export", operationId, {
          requestedRecordCount: requestedRecordIds.length,
        }, operationSignal);

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

    async reviewMembership(authentication, subjectId, { idempotencyKey, signal } = {}) {
      if (!SUBJECT_ID.test(subjectId ?? "")) throw new TypeError("A valid subject ID is required.");
      const normalizedIdempotencyKey = normalizeSensitiveIdempotencyKey(idempotencyKey);
      const keyHash = hashSensitiveIdempotencyKey(normalizedIdempotencyKey);
      const requestHash = hashSensitiveRequest("tenant:admin", [subjectId]);
      return withTenantContext(authentication, async (query, context, operationSignal) => {
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
        await authorizeSensitiveOperation(context, "tenant:admin", operationId, {
          targetSubjectId: subjectId,
        }, operationSignal);

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
