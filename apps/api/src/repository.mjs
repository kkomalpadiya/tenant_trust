import { randomUUID } from "node:crypto";
import { resolveRoleAction } from "@tenant-trust/authorization";
import { resolveTenantContext } from "@tenant-trust/tenant-context";

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

function operationMetadata(context, operationId, action, attributes = {}) {
  return Object.freeze({
    operationId,
    action,
    tenantId: context.tenantId,
    requestedBy: context.subjectId,
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
}

async function rollbackQuietly(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // The original failure remains authoritative and is mapped by the API boundary.
  }
}

export function createPostgresTenantRepository({
  pool,
  contextResolver = resolveTenantContext,
  sensitiveOperationAuthorizer = defaultSensitiveOperationAuthorizer,
  operationIdFactory = defaultOperationIdFactory,
} = {}) {
  if (!pool || typeof pool.connect !== "function") throw new TypeError("A PostgreSQL pool is required.");
  if (typeof contextResolver !== "function") throw new TypeError("A tenant context resolver is required.");
  if (typeof sensitiveOperationAuthorizer !== "function") {
    throw new TypeError("A sensitive operation authorizer must be a function.");
  }
  if (typeof operationIdFactory !== "function") throw new TypeError("An operation ID factory is required.");

  async function authorizeSensitiveOperation(context, action, operationId, attributes) {
    const eligibility = resolveRoleAction(context, action);
    if (eligibility.role !== "tenant-admin"
      || eligibility.scope !== "tenant"
      || eligibility.disposition !== "requires-controls") {
      throw new AccessDeniedError();
    }

    const authorized = await sensitiveOperationAuthorizer(Object.freeze({
      operationId,
      action,
      context,
      eligibility,
      attributes: Object.freeze({ ...attributes }),
    }));
    if (authorized !== true) throw new AccessDeniedError();
  }

  async function withTenantContext(authentication, operation) {
    assertCertificateAuthentication(authentication);
    const client = await pool.connect();
    let transactionStarted = false;
    try {
      await client.query("BEGIN");
      transactionStarted = true;
      await client.query("SET LOCAL ROLE tenant_trust_app");
      await client.query(
        "SELECT identity.set_tenant_actor_context($1::identity.tenant_id, $2::identity.subject_id)",
        [authentication.tenantId, authentication.subjectId],
      );

      const authorityResult = await client.query(
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
      const result = await operation(client, context);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      if (transactionStarted) await rollbackQuietly(client);
      if (error?.code === "42501") throw new AccessDeniedError();
      throw error;
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    async getProfile(authentication) {
      return withTenantContext(authentication, async (client, context) => {
        const result = await client.query(
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
      });
    },

    async listRecords(authentication) {
      return withTenantContext(authentication, async (client, context) => {
        const result = await client.query(
          `SELECT resource_id::text, owner_subject_id::text, resource_name, version, created_at, updated_at
           FROM app.resources
           WHERE tenant_id = $1::identity.tenant_id
           ORDER BY resource_id
           LIMIT 100`,
          [context.tenantId],
        );
        return Object.freeze(result.rows.map(mapRecord));
      });
    },

    async getRecord(authentication, recordId) {
      if (!RESOURCE_ID.test(recordId ?? "")) throw new TypeError("A valid record ID is required.");
      return withTenantContext(authentication, async (client, context) => {
        const result = await client.query(
          `SELECT resource_id::text, owner_subject_id::text, resource_name, version, created_at, updated_at
           FROM app.resources
           WHERE tenant_id = $1::identity.tenant_id
             AND resource_id = $2::app.resource_id`,
          [context.tenantId, recordId],
        );
        if (result.rowCount !== 1) throw new AccessDeniedError();
        return mapRecord(result.rows[0]);
      });
    },

    async exportRecords(authentication, recordIds) {
      const requestedRecordIds = normalizeRecordIds(recordIds);
      return withTenantContext(authentication, async (client, context) => {
        const operationId = createOperationId(operationIdFactory);
        await authorizeSensitiveOperation(context, "record:export", operationId, {
          requestedRecordCount: requestedRecordIds.length,
        });

        const result = await client.query(
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
          operation: operationMetadata(context, operationId, "record:export", {
            recordCount: records.length,
          }),
          records,
        });
      });
    },

    async reviewMembership(authentication, subjectId) {
      if (!SUBJECT_ID.test(subjectId ?? "")) throw new TypeError("A valid subject ID is required.");
      return withTenantContext(authentication, async (client, context) => {
        const operationId = createOperationId(operationIdFactory);
        await authorizeSensitiveOperation(context, "tenant:admin", operationId, {
          targetSubjectId: subjectId,
        });

        const result = await client.query(
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
          operation: operationMetadata(context, operationId, "tenant:admin", {
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
      });
    },
  });
}
