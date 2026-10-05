import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  createEvidenceSourceRegistryService,
  createPostgresEvidenceSourceRegistryRepository,
  EvidenceSourceRegistryError,
  evidenceSourceRegistrySafeDenial,
  fingerprintEd25519PublicKey,
} from "../src/index.mjs";

const ids = Object.freeze({
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  admin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ab",
  source: "src_018f1234-5678-7abc-8def-0123456789b6",
  key: "key_018f1234-5678-7abc-8def-0123456789d0",
});

const publicKey = Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString("base64url");
const rotatedPublicKey = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 32)).toString("base64url");
const fingerprint = createHash("sha256").update(Buffer.from(publicKey, "base64url")).digest("hex");

function context({ tenantId = ids.alpha, subjectId = ids.admin, roles = ["tenant-admin"] } = {}) {
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "evidence-source-test", tenantId, subjectId },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId, state: "active", version: 1 },
      membership: { tenantId, subjectId, state: "active", version: 1 },
      roles,
    },
  });
}

function serviceWith(overrides = {}) {
  return createEvidenceSourceRegistryService({
    idFactory: () => "018f1234-5678-7abc-8def-0123456789d0",
    clock: () => new Date("2026-10-05T10:00:00.000Z"),
    enrollSource: async (record) => ({
      sourceId: record.sourceId,
      keyId: record.keyId,
      keyVersion: 1,
      keySha256: record.publicKeySha256,
      sourceState: "active",
      sourceVersion: 2,
    }),
    rotateKey: async (record) => ({
      sourceId: record.sourceId,
      keyId: record.keyId,
      keyVersion: 2,
      keySha256: record.publicKeySha256,
      sourceState: "active",
      sourceVersion: 3,
    }),
    revokeKey: async (record) => ({
      sourceId: record.sourceId,
      keyId: record.keyId,
      keyVersion: 1,
      keyState: "revoked",
      sourceState: "suspended",
      sourceVersion: 3,
    }),
    ...overrides,
  });
}

test("fingerprints exactly 32 canonical Ed25519 public-key bytes", () => {
  assert.equal(fingerprintEd25519PublicKey(publicKey), fingerprint);
  for (const invalid of ["a".repeat(42), `${publicKey}=`, "!".repeat(43)]) {
    assert.throws(
      () => fingerprintEd25519PublicKey(invalid),
      (error) => error instanceof EvidenceSourceRegistryError && error.reasonCode === "PUBLIC_KEY_INVALID",
    );
  }
});

test("a tenant administrator enrolls a pre-authorized source with server-owned identity", async () => {
  let persisted;
  const registry = serviceWith({
    enrollSource: async (record) => {
      persisted = record;
      return {
        sourceId: record.sourceId,
        keyId: record.keyId,
        keyVersion: 1,
        keySha256: record.publicKeySha256,
        sourceState: "active",
        sourceVersion: 2,
      };
    },
  });
  const result = await registry.enroll({
    context: context(),
    request: { sourceId: ids.source, publicKeyBase64Url: publicKey },
  });
  assert.equal(persisted.tenantId, ids.alpha);
  assert.equal(persisted.actorSubjectId, ids.admin);
  assert.equal(persisted.keyId, ids.key);
  assert.equal(persisted.publicKeySha256, fingerprint);
  assert.equal(persisted.occurredAt, "2026-10-05T10:00:00.000Z");
  assert.equal(result.sourceState, "active");
});

test("ordinary members cannot enroll, rotate or revoke keys", async () => {
  const memberContext = context({ subjectId: ids.alice, roles: ["tenant-member"] });
  const registry = serviceWith();
  for (const operation of [
    () => registry.enroll({ context: memberContext, request: { sourceId: ids.source, publicKeyBase64Url: publicKey } }),
    () => registry.rotate({ context: memberContext, request: { sourceId: ids.source, publicKeyBase64Url: rotatedPublicKey } }),
    () => registry.revoke({ context: memberContext, request: { sourceId: ids.source, keyId: ids.key, reasonCode: "KEY_COMPROMISED" } }),
  ]) {
    await assert.rejects(operation, (error) => error instanceof EvidenceSourceRegistryError
      && error.reasonCode === "TENANT_ADMIN_REQUIRED");
  }
});

test("requests cannot select tenant, actor, fingerprint or lifecycle state", async () => {
  const registry = serviceWith();
  for (const extra of [
    { tenantId: ids.beta },
    { actorSubjectId: ids.alice },
    { publicKeySha256: "0".repeat(64) },
    { state: "active" },
  ]) {
    await assert.rejects(
      registry.enroll({
        context: context(),
        request: { sourceId: ids.source, publicKeyBase64Url: publicKey, ...extra },
      }),
      (error) => error instanceof EvidenceSourceRegistryError
        && error.reasonCode === "ENROLLMENT_REQUEST_INVALID",
    );
  }
});

test("rotation appends a new server-generated key epoch", async () => {
  let persisted;
  const registry = serviceWith({
    rotateKey: async (record) => {
      persisted = record;
      return {
        sourceId: record.sourceId,
        keyId: record.keyId,
        keyVersion: 2,
        keySha256: record.publicKeySha256,
        sourceState: "active",
        sourceVersion: 3,
      };
    },
  });
  const result = await registry.rotate({
    context: context(),
    request: { sourceId: ids.source, publicKeyBase64Url: rotatedPublicKey },
  });
  assert.equal(persisted.keyId, ids.key);
  assert.notEqual(persisted.publicKeySha256, fingerprint);
  assert.equal(result.keyVersion, 2);
});

test("revocation requires a bounded reason and preserves the selected key identity", async () => {
  let persisted;
  const registry = serviceWith({
    revokeKey: async (record) => {
      persisted = record;
      return {
        sourceId: record.sourceId,
        keyId: record.keyId,
        keyVersion: 1,
        keyState: "revoked",
        sourceState: "suspended",
        sourceVersion: 3,
      };
    },
  });
  const result = await registry.revoke({
    context: context(),
    request: { sourceId: ids.source, keyId: ids.key, reasonCode: "KEY_COMPROMISED" },
  });
  assert.equal(persisted.keyId, ids.key);
  assert.equal(persisted.reasonCode, "KEY_COMPROMISED");
  assert.equal(result.keyState, "revoked");
  await assert.rejects(
    registry.revoke({
      context: context(),
      request: { sourceId: ids.source, keyId: ids.key, reasonCode: "bad-reason" },
    }),
    (error) => error instanceof EvidenceSourceRegistryError
      && error.reasonCode === "REVOCATION_REASON_INVALID",
  );
});

test("unconfirmed persistence results fail closed", async () => {
  const registry = serviceWith({ enrollSource: async () => null });
  await assert.rejects(
    registry.enroll({ context: context(), request: { sourceId: ids.source, publicKeyBase64Url: publicKey } }),
    (error) => error instanceof EvidenceSourceRegistryError
      && error.reasonCode === "REGISTRY_WRITE_UNCONFIRMED",
  );
  assert.deepEqual(evidenceSourceRegistrySafeDenial(new EvidenceSourceRegistryError("DETAIL")), {
    statusCode: 403,
    code: "ACCESS_DENIED",
  });
});

test("the PostgreSQL adapter uses parameterized registry functions and maps one row", async () => {
  const calls = [];
  const repository = createPostgresEvidenceSourceRegistryRepository({
    query: async (sql, values) => {
      calls.push({ sql, values });
      if (sql.includes("enroll_evidence_source")) {
        return { rows: [{
          enrolled_source_id: ids.source,
          enrolled_key_id: ids.key,
          enrolled_key_version: "1",
          enrolled_key_sha256: fingerprint,
          enrolled_source_state: "active",
          enrolled_source_version: "2",
        }] };
      }
      if (sql.includes("rotate_evidence_source_key")) {
        return { rows: [{
          rotated_source_id: ids.source,
          active_key_id: ids.key,
          active_key_version: "2",
          active_key_sha256: fingerprint,
          rotated_source_state: "active",
          rotated_source_version: "3",
        }] };
      }
      return { rows: [{
        revoked_source_id: ids.source,
        revoked_key_id: ids.key,
        revoked_key_version: "2",
        revoked_key_state: "revoked",
        resulting_source_state: "suspended",
        resulting_source_version: "4",
      }] };
    },
  });
  const record = {
    sourceId: ids.source,
    keyId: ids.key,
    publicKeyBase64Url: publicKey,
    occurredAt: "2026-10-05T10:00:00.000Z",
    reasonCode: "KEY_COMPROMISED",
  };
  assert.equal((await repository.enrollSource(record)).keyVersion, 1);
  assert.equal((await repository.rotateKey(record)).sourceVersion, 3);
  assert.equal((await repository.revokeKey(record)).keyState, "revoked");
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[0].values, [ids.source, ids.key, publicKey, record.occurredAt]);
  assert.deepEqual(calls[2].values, [ids.source, ids.key, "KEY_COMPROMISED", record.occurredAt]);
});
