import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, randomUUID, X509Certificate } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import {
  CertificateIssuanceError,
  createCertificateIssuanceService,
  prepareCertificateIssuance,
  verifyIssuedCertificate,
} from "@tenant-trust/certificate-issuance";
import { createCertificateInventoryService } from "@tenant-trust/certificate-inventory";
import { createCertificateRevocationService } from "@tenant-trust/certificate-revocation";
import {
  CertificateStatusError,
  createCertificateStatusValidationService,
} from "@tenant-trust/certificate-status";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const image = environment.STEP_CA_IMAGE;
if (!image?.includes("@sha256:")) throw new Error("STEP_CA_IMAGE must be digest-pinned.");

const ids = {
  alphaTenant: `tnt_${randomUUID()}`,
  betaTenant: `tnt_${randomUUID()}`,
  alphaSubject: `sub_${randomUUID()}`,
  betaSubject: `sub_${randomUUID()}`,
  alphaIssuer: `iss_${randomUUID()}`,
  betaIssuer: `iss_${randomUUID()}`,
};
const runtimeRoot = resolve(repositoryRoot, "runtime");
const workingDirectory = resolve(runtimeRoot, `certificate-lifecycle-${randomUUID()}`);
const templatePath = resolve(repositoryRoot, "infra", "pki", "templates", "tenant-client-auth-v1.tpl");
if (!workingDirectory.startsWith(`${runtimeRoot}${sep}`)) throw new Error("Refusing a lifecycle directory outside ignored runtime storage.");

function runStep(args, label) {
  const result = spawnSync("docker", [
    "run", "--rm",
    "--mount", `type=bind,source=${workingDirectory},target=/work`,
    "--mount", `type=bind,source=${templatePath},target=/templates/tenant-client-auth-v1.tpl,readonly`,
    image, "step", ...args,
  ], {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
  return result.stdout;
}

function context({ tenantId, subjectId }) {
  return resolveTenantContext({
    authentication: {
      source: "trusted-session",
      authenticationId: `certificate-lifecycle:${subjectId}`,
      tenantId,
      subjectId,
    },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId, state: "active", version: 1 },
      membership: { tenantId, subjectId, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

function request({ subjectId, csrPem, operation = "issue", certificateId = null }) {
  return {
    requestId: `req_${randomUUID()}`,
    profileId: "tenant-client-auth-v1",
    subjectId,
    requestedValiditySeconds: 3_600,
    proofOfPossession: {
      publicKeyAlgorithm: "ecdsa-p256",
      csrPem,
      csrSha256: createHash("sha256").update(csrPem, "utf8").digest("hex"),
    },
    ...(operation === "renew" ? { renewalOfCertificateId: certificateId } : {}),
    idempotencyKey: `certificate:${operation}:lifecycle:${randomUUID()}`,
  };
}

async function createRoot(name, prefix) {
  runStep([
    "certificate", "create", name,
    `/work/${prefix}-root.crt`, `/work/${prefix}-root.key`,
    "--profile", "root-ca", "--kty", "EC", "--curve", "P-256",
    "--not-after", "87600h", "--no-password", "--insecure",
  ], `${name} root creation`);
}

async function createIntermediate(name, prefix, rootPrefix) {
  runStep([
    "certificate", "create", name,
    `/work/${prefix}-intermediate.crt`, `/work/${prefix}-intermediate.key`,
    "--profile", "intermediate-ca",
    "--ca", `/work/${rootPrefix}-root.crt`,
    "--ca-key", `/work/${rootPrefix}-root.key`,
    "--kty", "EC", "--curve", "P-256",
    "--not-after", "8760h", "--no-password", "--insecure",
  ], `${name} intermediate creation`);
  return readFile(resolve(workingDirectory, `${prefix}-intermediate.crt`), "utf8");
}

const inspectedCsrs = new Map();
async function createCsr(name, prefix) {
  runStep([
    "certificate", "create", name,
    `/work/${prefix}.csr`, `/work/${prefix}.key`,
    "--csr", "--kty", "EC", "--curve", "P-256", "--no-password", "--insecure",
  ], `${name} CSR creation`);
  const csrPem = await readFile(resolve(workingDirectory, `${prefix}.csr`), "utf8");
  const privateKeyPem = await readFile(resolve(workingDirectory, `${prefix}.key`), "utf8");
  inspectedCsrs.set(csrPem, {
    publicKeyAlgorithm: "ecdsa-p256",
    publicKeySha256: createHash("sha256")
      .update(createPublicKey(createPrivateKey(privateKeyPem)).export({ type: "spki", format: "der" }))
      .digest("hex"),
  });
  return csrPem;
}

let signingSequence = 0;
async function signWith(instruction, issuerPrefix, { notBefore = instruction.notBefore, notAfter = instruction.notAfter } = {}) {
  signingSequence += 1;
  const prefix = `signed-${signingSequence}`;
  await writeFile(resolve(workingDirectory, `${prefix}.json`), `${JSON.stringify({
    tenantId: instruction.tenantId,
    subjectId: instruction.subjectId,
    identityUri: instruction.subjectAlternativeNames[0],
  })}\n`, "utf8");
  await writeFile(resolve(workingDirectory, `${prefix}.csr`), instruction.csrPem, "utf8");
  return runStep([
    "certificate", "sign",
    `/work/${prefix}.csr`,
    `/work/${issuerPrefix}-intermediate.crt`,
    `/work/${issuerPrefix}-intermediate.key`,
    "--template", "/templates/tenant-client-auth-v1.tpl",
    "--set-file", `/work/${prefix}.json`,
    "--not-before", notBefore,
    "--not-after", notAfter,
    "--omit-cn-san",
  ], `${issuerPrefix} certificate signing`);
}

function metadataFromCertificate({ certificatePem, tenantId, subjectId, issuerId }) {
  const certificate = new X509Certificate(certificatePem);
  return {
    tenantId,
    subjectId,
    certificateId: `crt_${randomUUID()}`,
    issuerId,
    serialNumber: certificate.serialNumber.toUpperCase().padStart(32, "0"),
    fingerprintSha256: certificate.fingerprint256.replaceAll(":", "").toLowerCase(),
    notBefore: new Date(certificate.validFrom).toISOString(),
    notAfter: new Date(certificate.validTo).toISOString(),
  };
}

function statusValidator(at, inventory) {
  return createCertificateStatusValidationService({
    clock: () => new Date(at),
    loadCertificateStatus: async (query) => {
      const record = inventory.get(query.certificateId);
      if (!record) return null;
      return { ...record, statusObservedAt: new Date(at).toISOString() };
    },
  });
}

const alphaContext = context({ tenantId: ids.alphaTenant, subjectId: ids.alphaSubject });
const betaContext = context({ tenantId: ids.betaTenant, subjectId: ids.betaSubject });
const memberships = new Map([
  [`${ids.alphaTenant}:${ids.alphaSubject}`, { tenantId: ids.alphaTenant, subjectId: ids.alphaSubject, tenantState: "active", subjectState: "active", membershipState: "active" }],
  [`${ids.betaTenant}:${ids.betaSubject}`, { tenantId: ids.betaTenant, subjectId: ids.betaSubject, tenantState: "active", subjectState: "active", membershipState: "active" }],
]);
const inventory = new Map();

try {
  await mkdir(workingDirectory, { recursive: true });
  await createRoot("Tenant Trust Platform Root", "platform");
  const alphaIssuerCertificate = await createIntermediate("tenant-alpha-intermediate", "alpha", "platform");
  const betaIssuerCertificate = await createIntermediate("tenant-beta-intermediate", "beta", "platform");
  await createRoot("Untrusted Lookalike Root", "rogue");
  await createIntermediate("tenant-alpha-intermediate", "rogue-alpha", "rogue");

  const platformRoot = new X509Certificate(await readFile(resolve(workingDirectory, "platform-root.crt"), "utf8"));
  const alphaIntermediate = new X509Certificate(alphaIssuerCertificate);
  const betaIntermediate = new X509Certificate(betaIssuerCertificate);
  assert.equal(alphaIntermediate.verify(platformRoot.publicKey), true);
  assert.equal(betaIntermediate.verify(platformRoot.publicKey), true);
  assert.notEqual(alphaIntermediate.fingerprint256, betaIntermediate.fingerprint256);

  const issuers = new Map([
    [ids.alphaTenant, {
      tenantId: ids.alphaTenant,
      issuerId: ids.alphaIssuer,
      issuerName: "tenant-alpha-intermediate",
      authorityUrl: "https://tenant-alpha-ca.internal:9000",
      state: "active",
      allowedCertificateOperations: ["issue", "renew", "revoke"],
      issuerCertificatePem: alphaIssuerCertificate,
      prefix: "alpha",
    }],
    [ids.betaTenant, {
      tenantId: ids.betaTenant,
      issuerId: ids.betaIssuer,
      issuerName: "tenant-beta-intermediate",
      authorityUrl: "https://tenant-beta-ca.internal:9000",
      state: "active",
      allowedCertificateOperations: ["issue", "renew", "revoke"],
      issuerCertificatePem: betaIssuerCertificate,
      prefix: "beta",
    }],
  ]);
  const loadTargetMembership = async ({ tenantId, subjectId }) => memberships.get(`${tenantId}:${subjectId}`) ?? null;
  const resolveIssuer = async ({ tenantId }) => issuers.get(tenantId) ?? null;
  let lifecycleTime = new Date(Math.floor(Date.now() / 1_000) * 1_000);

  const inventoryService = createCertificateInventoryService({
    async insertIssuedCertificate(record) {
      inventory.set(record.certificateId, { ...record, version: 1 });
      return { certificateId: record.certificateId, eventId: record.issuedEventId, state: "active" };
    },
    async insertRenewedCertificate(record) {
      const predecessor = inventory.get(record.supersedesCertificateId);
      inventory.set(predecessor.certificateId, {
        ...predecessor,
        state: "superseded",
        version: predecessor.version + 1,
        lastEventId: record.supersededEventId,
      });
      inventory.set(record.certificateId, { ...record, version: 1 });
      return {
        certificateId: record.certificateId,
        renewedEventId: record.renewedEventId,
        supersededEventId: record.supersededEventId,
        state: "active",
        predecessorState: "superseded",
      };
    },
  });
  const service = createCertificateIssuanceService({
    loadTargetMembership,
    loadRenewalCertificate: async ({ tenantId, certificateId, subjectId }) => {
      const record = inventory.get(certificateId);
      return record?.tenantId === tenantId && record.subjectId === subjectId ? record : null;
    },
    inspectCertificateRequest: async (csrPem) => inspectedCsrs.get(csrPem) ?? null,
    resolveIssuer,
    signCertificate: async (instruction) => ({ certificatePem: await signWith(instruction, issuers.get(instruction.tenantId).prefix) }),
    recordIssuedCertificate: inventoryService.recordIssuedCertificate,
    recordRenewedCertificate: inventoryService.recordRenewedCertificate,
    clock: () => new Date(lifecycleTime),
  });

  const initialCsr = await createCsr(ids.alphaSubject, "alpha-initial");
  const initialRequest = request({ subjectId: ids.alphaSubject, csrPem: initialCsr });
  const prepared = await prepareCertificateIssuance({
    context: alphaContext,
    request: initialRequest,
    loadTargetMembership,
    resolveIssuer,
    clock: () => new Date(lifecycleTime),
  });
  const wrongIssuerPem = await signWith(prepared.signingInstruction, "beta");
  assert.throws(
    () => verifyIssuedCertificate({ certificatePem: wrongIssuerPem, prepared }),
    (error) => error instanceof CertificateIssuanceError && error.reasonCode === "CERTIFICATE_ISSUER_MISMATCH",
  );
  console.log("PASS a valid chain from the other tenant issuer is rejected despite sharing the platform root");

  const invalidChainPem = await signWith(prepared.signingInstruction, "rogue-alpha");
  assert.throws(
    () => verifyIssuedCertificate({ certificatePem: invalidChainPem, prepared }),
    (error) => error instanceof CertificateIssuanceError && error.reasonCode === "CERTIFICATE_ISSUER_MISMATCH",
  );
  console.log("PASS an untrusted lookalike issuer name cannot substitute for the selected issuer key");

  const issued = await service.issue({ context: alphaContext, request: initialRequest });
  const activeAt = new Date(lifecycleTime.getTime() + 30_000);
  const active = await statusValidator(activeAt, inventory).validate({ context: alphaContext, certificate: issued });
  assert.equal(active.outcome, "accept");
  assert.equal(active.reasonCode, "CERTIFICATE_ACTIVE");
  console.log("PASS the tenant-bound issued certificate is active only with its exact issuer and inventory identity");

  await assert.rejects(
    statusValidator(activeAt, inventory).validate({ context: betaContext, certificate: issued }),
    (error) => error instanceof CertificateStatusError && error.reasonCode === "PRESENTED_CERTIFICATE_INVALID",
  );
  console.log("PASS the valid Alpha certificate is rejected in Beta's authenticated tenant context");

  lifecycleTime = new Date(new Date(issued.notAfter).getTime() - 300_000);
  const renewalCsr = await createCsr(ids.alphaSubject, "alpha-renewal");
  const renewed = await service.renew({
    context: alphaContext,
    request: request({
      subjectId: ids.alphaSubject,
      csrPem: renewalCsr,
      operation: "renew",
      certificateId: issued.certificateId,
    }),
  });
  assert.notEqual(renewed.publicKeySha256, issued.publicKeySha256);
  const predecessor = await statusValidator(lifecycleTime, inventory).validate({ context: alphaContext, certificate: issued });
  assert.equal(predecessor.reasonCode, "CERTIFICATE_SUPERSEDED");
  const successor = await statusValidator(lifecycleTime, inventory).validate({ context: alphaContext, certificate: renewed });
  assert.equal(successor.reasonCode, "CERTIFICATE_ACTIVE");
  console.log("PASS renewal rotates the subject key, activates the successor and rejects the superseded predecessor");

  lifecycleTime = new Date(lifecycleTime.getTime() + 30_000);
  const revocationService = createCertificateRevocationService({
    loadCertificate: async ({ tenantId, certificateId }) => {
      const record = inventory.get(certificateId);
      return record?.tenantId === tenantId ? record : null;
    },
    loadExistingRevocation: async () => null,
    resolveIssuer,
    revokeAtIssuer: async (instruction) => ({
      status: "revoked",
      tenantId: instruction.tenantId,
      certificateId: instruction.certificateId,
      issuerId: instruction.issuerId,
      serialNumber: instruction.serialNumber,
      fingerprintSha256: instruction.fingerprintSha256,
      reasonCode: instruction.reasonCode,
      issuerConfirmationId: `step-ca:revocation:${randomUUID()}`,
      revokedAt: new Date(lifecycleTime).toISOString(),
    }),
    recordRevocation: async (record) => {
      const current = inventory.get(record.certificateId);
      const updated = {
        ...current,
        state: "revoked",
        version: current.version + 1,
        lastEventId: record.eventId,
      };
      inventory.set(record.certificateId, updated);
      return {
        certificateId: record.certificateId,
        eventId: record.eventId,
        correlationId: record.correlationId,
        state: "revoked",
        version: updated.version,
      };
    },
    clock: () => new Date(lifecycleTime),
  });
  await revocationService.revoke({
    context: alphaContext,
    request: {
      requestId: `req_${randomUUID()}`,
      certificateId: renewed.certificateId,
      reasonCode: "KEY_COMPROMISE",
      idempotencyKey: `certificate:revoke:lifecycle:${randomUUID()}`,
    },
  });
  const revoked = await statusValidator(new Date(lifecycleTime.getTime() + 1_000), inventory)
    .validate({ context: alphaContext, certificate: renewed });
  assert.equal(revoked.outcome, "deny");
  assert.equal(revoked.reasonCode, "CERTIFICATE_REVOKED");
  assert.equal(revoked.cacheableUntil, null);
  console.log("PASS issuer-confirmed revocation becomes permanent non-cacheable application denial");

  const expiredCsr = await createCsr(ids.alphaSubject, "alpha-expired");
  const expiredRequest = request({ subjectId: ids.alphaSubject, csrPem: expiredCsr });
  const expiredPrepared = await prepareCertificateIssuance({
    context: alphaContext,
    request: expiredRequest,
    loadTargetMembership,
    resolveIssuer,
    clock: () => new Date(lifecycleTime),
  });
  const expiredPem = await signWith(expiredPrepared.signingInstruction, "alpha", {
    notBefore: new Date(lifecycleTime.getTime() - 7_200_000).toISOString(),
    notAfter: new Date(lifecycleTime.getTime() - 3_600_000).toISOString(),
  });
  const expiredX509 = new X509Certificate(expiredPem);
  assert.equal(expiredX509.verify(alphaIntermediate.publicKey), true);
  const expiredCertificate = metadataFromCertificate({
    certificatePem: expiredPem,
    tenantId: ids.alphaTenant,
    subjectId: ids.alphaSubject,
    issuerId: ids.alphaIssuer,
  });
  let queriedExpiredInventory = false;
  const expiredResult = await createCertificateStatusValidationService({
    clock: () => new Date(lifecycleTime),
    loadCertificateStatus: async () => { queriedExpiredInventory = true; return null; },
  }).validate({ context: alphaContext, certificate: expiredCertificate });
  assert.equal(expiredResult.outcome, "deny");
  assert.equal(expiredResult.reasonCode, "CERTIFICATE_EXPIRED");
  assert.equal(queriedExpiredInventory, false);
  console.log("PASS a correctly signed but expired certificate is rejected before an inventory lookup");
} finally {
  await rm(workingDirectory, { recursive: true, force: true });
}

console.log("Complete certificate lifecycle boundary verification passed and removed all generated key material.");

