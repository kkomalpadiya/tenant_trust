import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  CertificateIssuanceError,
  certificateIssuanceSafeDenial,
  createCertificateIssuanceService,
} from "@tenant-trust/certificate-issuance";
import { createCertificateInventoryService } from "@tenant-trust/certificate-inventory";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ab",
  alphaAdmin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  bob: "sub_018f1234-5678-7abc-8def-0123456789ad",
  alphaIssuer: "iss_018f1234-5678-7abc-8def-0123456789b4",
  betaIssuer: "iss_018f1234-5678-7abc-8def-0123456789b5",
};
const runtimeRoot = resolve(repositoryRoot, "runtime");
const workingDirectory = resolve(runtimeRoot, `certificate-issuance-${randomUUID()}`);
const templatePath = resolve(repositoryRoot, "infra", "pki", "templates", "tenant-client-auth-v1.tpl");
const image = environment.STEP_CA_IMAGE;
if (!image) throw new Error("STEP_CA_IMAGE is required.");
if (!workingDirectory.startsWith(`${runtimeRoot}${sep}`)) throw new Error("Refusing to use a certificate test directory outside runtime.");

function runStep(args, label) {
  const result = spawnSync("docker", [
    "run",
    "--rm",
    "--mount",
    `type=bind,source=${workingDirectory},target=/work`,
    "--mount",
    `type=bind,source=${templatePath},target=/templates/tenant-client-auth-v1.tpl,readonly`,
    image,
    "step",
    ...args,
  ], {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
  return result.stdout;
}

function resolveContext({ tenantId, subjectId, roles }) {
  return resolveTenantContext({
    authentication: {
      source: "trusted-session",
      authenticationId: `issuance-verification:${subjectId}`,
      tenantId,
      subjectId,
    },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId, state: "active", version: 1 },
      membership: { tenantId, subjectId, state: "active", version: 1 },
      roles,
    },
  });
}

function clientRequest({ requestId, subjectId, csrPem, validity = 3600, key = "0001" }) {
  return {
    requestId,
    profileId: "tenant-client-auth-v1",
    subjectId,
    requestedValiditySeconds: validity,
    proofOfPossession: {
      publicKeyAlgorithm: "ecdsa-p256",
      csrPem,
      csrSha256: createHash("sha256").update(csrPem, "utf8").digest("hex"),
    },
    idempotencyKey: `certificate:issue:verification:${key}`,
  };
}

async function createIssuer(name, directory) {
  await mkdir(resolve(workingDirectory, directory), { recursive: true });
  runStep([
    "certificate", "create", name,
    `/work/${directory}/intermediate.crt`, `/work/${directory}/intermediate.key`,
    "--profile", "intermediate-ca",
    "--ca", "/work/platform-root.crt",
    "--ca-key", "/work/platform-root.key",
    "--kty", "EC",
    "--curve", "P-256",
    "--not-after", "8760h",
    "--no-password",
    "--insecure",
  ], `${name} creation`);
  return readFile(resolve(workingDirectory, directory, "intermediate.crt"), "utf8");
}

async function createCsr(name, directory) {
  await mkdir(resolve(workingDirectory, directory), { recursive: true });
  runStep([
    "certificate", "create", name,
    `/work/${directory}/request.csr`, `/work/${directory}/private.key`,
    "--csr",
    "--kty", "EC",
    "--curve", "P-256",
    "--no-password",
    "--insecure",
  ], `${name} key and CSR creation`);
  return readFile(resolve(workingDirectory, directory, "request.csr"), "utf8");
}

const memberships = new Map([
  [`${ids.alpha}:${ids.alice}`, { tenantId: ids.alpha, subjectId: ids.alice, tenantState: "active", subjectState: "active", membershipState: "active" }],
  [`${ids.alpha}:${ids.alphaAdmin}`, { tenantId: ids.alpha, subjectId: ids.alphaAdmin, tenantState: "active", subjectState: "active", membershipState: "active" }],
  [`${ids.beta}:${ids.bob}`, { tenantId: ids.beta, subjectId: ids.bob, tenantState: "active", subjectState: "active", membershipState: "active" }],
]);

let certificateSequence = 0;
try {
  await mkdir(workingDirectory, { recursive: true });
  runStep([
    "certificate", "create", "Tenant Trust Platform Root",
    "/work/platform-root.crt", "/work/platform-root.key",
    "--profile", "root-ca",
    "--kty", "EC",
    "--curve", "P-256",
    "--not-after", "87600h",
    "--no-password",
    "--insecure",
  ], "platform root creation");

  const alphaIssuerCertificate = await createIssuer("tenant-alpha-intermediate", "alpha-issuer");
  const betaIssuerCertificate = await createIssuer("tenant-beta-intermediate", "beta-issuer");
  assert.notEqual(
    createHash("sha256").update(alphaIssuerCertificate).digest("hex"),
    createHash("sha256").update(betaIssuerCertificate).digest("hex"),
  );

  const issuers = new Map([
    [ids.alpha, {
      tenantId: ids.alpha,
      issuerId: ids.alphaIssuer,
      issuerName: "tenant-alpha-intermediate",
      authorityUrl: "https://tenant-alpha-ca.internal:9000",
      state: "active",
      allowedCertificateOperations: ["issue", "renew", "revoke"],
      issuerCertificatePem: alphaIssuerCertificate,
      testDirectory: "alpha-issuer",
    }],
    [ids.beta, {
      tenantId: ids.beta,
      issuerId: ids.betaIssuer,
      issuerName: "tenant-beta-intermediate",
      authorityUrl: "https://tenant-beta-ca.internal:9000",
      state: "active",
      allowedCertificateOperations: ["issue", "renew", "revoke"],
      issuerCertificatePem: betaIssuerCertificate,
      testDirectory: "beta-issuer",
    }],
  ]);

  const signerCalls = [];
  async function signWithIssuer(instruction, issuerDirectory = issuers.get(instruction.tenantId).testDirectory) {
    signerCalls.push(instruction);
    certificateSequence += 1;
    const requestFile = `signing-request-${certificateSequence}.json`;
    const csrFile = `signing-request-${certificateSequence}.csr`;
    await writeFile(resolve(workingDirectory, requestFile), `${JSON.stringify({
      tenantId: instruction.tenantId,
      subjectId: instruction.subjectId,
      identityUri: instruction.subjectAlternativeNames[0],
    })}\n`, "utf8");
    await writeFile(resolve(workingDirectory, csrFile), instruction.csrPem, "utf8");
    const certificatePem = runStep([
      "certificate", "sign",
      `/work/${csrFile}`,
      `/work/${issuerDirectory}/intermediate.crt`,
      `/work/${issuerDirectory}/intermediate.key`,
      "--template", "/templates/tenant-client-auth-v1.tpl",
      "--set-file", `/work/${requestFile}`,
      "--not-before", instruction.notBefore,
      "--not-after", instruction.notAfter,
      "--omit-cn-san",
    ], "tenant certificate signing");
    return { certificatePem };
  }

  const loadTargetMembership = async ({ tenantId, subjectId }) => memberships.get(`${tenantId}:${subjectId}`) ?? null;
  const resolveIssuer = async ({ tenantId }) => issuers.get(tenantId) ?? null;
  const inventoryRecords = new Map();
  const inventoryService = createCertificateInventoryService({
    insertIssuedCertificate: async (record) => {
      inventoryRecords.set(record.certificateId, record);
      return { certificateId: record.certificateId, eventId: record.issuedEventId, state: record.state };
    },
  });
  const recordIssuedCertificate = inventoryService.recordIssuedCertificate;
  const service = createCertificateIssuanceService({
    loadTargetMembership,
    resolveIssuer,
    signCertificate: signWithIssuer,
    recordIssuedCertificate,
  });

  const alphaCsr = await createCsr(ids.alice, "alpha-subject");
  const betaCsr = await createCsr(ids.bob, "beta-subject");
  const alphaContext = resolveContext({ tenantId: ids.alpha, subjectId: ids.alice, roles: ["tenant-member"] });
  const betaContext = resolveContext({ tenantId: ids.beta, subjectId: ids.bob, roles: ["tenant-member"] });

  const alphaCertificate = await service.issue({
    context: alphaContext,
    request: clientRequest({ requestId: "req_018f1234-5678-7abc-8def-0123456789c2", subjectId: ids.alice, csrPem: alphaCsr, key: "alpha" }),
  });
  const betaCertificate = await service.issue({
    context: betaContext,
    request: clientRequest({ requestId: "req_018f1234-5678-7abc-8def-0123456789c3", subjectId: ids.bob, csrPem: betaCsr, key: "beta" }),
  });
  assert.equal(alphaCertificate.issuerId, ids.alphaIssuer);
  assert.equal(betaCertificate.issuerId, ids.betaIssuer);
  assert.match(alphaCertificate.certificateId, /^crt_/u);
  assert.match(alphaCertificate.issuedEventId, /^evt_/u);
  assert.equal(inventoryRecords.size, 2);
  assert.notEqual(alphaCertificate.fingerprintSha256, betaCertificate.fingerprintSha256);
  assert.equal(signerCalls.some((call) => JSON.stringify(call).includes("PRIVATE KEY")), false);
  console.log("PASS authorized Alpha and Beta subjects generated keys and received tenant-bound client certificates");

  const callsBeforeDenial = signerCalls.length;
  await assert.rejects(
    service.issue({
      context: alphaContext,
      request: clientRequest({ requestId: "req_018f1234-5678-7abc-8def-0123456789c4", subjectId: ids.alphaAdmin, csrPem: alphaCsr, key: "unauthorized" }),
    }),
    (error) => error instanceof CertificateIssuanceError && error.reasonCode === "SUBJECT_ENROLLMENT_UNAUTHORIZED",
  );
  assert.equal(signerCalls.length, callsBeforeDenial);
  console.log("PASS unauthorized enrollment was denied before the signer was called");

  const alphaAdminContext = resolveContext({ tenantId: ids.alpha, subjectId: ids.alphaAdmin, roles: ["tenant-admin"] });
  await assert.rejects(
    service.issue({
      context: alphaAdminContext,
      request: clientRequest({ requestId: "req_018f1234-5678-7abc-8def-0123456789c5", subjectId: ids.bob, csrPem: betaCsr, key: "foreign-subject" }),
    }),
    (error) => error instanceof CertificateIssuanceError && error.reasonCode === "TARGET_MEMBERSHIP_INACTIVE",
  );
  console.log("PASS a tenant administrator could not enroll a foreign-tenant subject");

  const foreignMappingService = createCertificateIssuanceService({
    loadTargetMembership,
    resolveIssuer: async () => issuers.get(ids.beta),
    signCertificate: signWithIssuer,
    recordIssuedCertificate,
  });
  await assert.rejects(
    foreignMappingService.issue({
      context: alphaContext,
      request: clientRequest({ requestId: "req_018f1234-5678-7abc-8def-0123456789c6", subjectId: ids.alice, csrPem: alphaCsr, key: "foreign-mapping" }),
    }),
    (error) => error instanceof CertificateIssuanceError && error.reasonCode === "ISSUER_TENANT_MISMATCH",
  );
  console.log("PASS trusted-context issuer resolution rejected a foreign-tenant mapping");

  const wrongSignerService = createCertificateIssuanceService({
    loadTargetMembership,
    resolveIssuer,
    signCertificate: (instruction) => signWithIssuer(instruction, "beta-issuer"),
    recordIssuedCertificate,
  });
  await assert.rejects(
    wrongSignerService.issue({
      context: alphaContext,
      request: clientRequest({ requestId: "req_018f1234-5678-7abc-8def-0123456789c7", subjectId: ids.alice, csrPem: alphaCsr, key: "wrong-signer" }),
    }),
    (error) => error instanceof CertificateIssuanceError && error.reasonCode === "CERTIFICATE_ISSUER_MISMATCH",
  );
  console.log("PASS a certificate signed by the foreign tenant issuer was rejected cryptographically");

  assert.deepEqual(
    certificateIssuanceSafeDenial(new CertificateIssuanceError("TARGET_MEMBERSHIP_INACTIVE")),
    { statusCode: 403, code: "CERTIFICATE_ENROLLMENT_DENIED" },
  );
  console.log("Certificate issuance verification passed.");
} finally {
  if (!workingDirectory.startsWith(`${runtimeRoot}${sep}`)) throw new Error("Refusing to remove a directory outside runtime.");
  await rm(workingDirectory, { recursive: true, force: true });
}
