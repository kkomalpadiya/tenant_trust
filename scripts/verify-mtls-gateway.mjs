import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import { createServer as createNetServer } from "node:net";
import { resolve, sep } from "node:path";
import {
  GatewayIdentityError,
  createGatewayIdentityResolver,
  gatewayIdentitySafeDenial,
} from "@tenant-trust/gateway-identity";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const ids = {
  alphaTenant: `tnt_${randomUUID()}`,
  alphaSubject: `sub_${randomUUID()}`,
  alphaIssuer: `iss_${randomUUID()}`,
  betaTenant: `tnt_${randomUUID()}`,
  betaSubject: `sub_${randomUUID()}`,
  betaIssuer: `iss_${randomUUID()}`,
};
const runtimeRoot = resolve(repositoryRoot, "runtime");
const workingDirectory = resolve(runtimeRoot, `mtls-gateway-${randomUUID()}`);
const gatewayConfigPath = resolve(repositoryRoot, "infra", "gateway", "nginx.conf");
const clientTemplatePath = resolve(repositoryRoot, "infra", "pki", "templates", "tenant-client-auth-v1.tpl");
const containerName = `tenant-trust-mtls-gateway-${randomUUID()}`;
if (!workingDirectory.startsWith(`${runtimeRoot}${sep}`)) throw new Error("Refusing an mTLS directory outside ignored runtime storage.");

function parseEnvironment(text) {
  return Object.fromEntries(text.split(/\r?\n/u)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    }));
}

const exampleEnvironment = parseEnvironment(await readFile(resolve(repositoryRoot, ".env.example"), "utf8"));
const stepImage = environment.STEP_CA_IMAGE || exampleEnvironment.STEP_CA_IMAGE;
const nginxImage = environment.NGINX_IMAGE || exampleEnvironment.NGINX_IMAGE;
for (const [name, image] of [["STEP_CA_IMAGE", stepImage], ["NGINX_IMAGE", nginxImage]]) {
  if (!image?.includes("@sha256:")) throw new Error(`${name} must be digest-pinned.`);
}

function run(command, args, label, { allowFailure = false } = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.status !== 0 && !allowFailure) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
  return result;
}

function runStep(args, label) {
  return run("docker", [
    "run", "--rm",
    "--mount", `type=bind,source=${workingDirectory},target=/work`,
    "--mount", `type=bind,source=${clientTemplatePath},target=/templates/tenant-client-auth-v1.tpl,readonly`,
    stepImage, "step", ...args,
  ], label).stdout;
}

async function createRoot(commonName, prefix) {
  runStep([
    "certificate", "create", commonName,
    `/work/${prefix}-root.crt`, `/work/${prefix}-root.key`,
    "--profile", "root-ca", "--kty", "EC", "--curve", "P-256",
    "--not-after", "87600h", "--no-password", "--insecure",
  ], `${commonName} creation`);
}

async function createIntermediate(commonName, prefix, rootPrefix) {
  runStep([
    "certificate", "create", commonName,
    `/work/${prefix}-intermediate.crt`, `/work/${prefix}-intermediate.key`,
    "--profile", "intermediate-ca",
    "--ca", `/work/${rootPrefix}-root.crt`,
    "--ca-key", `/work/${rootPrefix}-root.key`,
    "--kty", "EC", "--curve", "P-256",
    "--not-after", "8760h", "--no-password", "--insecure",
  ], `${commonName} creation`);
}

async function createServiceCertificate(commonName, dnsName, prefix, rootPrefix) {
  runStep([
    "certificate", "create", commonName,
    `/work/${prefix}.crt`, `/work/${prefix}.key`,
    "--profile", "leaf",
    "--ca", `/work/${rootPrefix}-root.crt`,
    "--ca-key", `/work/${rootPrefix}-root.key`,
    "--san", dnsName,
    "--kty", "EC", "--curve", "P-256",
    "--not-after", "24h", "--no-password", "--insecure",
  ], `${commonName} creation`);
}

async function createClientCertificate({ issuerPrefix, outputPrefix, tenantId, subjectId }) {
  runStep([
    "certificate", "create", subjectId,
    `/work/${outputPrefix}.csr`, `/work/${outputPrefix}.key`,
    "--csr", "--kty", "EC", "--curve", "P-256", "--no-password", "--insecure",
  ], `${outputPrefix} CSR creation`);
  await writeFile(resolve(workingDirectory, `${outputPrefix}.json`), `${JSON.stringify({
    tenantId,
    subjectId,
    identityUri: `urn:tenant-trust:identity:v1:tenant:${tenantId}:subject:${subjectId}`,
  })}\n`, "utf8");
  const now = Date.now();
  const certificate = runStep([
    "certificate", "sign",
    `/work/${outputPrefix}.csr`,
    `/work/${issuerPrefix}-intermediate.crt`,
    `/work/${issuerPrefix}-intermediate.key`,
    "--template", "/templates/tenant-client-auth-v1.tpl",
    "--set-file", `/work/${outputPrefix}.json`,
    "--not-before", new Date(now - 60_000).toISOString(),
    "--not-after", new Date(now + 3_600_000).toISOString(),
    "--omit-cn-san",
  ], `${outputPrefix} certificate signing`);
  await writeFile(resolve(workingDirectory, `${outputPrefix}.crt`), certificate, "utf8");
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createNetServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close((error) => error ? reject(error) : resolvePort(address.port));
    });
  });
}

function request(options) {
  return new Promise((resolveResponse, reject) => {
    const outgoing = httpsRequest({ ...options, method: "GET", agent: false }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolveResponse({
        statusCode: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    outgoing.setTimeout(5_000, () => outgoing.destroy(new Error("HTTPS request timed out.")));
    outgoing.on("error", reject);
    outgoing.end();
  });
}

async function waitForGateway(options) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const response = await request(options);
      if (response.statusCode) return;
    } catch {
      // The listener can refuse connections briefly while NGINX starts.
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  const logs = run("docker", ["logs", containerName], "NGINX startup logs", { allowFailure: true });
  throw new Error(`NGINX did not become ready.\n${(logs.stderr || logs.stdout).trim()}`);
}

let apiServer;
let containerStarted = false;
let primaryFailure;
let cleanupFailure;
let applicationRequestCount = 0;
let lastApplicationHeaders;
let lastApplicationRawHeaders;

try {
  await mkdir(workingDirectory, { recursive: true });
  await createRoot("Tenant Trust Platform Client Root", "platform-client");
  await createIntermediate("tenant-alpha-intermediate", "alpha", "platform-client");
  await createIntermediate("tenant-beta-intermediate", "beta", "platform-client");
  await createRoot("Tenant Trust Edge Root", "edge");
  await createRoot("Tenant Trust Internal Root", "internal");
  await createServiceCertificate("gateway.tenant-trust.local", "gateway.tenant-trust.local", "edge-server", "edge");
  await createServiceCertificate("tenant-trust-api.internal", "tenant-trust-api.internal", "api-server", "internal");
  await createServiceCertificate("tenant-trust-gateway", "tenant-trust-gateway.internal", "gateway-client", "internal");
  await createServiceCertificate("untrusted-internal-client", "untrusted-internal-client.internal", "untrusted-internal-client", "internal");
  await createClientCertificate({
    issuerPrefix: "alpha",
    outputPrefix: "alpha-client",
    tenantId: ids.alphaTenant,
    subjectId: ids.alphaSubject,
  });
  await createClientCertificate({
    issuerPrefix: "beta",
    outputPrefix: "beta-client",
    tenantId: ids.betaTenant,
    subjectId: ids.betaSubject,
  });
  await createClientCertificate({
    issuerPrefix: "beta",
    outputPrefix: "wrong-issuer-client",
    tenantId: ids.alphaTenant,
    subjectId: ids.alphaSubject,
  });

  const [
    internalRoot,
    apiServerCertificate,
    apiServerKey,
    gatewayClientCertificate,
    untrustedInternalClientCertificate,
    untrustedInternalClientKey,
    alphaIssuerCertificate,
    betaIssuerCertificate,
  ] = await Promise.all([
    readFile(resolve(workingDirectory, "internal-root.crt"), "utf8"),
    readFile(resolve(workingDirectory, "api-server.crt"), "utf8"),
    readFile(resolve(workingDirectory, "api-server.key"), "utf8"),
    readFile(resolve(workingDirectory, "gateway-client.crt"), "utf8"),
    readFile(resolve(workingDirectory, "untrusted-internal-client.crt"), "utf8"),
    readFile(resolve(workingDirectory, "untrusted-internal-client.key"), "utf8"),
    readFile(resolve(workingDirectory, "alpha-intermediate.crt"), "utf8"),
    readFile(resolve(workingDirectory, "beta-intermediate.crt"), "utf8"),
  ]);
  const issuers = new Map([
    [ids.alphaTenant, {
      tenantId: ids.alphaTenant,
      issuerId: ids.alphaIssuer,
      state: "active",
      issuerCertificatePem: alphaIssuerCertificate,
    }],
    [ids.betaTenant, {
      tenantId: ids.betaTenant,
      issuerId: ids.betaIssuer,
      state: "active",
      issuerCertificatePem: betaIssuerCertificate,
    }],
  ]);
  const identityResolver = createGatewayIdentityResolver({
    trustedGatewayCertificatePem: gatewayClientCertificate,
    resolveTenantIssuer: async ({ tenantId }) => issuers.get(tenantId) ?? null,
  });

  apiServer = createHttpsServer({
    key: apiServerKey,
    cert: apiServerCertificate,
    ca: internalRoot,
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
  }, async (incoming, response) => {
    if (incoming.method !== "GET" || incoming.url !== "/__t41/identity") {
      response.writeHead(404, { "content-type": "application/json", connection: "close" });
      response.end('{"code":"NOT_FOUND"}\n');
      return;
    }
    applicationRequestCount += 1;
    lastApplicationHeaders = { ...incoming.headers };
    lastApplicationRawHeaders = [...incoming.rawHeaders];
    try {
      const identity = await identityResolver.resolve({ socket: incoming.socket, headers: incoming.headers });
      response.writeHead(200, { "content-type": "application/json", connection: "close" });
      response.end(`${JSON.stringify(identity)}\n`);
    } catch (error) {
      if (!(error instanceof GatewayIdentityError)) throw error;
      response.writeHead(401, { "content-type": "application/json", connection: "close" });
      response.end(`${JSON.stringify(gatewayIdentitySafeDenial(error))}\n`);
    }
  });
  await new Promise((resolveListen, reject) => {
    apiServer.once("error", reject);
    apiServer.listen(0, "0.0.0.0", resolveListen);
  });
  const apiPort = apiServer.address().port;

  const nginxConfig = await readFile(gatewayConfigPath, "utf8");
  const verificationConfig = nginxConfig.replace(
    "https://tenant-trust-api:8444",
    `https://host.docker.internal:${apiPort}`,
  );
  if (verificationConfig === nginxConfig) throw new Error("The verification upstream placeholder was not found.");
  await writeFile(resolve(workingDirectory, "nginx.conf"), verificationConfig, "utf8");

  const gatewayPort = await freePort();
  run("docker", [
    "run", "-d", "--name", containerName,
    "--add-host", "host.docker.internal:host-gateway",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/var/cache/nginx",
    "--tmpfs", "/var/run",
    "--tmpfs", "/tmp",
    "-p", `127.0.0.1:${gatewayPort}:8443`,
    "--mount", `type=bind,source=${workingDirectory},target=/run/tenant-trust,readonly`,
    "--entrypoint", "nginx",
    nginxImage,
    "-c", "/run/tenant-trust/nginx.conf",
    "-g", "daemon off;",
  ], "NGINX mTLS gateway startup");
  containerStarted = true;

  const edgeRoot = await readFile(resolve(workingDirectory, "edge-root.crt"), "utf8");
  const baseRequest = {
    host: "127.0.0.1",
    port: gatewayPort,
    path: "/__t41/identity",
    servername: "gateway.tenant-trust.local",
    ca: edgeRoot,
    rejectUnauthorized: true,
  };
  await waitForGateway(baseRequest);

  const alphaClientCertificate = await readFile(resolve(workingDirectory, "alpha-client.crt"), "utf8");
  const alphaClientKey = await readFile(resolve(workingDirectory, "alpha-client.key"), "utf8");
  const betaClientCertificate = await readFile(resolve(workingDirectory, "beta-client.crt"), "utf8");
  const forgedHeaders = {
    "Tenant-Trust-Gateway-Version": "1",
    "Tenant-Trust-Client-Verification": "SUCCESS",
    "Tenant-Trust-Forwarded-Protocol": "TLSv1.3",
    "Tenant-Trust-Client-Certificate": encodeURIComponent(betaClientCertificate),
    "X-Forwarded-Client-Cert": encodeURIComponent(betaClientCertificate),
    "X-Client-Cert": encodeURIComponent(betaClientCertificate),
    "X-SSL-Client-Cert": encodeURIComponent(betaClientCertificate),
    "X-Tenant-Id": ids.betaTenant,
    "X-Subject-Id": ids.betaSubject,
  };
  const accepted = await request({
    ...baseRequest,
    cert: `${alphaClientCertificate}${alphaIssuerCertificate}`,
    key: alphaClientKey,
  });
  assert.equal(accepted.statusCode, 200);
  const identity = JSON.parse(accepted.body);
  assert.equal(identity.source, "mtls-certificate");
  assert.equal(identity.tenantId, ids.alphaTenant);
  assert.equal(identity.subjectId, ids.alphaSubject);
  assert.equal(identity.certificate.issuerId, ids.alphaIssuer);
  assert.match(identity.authenticationId, /^sha256:[0-9a-f]{64}$/u);
  console.log("PASS NGINX accepted a valid tenant client chain and the application derived its tenant-bound identity");

  const requestCountBeforeMissingCertificate = applicationRequestCount;
  const missingCertificate = await request({ ...baseRequest, headers: forgedHeaders });
  assert.ok(missingCertificate.statusCode >= 400);
  assert.equal(applicationRequestCount, requestCountBeforeMissingCertificate);
  console.log("PASS forged identity headers could not bypass NGINX client-certificate authentication");

  const overwritten = await request({
    ...baseRequest,
    cert: `${alphaClientCertificate}${alphaIssuerCertificate}`,
    key: alphaClientKey,
    headers: forgedHeaders,
  });
  assert.equal(overwritten.statusCode, 200);
  const overwrittenIdentity = JSON.parse(overwritten.body);
  assert.equal(overwrittenIdentity.tenantId, ids.alphaTenant);
  assert.equal(overwrittenIdentity.subjectId, ids.alphaSubject);
  assert.equal(overwrittenIdentity.certificate.issuerId, ids.alphaIssuer);
  for (const headerName of [
    "x-forwarded-client-cert",
    "x-client-cert",
    "x-ssl-client-cert",
    "x-tenant-id",
    "x-subject-id",
  ]) assert.equal(lastApplicationHeaders[headerName], undefined);
  for (const headerName of [
    "tenant-trust-gateway-version",
    "tenant-trust-client-verification",
    "tenant-trust-forwarded-protocol",
    "tenant-trust-client-certificate",
  ]) {
    assert.equal(lastApplicationRawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === headerName).length, 1);
  }
  console.log("PASS NGINX replaced forged gateway identity headers and removed ambient tenant, subject and certificate headers");

  const wrongIssuerCertificate = await readFile(resolve(workingDirectory, "wrong-issuer-client.crt"), "utf8");
  const wrongIssuerKey = await readFile(resolve(workingDirectory, "wrong-issuer-client.key"), "utf8");
  const wrongIssuer = await request({
    ...baseRequest,
    cert: `${wrongIssuerCertificate}${betaIssuerCertificate}`,
    key: wrongIssuerKey,
  });
  assert.equal(wrongIssuer.statusCode, 401);
  assert.deepEqual(JSON.parse(wrongIssuer.body), { statusCode: 401, code: "CLIENT_CERTIFICATE_REQUIRED" });
  console.log("PASS the application rejected a platform-root-valid certificate signed by the wrong tenant issuer");

  const requestCountBeforeUnauthenticatedBypass = applicationRequestCount;
  await assert.rejects(request({
    host: "127.0.0.1",
    port: apiPort,
    path: "/__t41/identity",
    servername: "tenant-trust-api.internal",
    ca: internalRoot,
    rejectUnauthorized: true,
    headers: forgedHeaders,
  }));
  assert.equal(applicationRequestCount, requestCountBeforeUnauthenticatedBypass);
  console.log("PASS direct forged-header access without an internal client certificate never reached the protected handler");

  const untrustedInternalBypass = await request({
    host: "127.0.0.1",
    port: apiPort,
    path: "/__t41/identity",
    servername: "tenant-trust-api.internal",
    ca: internalRoot,
    cert: untrustedInternalClientCertificate,
    key: untrustedInternalClientKey,
    rejectUnauthorized: true,
    headers: forgedHeaders,
  });
  assert.equal(untrustedInternalBypass.statusCode, 401);
  assert.deepEqual(JSON.parse(untrustedInternalBypass.body), { statusCode: 401, code: "CLIENT_CERTIFICATE_REQUIRED" });
  console.log("PASS an internal-CA-valid non-gateway certificate could not use forged headers to impersonate the pinned gateway");
} catch (error) {
  primaryFailure = error;
} finally {
  if (containerStarted) {
    const removed = run("docker", ["rm", "-f", containerName], "NGINX mTLS gateway cleanup", { allowFailure: true });
    if (removed.status !== 0) cleanupFailure = new Error((removed.stderr || removed.stdout).trim() || "NGINX cleanup failed.");
  }
  if (apiServer?.listening) {
    apiServer.closeAllConnections?.();
    await new Promise((resolveClose) => apiServer.close(resolveClose));
  }
  await rm(workingDirectory, { recursive: true, force: true });

  const containerInspection = run("docker", ["container", "inspect", containerName], "NGINX cleanup check", { allowFailure: true });
  if (containerInspection.status === 0) cleanupFailure = new Error(`Disposable container ${containerName} still exists.`);
  try {
    await stat(workingDirectory);
    cleanupFailure = new Error("Disposable mTLS key directory still exists.");
  } catch (error) {
    if (error.code !== "ENOENT") cleanupFailure = error;
  }
}

if (primaryFailure) throw primaryFailure;
if (cleanupFailure) throw cleanupFailure;
console.log("mTLS gateway spoofing and bypass verification passed and removed its container and generated private keys.");
