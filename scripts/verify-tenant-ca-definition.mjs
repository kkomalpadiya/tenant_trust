import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");
const definitionPath = resolve(repositoryRoot, "infra/pki/tenant-ca-hierarchy.json");
const seedPath = resolve(repositoryRoot, "database/seeds/003_demo_security_configuration.sql");
const definition = JSON.parse(await readFile(definitionPath, "utf8"));
const seed = await readFile(seedPath, "utf8");

const tenantIdPattern = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const issuerIdPattern = /^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const expectedCertificateOperations = ["issue", "renew", "revoke"];

function requireNonEmptyString(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.ok(value.length > 0, `${label} must not be empty`);
}

function assertUnique(items, selector, label) {
  const values = items.map(selector);
  assert.equal(new Set(values).size, values.length, `${label} must be unique per tenant issuer`);
}

function assertNoEmbeddedSecretMaterial(value, path = "definition") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoEmbeddedSecretMaterial(entry, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;

  for (const [key, child] of Object.entries(value)) {
    assert.ok(
      !["password", "privateKey", "privateKeyPem", "secret", "token"].includes(key),
      `${path}.${key} must be represented by an external reference, not committed material`,
    );
    assertNoEmbeddedSecretMaterial(child, `${path}.${key}`);
  }
}

assert.equal(definition.schemaVersion, "1.0.0");
requireNonEmptyString(definition.trustDomain, "trustDomain");

const { platformRoot, issuerSelection, issuers } = definition;
assert.equal(platformRoot.rootId, "tenant-trust-platform-root");
assert.equal(platformRoot.version, 1);
assert.equal(platformRoot.availability, "offline");
assert.deepEqual(platformRoot.permittedSigningPurposes, ["tenant-intermediate"]);
assert.equal(platformRoot.privateKeyCustody.online, false);
assert.equal(platformRoot.privateKeyCustody.exportable, false);
requireNonEmptyString(platformRoot.certificateBundleReference, "platform root certificate bundle reference");
requireNonEmptyString(platformRoot.privateKeyCustody.keyReference, "platform root key reference");

assert.equal(issuerSelection.source, "validated-tenant-context");
assert.equal(issuerSelection.clientSuppliedIssuerAccepted, false);
assert.equal(issuerSelection.mappingAuthority, "identity.tenant_issuer_mappings");

assert.equal(issuers.length, 2, "the demonstration definition must contain exactly two tenant issuers");
for (const issuer of issuers) {
  assert.match(issuer.tenantId, tenantIdPattern);
  assert.match(issuer.issuerId, issuerIdPattern);
  assert.equal(issuer.state, "planned");
  assert.equal(issuer.parentRootId, platformRoot.rootId);
  assert.equal(issuer.parentRootVersion, platformRoot.version);

  const authorityUrl = new URL(issuer.authorityUrl);
  assert.equal(authorityUrl.protocol, "https:");
  assert.ok(issuer.dnsNames.includes(authorityUrl.hostname));
  requireNonEmptyString(issuer.stateBoundary, `${issuer.issuerName} state boundary`);
  requireNonEmptyString(issuer.configurationBoundary, `${issuer.issuerName} configuration boundary`);
  requireNonEmptyString(issuer.intermediateCertificateReference, `${issuer.issuerName} certificate reference`);
  requireNonEmptyString(issuer.intermediateKeyCustody.keyReference, `${issuer.issuerName} key reference`);
  assert.equal(issuer.intermediateKeyCustody.exportable, false);

  requireNonEmptyString(issuer.provisioner.name, `${issuer.issuerName} provisioner`);
  requireNonEmptyString(issuer.provisioner.credentialReference, `${issuer.issuerName} provisioner credential reference`);
  assert.equal(issuer.provisioner.credentialStoredInGit, false);

  assert.equal(issuer.authorization.lifecycleOperator, "platform-pki-operator");
  requireNonEmptyString(issuer.authorization.certificateServicePrincipal, `${issuer.issuerName} certificate service principal`);
  assert.deepEqual(issuer.authorization.allowedCertificateOperations, expectedCertificateOperations);
  assert.equal(issuer.authorization.tenantAdminDirectCaAccess, false);

  for (const expectedSeedValue of [issuer.tenantId, issuer.issuerId, issuer.issuerName, issuer.authorityUrl]) {
    assert.ok(seed.includes(`'${expectedSeedValue}'`), `${issuer.issuerName} must match its planned database seed mapping`);
  }
}

for (const [selector, label] of [
  [(issuer) => issuer.tenantId, "tenant IDs"],
  [(issuer) => issuer.issuerId, "issuer IDs"],
  [(issuer) => issuer.issuerName, "issuer names"],
  [(issuer) => issuer.authorityUrl, "authority URLs"],
  [(issuer) => issuer.stateBoundary, "state boundaries"],
  [(issuer) => issuer.configurationBoundary, "configuration boundaries"],
  [(issuer) => issuer.intermediateKeyCustody.keyReference, "intermediate key references"],
  [(issuer) => issuer.provisioner.name, "provisioners"],
  [(issuer) => issuer.provisioner.credentialReference, "provisioner credential references"],
  [(issuer) => issuer.authorization.certificateServicePrincipal, "certificate service principals"],
]) {
  assertUnique(issuers, selector, label);
}

assertNoEmbeddedSecretMaterial(definition);

console.log("PASS one offline platform root can sign only tenant intermediates");
console.log("PASS Tenant Alpha and Tenant Beta have distinct issuer, state, key, provisioner and service-principal boundaries");
console.log("PASS issuer selection comes only from validated tenant context and matches the planned database mappings");
console.log("PASS committed PKI definition contains references and custody rules, not private keys or credentials");
