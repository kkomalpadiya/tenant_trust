import { createHash, timingSafeEqual, X509Certificate } from "node:crypto";
import { TLSSocket } from "node:tls";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ISSUER_ID = /^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SERIAL = /^(?!0{32}$)[0-9A-F]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";
const MAX_CERTIFICATE_HEADER_BYTES = 16 * 1024;

export const GATEWAY_IDENTITY_HEADERS = Object.freeze({
  certificate: "tenant-trust-client-certificate",
  verification: "tenant-trust-client-verification",
  protocol: "tenant-trust-forwarded-protocol",
  version: "tenant-trust-gateway-version",
});

export const GATEWAY_IDENTITY_DENIAL = Object.freeze({
  statusCode: 401,
  code: "CLIENT_CERTIFICATE_REQUIRED",
});

export class GatewayIdentityError extends Error {
  constructor(reasonCode) {
    super("Gateway identity validation failed.");
    this.name = "GatewayIdentityError";
    this.reasonCode = reasonCode;
  }
}

function deny(reasonCode) {
  throw new GatewayIdentityError(reasonCode);
}

function parseCertificate(value, reasonCode) {
  try {
    return new X509Certificate(value);
  } catch {
    deny(reasonCode);
  }
}

function certificateDigest(certificate) {
  return createHash("sha256").update(certificate.raw).digest();
}

function sameCertificate(first, second) {
  const firstDigest = certificateDigest(first);
  const secondDigest = certificateDigest(second);
  return firstDigest.length === secondDigest.length && timingSafeEqual(firstDigest, secondDigest);
}

function singleHeader(headers, name) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) deny("FORWARDED_HEADERS_INVALID");
  const entries = Object.entries(headers).filter(([key]) => key.toLowerCase() === name);
  if (entries.length !== 1 || typeof entries[0][1] !== "string" || entries[0][1].length === 0) {
    deny("FORWARDED_HEADER_INVALID");
  }
  return entries[0][1];
}

function decodeCertificateHeader(value) {
  if (Buffer.byteLength(value, "utf8") > MAX_CERTIFICATE_HEADER_BYTES) deny("FORWARDED_CERTIFICATE_INVALID");
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    deny("FORWARDED_CERTIFICATE_INVALID");
  }
  if (Buffer.byteLength(decoded, "utf8") > MAX_CERTIFICATE_HEADER_BYTES
    || !/^-----BEGIN CERTIFICATE-----\r?\n[\s\S]+\r?\n-----END CERTIFICATE-----\r?\n?$/u.test(decoded)) {
    deny("FORWARDED_CERTIFICATE_INVALID");
  }
  return decoded;
}

function parseDistinguishedName(value) {
  const entries = value.split(/\n|,\s*(?=[A-Z][A-Z0-9.]*=)/u).map((entry) => {
    const separator = entry.indexOf("=");
    return separator < 1 ? [entry, ""] : [entry.slice(0, separator), entry.slice(separator + 1)];
  });
  if (entries.length !== 2 || new Set(entries.map(([key]) => key)).size !== 2) deny("CERTIFICATE_IDENTITY_INVALID");
  return Object.fromEntries(entries);
}

function parseIdentity(certificate) {
  const subject = parseDistinguishedName(certificate.subject);
  if (Object.keys(subject).sort().join(",") !== "CN,O"
    || !TENANT_ID.test(subject.O ?? "")
    || !SUBJECT_ID.test(subject.CN ?? "")) {
    deny("CERTIFICATE_IDENTITY_INVALID");
  }
  const expectedUri = `urn:tenant-trust:identity:v1:tenant:${subject.O}:subject:${subject.CN}`;
  if (certificate.subjectAltName !== `URI:${expectedUri}`) deny("CERTIFICATE_SAN_INVALID");
  return Object.freeze({ tenantId: subject.O, subjectId: subject.CN });
}

function supportedPublicKey(certificate) {
  if (certificate.publicKey.asymmetricKeyType === "ed25519") return true;
  return certificate.publicKey.asymmetricKeyType === "ec"
    && ["prime256v1", "P-256"].includes(certificate.publicKey.asymmetricKeyDetails?.namedCurve);
}

function validateClientCertificateProfile(certificate, now) {
  if (certificate.ca || !supportedPublicKey(certificate)) deny("CERTIFICATE_PROFILE_INVALID");
  const usages = certificate.keyUsage ?? [];
  if (usages.length !== 1 || usages[0] !== CLIENT_AUTH_OID) deny("CERTIFICATE_PROFILE_INVALID");
  const notBefore = new Date(certificate.validFrom);
  const notAfter = new Date(certificate.validTo);
  if (!Number.isFinite(notBefore.getTime())
    || !Number.isFinite(notAfter.getTime())
    || now < notBefore
    || now >= notAfter) {
    deny("CERTIFICATE_TIME_INVALID");
  }
  return { notBefore, notAfter };
}

function validateTrustedGatewaySocket(socket, trustedGatewayCertificate) {
  if (!(socket instanceof TLSSocket)
    || socket.encrypted !== true
    || socket.authorized !== true
    || socket.authorizationError) {
    deny("GATEWAY_CONNECTION_UNTRUSTED");
  }
  const peer = socket.getPeerCertificate(false);
  if (!peer?.raw) deny("GATEWAY_CERTIFICATE_REQUIRED");
  const peerCertificate = parseCertificate(peer.raw, "GATEWAY_CERTIFICATE_INVALID");
  if (!sameCertificate(peerCertificate, trustedGatewayCertificate)) deny("GATEWAY_CERTIFICATE_MISMATCH");
}

function validateForwardingHeaders(headers) {
  if (singleHeader(headers, GATEWAY_IDENTITY_HEADERS.version) !== "1") deny("GATEWAY_PROTOCOL_INVALID");
  if (singleHeader(headers, GATEWAY_IDENTITY_HEADERS.verification) !== "SUCCESS") {
    deny("CLIENT_CERTIFICATE_UNVERIFIED");
  }
  const protocol = singleHeader(headers, GATEWAY_IDENTITY_HEADERS.protocol);
  if (protocol !== "TLSv1.2" && protocol !== "TLSv1.3") deny("CLIENT_TLS_PROTOCOL_INVALID");
  return decodeCertificateHeader(singleHeader(headers, GATEWAY_IDENTITY_HEADERS.certificate));
}

export function createGatewayIdentityResolver({
  trustedGatewayCertificatePem,
  resolveTenantIssuer,
  clock = () => new Date(),
} = {}) {
  if (typeof trustedGatewayCertificatePem !== "string" || trustedGatewayCertificatePem.length < 80) {
    throw new TypeError("A trusted gateway certificate is required.");
  }
  if (typeof resolveTenantIssuer !== "function") throw new TypeError("A tenant issuer resolver is required.");
  if (typeof clock !== "function") throw new TypeError("A trusted clock is required.");
  const trustedGatewayCertificate = parseCertificate(trustedGatewayCertificatePem, "GATEWAY_CERTIFICATE_INVALID");
  if (trustedGatewayCertificate.ca) throw new TypeError("The trusted gateway identity must be an end-entity certificate.");

  return Object.freeze({
    async resolve({ socket, headers } = {}) {
      validateTrustedGatewaySocket(socket, trustedGatewayCertificate);
      const certificatePem = validateForwardingHeaders(headers);
      const certificate = parseCertificate(certificatePem, "FORWARDED_CERTIFICATE_INVALID");
      const identity = parseIdentity(certificate);
      let now;
      try {
        now = clock();
      } catch {
        deny("AUTHENTICATION_TIME_INVALID");
      }
      if (!(now instanceof Date) || !Number.isFinite(now.getTime())) deny("AUTHENTICATION_TIME_INVALID");
      const { notBefore, notAfter } = validateClientCertificateProfile(certificate, now);

      let issuer;
      try {
        issuer = await resolveTenantIssuer({ tenantId: identity.tenantId });
      } catch {
        deny("TENANT_ISSUER_UNAVAILABLE");
      }
      if (!issuer
        || issuer.tenantId !== identity.tenantId
        || !ISSUER_ID.test(issuer.issuerId ?? "")
        || issuer.state !== "active"
        || typeof issuer.issuerCertificatePem !== "string") {
        deny("TENANT_ISSUER_UNAVAILABLE");
      }
      const issuerCertificate = parseCertificate(issuer.issuerCertificatePem, "TENANT_ISSUER_INVALID");
      if (!issuerCertificate.ca
        || !certificate.checkIssued(issuerCertificate)
        || !certificate.verify(issuerCertificate.publicKey)) {
        deny("CERTIFICATE_ISSUER_MISMATCH");
      }

      const serialNumber = certificate.serialNumber.toUpperCase().padStart(32, "0");
      const fingerprintSha256 = certificate.fingerprint256.replaceAll(":", "").toLowerCase();
      const publicKeySha256 = createHash("sha256")
        .update(certificate.publicKey.export({ type: "spki", format: "der" }))
        .digest("hex");
      if (!SERIAL.test(serialNumber) || !SHA256.test(fingerprintSha256) || !SHA256.test(publicKeySha256)) {
        deny("CERTIFICATE_METADATA_INVALID");
      }

      return Object.freeze({
        source: "mtls-certificate",
        authenticationId: `sha256:${fingerprintSha256}`,
        tenantId: identity.tenantId,
        subjectId: identity.subjectId,
        certificate: Object.freeze({
          profileId: "tenant-client-auth-v1",
          issuerId: issuer.issuerId,
          serialNumber,
          fingerprintSha256,
          publicKeySha256,
          notBefore: notBefore.toISOString(),
          notAfter: notAfter.toISOString(),
        }),
      });
    },
  });
}

export function gatewayIdentitySafeDenial(error) {
  if (!(error instanceof GatewayIdentityError)) throw error;
  return GATEWAY_IDENTITY_DENIAL;
}
