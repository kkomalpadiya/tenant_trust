import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GATEWAY_IDENTITY_DENIAL,
  GATEWAY_IDENTITY_HEADERS,
  GatewayIdentityError,
  createGatewayIdentityResolver,
  gatewayIdentitySafeDenial,
} from "../src/index.mjs";

const publicGatewayCertificate = `-----BEGIN CERTIFICATE-----
MIIByDCCAW6gAwIBAgIQWF90QIXwvSxfnDj8rHjiGTAKBggqhkjOPQQDAjAXMRUw
EwYDVQQDEwxGaXh0dXJlIFJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzUwMTAxMDAw
MDAwWjAfMR0wGwYDVQQDExR0ZW5hbnQtdHJ1c3QtZ2F0ZXdheTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABOP0WPpDqQbn2kvU8TGz3fWuYEHPk56dhQAVTWx6IozM
dNsnG6H0iYBSWzSnGAJuuxPve75Rvei2YdKgK5zh1a+jgZMwgZAwDgYDVR0PAQH/
BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU
DAaHOzEqKxmTnvWJ4YBAW0PeZ2gwHwYDVR0jBBgwFoAURc55zrMtKGVWfbRLsKid
113D7SEwHwYDVR0RBBgwFoIUdGVuYW50LXRydXN0LWdhdGV3YXkwCgYIKoZIzj0E
AwIDSAAwRQIhAJAWntHMBbbcr4JyalGfWVJP4+54Us2fze8Ta3loQdHaAiB3z+sO
05iuti6Jx/70nXoWrbn06Nzn2WcXRZa0eQLpbw==
-----END CERTIFICATE-----
`;

function resolver() {
  return createGatewayIdentityResolver({
    trustedGatewayCertificatePem: publicGatewayCertificate,
    resolveTenantIssuer: async () => null,
  });
}

test("publishes one versioned set of gateway-owned forwarding headers", () => {
  assert.deepEqual(GATEWAY_IDENTITY_HEADERS, {
    certificate: "tenant-trust-client-certificate",
    verification: "tenant-trust-client-verification",
    protocol: "tenant-trust-forwarded-protocol",
    version: "tenant-trust-gateway-version",
  });
  assert.ok(Object.isFrozen(GATEWAY_IDENTITY_HEADERS));
});

test("requires an exact configured gateway certificate and tenant issuer resolver", () => {
  assert.throws(() => createGatewayIdentityResolver(), /trusted gateway certificate/iu);
  assert.throws(
    () => createGatewayIdentityResolver({ trustedGatewayCertificatePem: publicGatewayCertificate }),
    /tenant issuer resolver/iu,
  );
  assert.throws(
    () => createGatewayIdentityResolver({
      trustedGatewayCertificatePem: `-----BEGIN CERTIFICATE-----\n${"A".repeat(96)}\n-----END CERTIFICATE-----\n`,
      resolveTenantIssuer: async () => null,
    }),
    (error) => error instanceof GatewayIdentityError && error.reasonCode === "GATEWAY_CERTIFICATE_INVALID",
  );
});

test("rejects forwarded identity before reading headers when the connection is not authenticated TLS", async () => {
  let issuerCalled = false;
  const identityResolver = createGatewayIdentityResolver({
    trustedGatewayCertificatePem: publicGatewayCertificate,
    resolveTenantIssuer: async () => { issuerCalled = true; return null; },
  });

  await assert.rejects(
    identityResolver.resolve({
      socket: { authorized: true },
      headers: {
        [GATEWAY_IDENTITY_HEADERS.version]: "1",
        [GATEWAY_IDENTITY_HEADERS.verification]: "SUCCESS",
        [GATEWAY_IDENTITY_HEADERS.protocol]: "TLSv1.3",
        [GATEWAY_IDENTITY_HEADERS.certificate]: encodeURIComponent(publicGatewayCertificate),
      },
    }),
    (error) => error instanceof GatewayIdentityError && error.reasonCode === "GATEWAY_CONNECTION_UNTRUSTED",
  );
  assert.equal(issuerCalled, false);
});

test("maps all gateway identity failures to one non-enumerating response", () => {
  assert.equal(
    gatewayIdentitySafeDenial(new GatewayIdentityError("CERTIFICATE_ISSUER_MISMATCH")),
    GATEWAY_IDENTITY_DENIAL,
  );
  assert.deepEqual(GATEWAY_IDENTITY_DENIAL, { statusCode: 401, code: "CLIENT_CERTIFICATE_REQUIRED" });
  assert.throws(() => gatewayIdentitySafeDenial(new Error("unrelated")), /unrelated/u);
});
