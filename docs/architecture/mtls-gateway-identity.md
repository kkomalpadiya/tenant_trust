# mTLS gateway and application identity

## Trust boundaries

NGINX 1.31.3 is the selected client-facing gateway. Its image is digest-pinned in `.env.example`. The gateway listens only with TLS 1.2 or TLS 1.3, requires a client certificate, validates the complete presented chain against the platform client root and allows an intermediate depth suitable for the tenant CA hierarchy.

The client connection and the gateway-to-application connection use different trust domains. NGINX authenticates to the application with a dedicated internal client certificate and verifies the application's internal server certificate. The application TLS listener must require the internal CA and reject unauthorized peers. `@tenant-trust/gateway-identity` then pins the exact gateway leaf certificate, so another certificate from the internal CA cannot become an identity-forwarding gateway.

Generated server, gateway and client private keys belong only in ignored runtime storage or an external secret manager. `infra/gateway/nginx.conf` contains paths and policy, not credentials.

## Forwarded identity contract

NGINX owns and overwrites exactly four application inputs:

| Header | Gateway value |
| --- | --- |
| `Tenant-Trust-Gateway-Version` | Literal contract version `1` |
| `Tenant-Trust-Client-Verification` | NGINX `$ssl_client_verify`, which must be `SUCCESS` |
| `Tenant-Trust-Forwarded-Protocol` | Negotiated client TLS protocol |
| `Tenant-Trust-Client-Certificate` | URL-escaped PEM from `$ssl_client_escaped_cert` |

The configuration clears common certificate, tenant and subject headers and does not log the forwarded certificate. Application code ignores every other certificate or identity header. The four values are not trusted by themselves: `createGatewayIdentityResolver` checks the authenticated internal TLS socket and exact gateway certificate before reading them.

The resolver then parses the forwarded X.509 certificate, requires the `tenant-client-auth-v1` opaque subject and single URI SAN, requires an allowed P-256 or Ed25519 client-authentication key, checks current validity, and resolves the active tenant issuer from the parsed tenant ID. It verifies the leaf directly with that issuer certificate. A chain accepted by the platform root is therefore insufficient when the leaf was signed by another tenant's intermediate.

The immutable output has `mtls-certificate` provenance, a SHA-256 authentication identity, the tenant and subject IDs, and bounded certificate metadata. It contains no role, policy or trust claims. The later API adapter must still load authoritative inventory status, tenant, subject, membership and roles before calling `resolveTenantContext`. Unknown, stale, revoked or superseded status remains a denial.

## Verification

Run:

```powershell
npm run mtls-gateway:verify
```

The gate creates disposable edge, internal and tenant certificate chains in ignored runtime storage, starts a digest-pinned NGINX container and a TLS application receiver, and proves:

- a valid tenant client chain reaches the application as the expected tenant-bound identity;
- a missing client certificate is rejected at NGINX;
- a platform-root-valid certificate signed by the wrong tenant issuer is rejected by the application;
- the application TLS listener rejects a connection without the gateway's internal certificate.

The gate removes its container and generated private keys in `finally`. It does not claim to complete T4.2: forged-header permutations and route-level direct-bypass testing remain the next task.
