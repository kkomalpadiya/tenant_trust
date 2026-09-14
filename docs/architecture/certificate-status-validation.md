# Certificate status validation

## Selected mechanism

The prototype uses `application-status-v1`: every protected application request validates the presented certificate against the authoritative PostgreSQL certificate inventory. This is the required application authorization check in addition to ordinary X.509 chain, signature, hostname/purpose and validity validation at the TLS boundary.

The choice is deliberately independent of Smallstep feature assumptions. The configured CA may later publish a CRL or OCSP response, but neither is required for this prototype's access decision. CA-side revocation execution and distribution remain separate lifecycle work; the application can deny a certificate as soon as its inventory state changes.

## Authoritative lookup and binding

`@tenant-trust/certificate-status` receives only a resolver-branded tenant context and verified public certificate metadata. Its PostgreSQL adapter must run inside a transaction that has called `identity.set_tenant_actor_context`. The parameterized query matches all of these values together:

- tenant, subject and certificate IDs;
- issuer ID and issuer-scoped serial number;
- SHA-256 certificate fingerprint; and
- stored not-before and not-after timestamps.

Forced row-level security remains the tenant and actor visibility boundary. A caller cannot select another tenant through the certificate or query parameters. Missing rows, mismatched fields and malformed source records deny.

## Freshness and caching

The version 1 policy fixes the following bounds:

| Control | Value | Behavior |
| --- | --- | --- |
| Maximum source age | 5 seconds | An older observation is stale and denies. |
| Future clock skew | 2 seconds | A source timestamp further in the future is invalid for use and denies. |
| Repository timeout | 1 second | A slow lookup denies as unavailable. |
| Successful result lifetime | 30 seconds maximum | An active result may be cached only until the earlier of observation plus 30 seconds or certificate expiry. |
| Denial caching | Disabled | Denials always carry `cacheableUntil: null`. |
| Cached allow during outage | Disabled | A last-known-good allow is never extended when status cannot be refreshed. |

The 30-second result lifetime does not allow a 30-second-old source response. A consumer may cache only a result that was created from a source observation within the five-second freshness limit, and only until the returned absolute `cacheableUntil` value. Consumers must not independently lengthen that deadline.

## Fail-closed decisions

Only an exact, fresh `active` inventory record produces `accept`. A certificate that is not yet valid, expired, revoked, superseded, unknown, foreign, mismatched, stale or malformed produces a non-cacheable denial. Repository errors and timeouts also deny; there is no fallback to an earlier allow or to certificate validity alone.

Known credential rejection maps to `401 CERTIFICATE_NOT_ACCEPTED`. Status-source timeout, outage, malformed data or staleness maps to `503 CERTIFICATE_STATUS_UNAVAILABLE`. Both are safe external responses and intentionally avoid disclosing inventory details. Internal reason codes remain bounded for audit and diagnostics.

## Consumer contract

Authentication middleware must first complete cryptographic certificate verification, resolve trusted tenant context, then call the status validator before trust or policy evaluation. It may proceed only when `outcome` is `accept` and the current time is strictly before `cacheableUntil`. It must treat exceptions, unknown schema versions, malformed verdicts and missed deadlines as denial.

The JSON Schema at `packages/contracts/schemas/pki/certificate-status.schema.json` fixes the shared verdict shape. Run `npm run certificate-status:verify` to validate the contract and exercise active, revoked, expired, superseded, unknown, stale, future-dated, mismatched, timed-out and unavailable behavior. The repository adapter tests also verify bound SQL parameters and timestamp normalization.
