# Certificate identity profile and request contract

## Contract boundary

`tenant-client-auth-v1` is the only certificate profile defined for the initial prototype. The machine-readable profile is `packages/contracts/schemas/pki/certificate-identity-profile.json`, and the normalized internal request contract is `packages/contracts/schemas/pki/certificate-request.schema.json`.

The JSON request exists after authentication and trusted tenant-context resolution. The API adds `tenantId` and `requestedBySubjectId` from authoritative state before validation. An external caller may select a target `subjectId` only when later authorization permits that relationship. A caller cannot supply the issuer, authority URL, subject DN, SAN, key usage, extended key usage, serial number, validity timestamps or private key.

The PKI service resolves the active `issuerId` from the trusted tenant mapping defined by T3.1. Fields inside a signed CSR remain untrusted requests. The service verifies proof of possession, extracts the public key, checks the declared algorithm, and constructs the certificate subject, SAN and extensions from this profile instead of copying CSR identity or privilege extensions.

## X.509 identity

The subject contains only opaque identifiers:

| X.509 field | Value |
| --- | --- |
| Subject common name | `subjectId` |
| Subject organization name | `tenantId` |
| Required URI SAN | `urn:tenant-trust:identity:v1:tenant:{tenantId}:subject:{subjectId}` |

Human names, email addresses, roles, device posture and policy outcomes are excluded. They are mutable or personal attributes and must come from authoritative application state. DNS, IP-address and email SANs are forbidden for this client certificate profile.

Validation parses the URI SAN into exactly one tenant ID and one subject ID, then requires both values to equal the certificate subject and the current trusted tenant context. Duplicate identity SANs, extra SAN types, malformed identifiers and mismatches fail closed. A valid chain from another tenant's intermediate is still a foreign-tenant certificate.

## Certificate extensions and keys

The certificate is an end-entity client-authentication certificate:

- Basic Constraints is critical and sets `CA=false`.
- Key Usage is critical and contains only `digitalSignature`.
- Extended Key Usage contains only `clientAuth`.
- Subject Key Identifier and Authority Key Identifier are required.
- Allowed public-key algorithms are ECDSA P-256 and Ed25519, each providing at least 128-bit security.
- A PKCS #10 CSR signature must verify with the submitted public key. The private key is generated and retained by the subject and never enters the request, event payload, database, log or repository.

Requests for `keyCertSign`, `cRLSign`, `serverAuth`, key encipherment, an unsupported curve or algorithm, or a CSR whose signature/hash/declared algorithm disagrees are rejected. Algorithm-specific certificate signatures will be selected by the tenant CA implementation in T3.3.

## Serial-number policy

The issuing CA generates a non-zero random 128-bit serial number. The canonical contract representation is exactly 32 uppercase hexadecimal characters. The caller and CSR cannot supply it. Uniqueness is enforced within an issuer, and the durable certificate inventory added in T3.4 must use `(tenantId, issuerId, serialNumber)` as the lookup and uniqueness scope.

The 16-octet value remains below the RFC 5280 20-octet limit even when DER needs a sign-preserving prefix. An issuance collision is retried with a new CA-generated value; it never overwrites an existing certificate record.

## Validity policy

`requestedValiditySeconds` is an integer from 300 seconds through 86,400 seconds. The default is 3,600 seconds. The issuer may shorten a request because of tenant, membership, issuer, source-certificate or policy state, but it cannot extend it above the request or profile maximum.

The CA sets `notBefore` to issuance time minus a 60-second clock-skew allowance and sets `notAfter` to `notBefore + requestedValiditySeconds`. The resulting timestamps are recorded as RFC 3339 UTC values and must satisfy `notBefore < notAfter`. Renewal uses the same maximum and cannot extend the new certificate merely because the old certificate has remaining time.

Authorization evaluates current tenant, membership, subject and issuer state immediately before issuance. A suspended tenant, inactive membership, inactive issuer, unknown profile, unverified CSR or invalid time source fails closed. Existing certificates are not made valid by a failed renewal request.

## Request fields

| Field | Rule |
| --- | --- |
| `schemaVersion` | Exactly `1.0.0` |
| `requestId` | Opaque `req_UUID` generated once for this lifecycle request |
| `profileId` | Exactly `tenant-client-auth-v1` |
| `operation` | `issue` or `renew` |
| `tenantId` | Injected from validated tenant context |
| `subjectId` | Target subject; authorization must confirm same-tenant eligibility |
| `requestedBySubjectId` | Injected authenticated actor |
| `requestedAt` | RFC 3339 UTC timestamp with trailing `Z` |
| `requestedValiditySeconds` | Integer from 300 through 86,400 |
| `proofOfPossession` | Algorithm, bounded PEM PKCS #10 CSR and lowercase SHA-256 digest |
| `renewalOfCertificateId` | `null` for issue; required `crt_UUID` for renewal |
| `idempotencyKey` | Stable scoped key; conflicting reuse is rejected |

JSON Schema validates shape and conditional lineage. The service must additionally verify trusted-context equality, actor authority, subject membership/state, issuer state, CSR signature and digest, public-key algorithm, absence or disregard of CSR-requested identity extensions, time relationships and idempotency conflicts.

## Verification and implementation boundary

Run `npm run certificate-profile:verify`. Tests compile the request schema, accept issue and renewal examples, reject invalid lineage, validity, timestamps, algorithms and proof-of-possession values, and prove that caller-supplied issuer, identity, privilege, serial, timestamp and private-key fields are not accepted. They also lock the profile's subject/SAN, client-auth extensions, algorithms, serial generation and validity rules.

T3.2 defines and tests the contract only. T3.3 must generate a real supported key and CSR, verify the CSR cryptographically, construct the certificate from the profile, issue through the trusted tenant mapping, and add live tests for unauthorized enrollment and cross-tenant issuer denial.
