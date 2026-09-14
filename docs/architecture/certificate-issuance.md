# Certificate request and issuance

## Security boundary

`@tenant-trust/certificate-issuance` implements the application boundary for initial enrollment and fresh-key renewal of `tenant-client-auth-v1` certificates. It receives an immutable context created by `@tenant-trust/tenant-context` and a narrow caller request containing a target subject, CSR, CSR digest, requested validity and idempotency key.

The boundary requires a `recordIssuedCertificate` dependency. After it verifies the returned leaf, it delegates to the tenant-bound inventory service and does not return success until durable certificate and initial lifecycle-event identities are confirmed.

The package derives the normalized contract fields that carry authority: `tenantId`, `requestedBySubjectId`, `operation` and `requestedAt`. Unknown request fields are rejected, so a caller cannot select an issuer or authority URL, replace the requester, supply certificate subject/SAN/extensions/timestamps, or submit private-key material.

## Request flow

1. The subject generates a supported P-256 or Ed25519 private key locally and signs a PKCS #10 CSR. The private key never enters the service request.
2. The service verifies the exact CSR bytes against the lowercase SHA-256 digest and validates the request bounds.
3. The target membership is loaded with `(trustedTenantId, targetSubjectId)`. It must join an active tenant, active subject and active membership.
4. A member may enroll only itself. A tenant administrator may enroll another active subject only in the same tenant.
5. The service resolves one active issuer using only the trusted tenant ID. The mapping must belong to that tenant and allow issuance.
6. The signer verifies the CSR signature, ignores caller-requested identity or privilege extensions, and constructs the certificate from the committed profile template.
7. The service parses the returned X.509 certificate and verifies the subject, URI SAN, key algorithm, client-auth usage, validity, serial number, signature and immediate issuer certificate.

Any missing membership, inactive state, untrusted context, unsupported key, CSR mismatch, issuer mismatch or malformed certificate fails closed. Internal reason codes map to the single external response `403 CERTIFICATE_ENROLLMENT_DENIED`, so the response does not reveal whether a foreign subject or issuer exists.

## Issuer and certificate verification

The resolved issuer record supplies public metadata and the tenant intermediate certificate. The service does not trust a signer response merely because the signing call succeeded. It requires the returned leaf to be issued by and cryptographically verify against that exact intermediate. The leaf must also contain:

- subject `CN=<subjectId>, O=<tenantId>`;
- exactly one URI SAN, `urn:tenant-trust:identity:v1:tenant:<tenantId>:subject:<subjectId>`;
- a supported public key and only the client-auth extended usage;
- a non-zero serial represented as 32 uppercase hexadecimal characters;
- a validity window within the requested 5-minute to 24-hour bound and the profile backdate policy.

Verified certificate metadata includes the canonical public-key SPKI digest. Initial issuance is persisted through the inventory writer; renewal additionally verifies eligibility and fresh-key possession before signing, then persists successor activation and predecessor supersession atomically. See [Certificate renewal and key rotation](certificate-renewal.md).

## Verification scenario

Run `npm run certificate-issuance:verify`. Unit tests cover request normalization, caller-field rejection, CSR integrity, self-enrollment, administrator enrollment, inactive/foreign membership denial, issuer mismatch denial and uniform external errors.

The integration half runs the pinned Smallstep image as short-lived cryptographic tools. It creates one ephemeral platform root, distinct Alpha and Beta intermediates, and P-256 subject keys and CSRs. It issues real tenant-bound certificates, verifies their parsed identity and issuer signatures, and proves all of these negative cases:

- a member cannot enroll another subject;
- an Alpha administrator cannot enroll a Beta subject;
- an Alpha request cannot resolve the Beta issuer mapping;
- a leaf signed with the Beta intermediate is rejected when Alpha is expected.

All keys and certificates are created below ignored `runtime/` storage and removed in a `finally` cleanup. The checked-in profile template contains no key or credential. The current long-running `step-ca` remains the foundation CA; later deployment work can connect the same signer interface to isolated online tenant authorities without changing the authorization boundary.
