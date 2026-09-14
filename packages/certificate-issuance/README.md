# Certificate issuance

This package implements the trusted application boundary for initial client-certificate enrollment. It accepts a caller request only after `@tenant-trust/tenant-context` has resolved an authenticated, active tenant member.

The boundary derives `tenantId`, `requestedBySubjectId`, operation and request time. It verifies the CSR digest, authorizes self-enrollment or same-tenant administrator enrollment, loads the target membership through the trusted tenant scope and resolves one active issuer from that same scope. Callers cannot select an issuer, authority URL, subject DN, SAN, validity timestamps, certificate extensions or private key.

The private key stays with the subject. The signer receives the CSR plus an immutable instruction containing the profile-derived subject, tenant/subject URI SAN, client-auth usage and validity. After signing, the package parses the X.509 certificate and verifies its identity, SAN, key algorithm, client-auth usage, validity, serial, signature and immediate issuer certificate. It then requires a certificate inventory writer to confirm durable certificate and lifecycle-event records before returning success.

`npm run certificate-issuance:verify` runs the unit boundary tests and a Docker-backed cryptographic scenario. The scenario creates an ephemeral platform root, distinct Alpha and Beta intermediates, P-256 subject keys and signed CSRs, then proves authorized issuance and rejects unauthorized, foreign-membership, foreign-mapping and wrong-issuer signing attempts. All generated keys and certificates remain under ignored runtime storage and are removed when the scenario exits.
