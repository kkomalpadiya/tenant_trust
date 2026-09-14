# Certificate revocation

This package implements the trusted application boundary for permanent certificate revocation. A subject may revoke their own active certificate. A `tenant-admin` may revoke any active certificate in the same tenant. The request cannot select a tenant, subject, issuer, serial number, fingerprint, event identity or revocation time.

The service loads the exact certificate through trusted tenant scope, resolves the active mapped issuer, verifies that issuer permits `revoke`, and sends an immutable instruction containing the certificate binding, approved reason and idempotency key. It records the revoked state only after the issuer returns a matching authenticated confirmation. An unavailable or malformed issuer response cannot produce a persisted revocation success.

The allowed reasons map to permanent RFC 5280/Smallstep reason codes. `CertificateHold` and `RemoveFromCRL` are intentionally unsupported because a revoked Tenant Trust certificate can never return to `active`.

`createPostgresCertificateRevocationRepository` supplies actor-bound, parameterized lookup and persistence methods. Its writer calls `identity.record_certificate_revocation`, which locks the active certificate, rechecks self-or-admin authorization, updates the authoritative state and appends the reasoned lifecycle event in one transaction. Identical retry returns the durable result without another issuer call; conflicting idempotency reuse fails closed.
