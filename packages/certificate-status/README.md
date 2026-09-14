# Certificate status validation

This package implements `application-status-v1`, the certificate expiry and revocation validation mechanism for the prototype. PostgreSQL certificate inventory is authoritative. The design does not require CRL or OCSP support from the configured CA.

`createCertificateStatusValidationService` validates a presented certificate against trusted tenant context, rejects certificates outside their X.509 validity window before any lookup, and loads the exact tenant/certificate/issuer/serial/fingerprint identity from the current actor-bound database transaction. Only an `active` row with a fresh observation can produce `accept`.

The fixed version 1 policy requires a repository response no older than five seconds, tolerates at most two seconds of future clock skew, limits a successful result to 30 seconds or certificate expiry, and never caches a denial. Unknown, revoked, expired, superseded, stale, malformed, timed-out and unavailable results all deny. Source problems map to `503 CERTIFICATE_STATUS_UNAVAILABLE`; known certificate rejection maps to `401 CERTIFICATE_NOT_ACCEPTED`. No last-known-good allow is reused during an outage.

`createPostgresCertificateStatusRepository` supplies the parameterized query adapter. Call it only inside a transaction that has already bound trusted tenant/subject context with `identity.set_tenant_actor_context`; forced RLS remains the database isolation boundary.
