# Certificate inventory

This package converts verified X.509 issuance and renewal results into the authoritative certificate inventory shape. It derives opaque certificate, event and correlation IDs inside the trusted boundary, rechecks tenant/subject and predecessor binding, and passes only public certificate metadata to the persistence adapter.

`createCertificateInventoryService` returns success only after its repository confirms the certificate ID, initial lifecycle event ID and active state. The PostgreSQL adapter should call `identity.record_certificate_issuance` in an actor-bound transaction. That function writes `identity.certificates` and `identity.certificate_lifecycle_events` atomically.

Renewal allocates separate `renewed` and `superseded` event IDs. The PostgreSQL adapter calls `identity.record_certificate_renewal`, which locks the predecessor and atomically activates the successor, supersedes the predecessor and appends both causal events. The inventory deliberately excludes private keys and certificate PEM while retaining the public SPKI SHA-256 digest required to prove real key rotation.
