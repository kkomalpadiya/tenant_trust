# Certificate inventory

This package converts a verified X.509 issuance result into the authoritative certificate inventory shape. It derives opaque certificate, event and correlation IDs inside the trusted boundary, rechecks tenant/subject binding and passes only public certificate metadata to the persistence adapter.

`createCertificateInventoryService` returns success only after its repository confirms the certificate ID, initial lifecycle event ID and active state. The PostgreSQL adapter should call `identity.record_certificate_issuance` in an actor-bound transaction. That function writes `identity.certificates` and `identity.certificate_lifecycle_events` atomically.

The inventory deliberately excludes private keys and does not persist the certificate PEM. Presented certificates can be parsed again and matched by issuer, serial or SHA-256 fingerprint during later validation work.
