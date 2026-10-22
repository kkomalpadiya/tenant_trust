# Certificate lifecycle trust feedback

T9.4 converts authenticated T3.8 certificate lifecycle outcomes into tenant-scoped certificate evidence for the trust service. It does not accept a client-created evidence envelope and does not treat feedback as a new security-action trigger.

## Validation boundary

The consumer verifies the signed `certificate.*.v1` event before deriving any effect. PostgreSQL then independently requires the exact lifecycle event to exist in the certificate outbox with `published` status, matching JetStream sequence and signed-event digest. This two-sided check binds the signature, durable lifecycle record and delivered broker identity.

Each lifecycle event deterministically becomes `evd_<event UUID>`. Issuance, renewal and supersession produce certificate component score 100; revocation and expiry produce score 0. Supersession is non-negative because normal key rotation replaces the old certificate with a newly active one. Every record retains the lifecycle event, its immediate `causationId`, workflow correlation, tenant, subject and certificate. A revocation produced by T9.3 additionally links to the exact successful `revoke-certificate` action whose external confirmation is that lifecycle event.

## Exactly-once and loop prevention

`trust.certificate_lifecycle_evidence` is append-only and unique by tenant and lifecycle event. Redelivery returns `duplicate` and does not call the trust-effect handler again. The durable evidence insert and caller-provided trust effect run in one PostgreSQL transaction; if the effect fails, the receipt rolls back and the delivery can be retried safely.

All derived lifecycle evidence has `security_action_eligible = false`. Terminal revocation, expiry and supersession describe outcomes that already happened, so they can inform trust but cannot independently authorize another action. This enforces the T9.2 rule that `certificate-revoked` is terminal feedback and prevents a revocation → trust drop → revocation loop.

## Verification

Run `npm run certificate-trust-feedback:verify`. It runs the signed certificate-event tests, the trust-service suite, applies migrations, and executes a rollback-only PostgreSQL gate covering published-event authority, action and causal binding, exact replay suppression, append-only storage and non-recursive evidence.
