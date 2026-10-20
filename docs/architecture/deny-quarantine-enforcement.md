# DENY and QUARANTINE enforcement

The adaptive API treats only an exact, contract-valid OPA `ALLOW` as permission to run a protected query. A `DENY` raises the same uniform access-denied result used by the existing API boundary, rolls back the tenant transaction and creates no security action. The caller therefore cannot distinguish policy details from a protected resource's existence.

A `QUARANTINE` also denies the protected operation, but first records one durable `audit.security_action_requests` row through `audit.request_quarantine_action`. The row binds the action request to the authenticated tenant and subject, exact active certificate, OPA decision, server request and correlation IDs, policy action, resource hash, trust transition, active policy version, canonical input hash, reason code and requested time. The API commits that constrained row, then returns the same generic denial. The protected data query never runs. If the caller presented a valid one-time step-up proof before the quarantine decision, its consumption remains committed so the proof cannot be replayed.

The application role has no direct table privileges. The security-definer function derives tenant and actor from transaction-local context, requires an active actor and an exact active certificate, and relies on tenant-qualified foreign keys for the trust transition and policy version. Rows are append-only. Repeating the same decision and action returns the original request; reusing that identity with different bound values fails closed.

For adaptive sensitive operations, policy evaluation now occurs before reserving the sensitive-operation idempotency receipt. This prevents a quarantined export or administration attempt from committing an operation receipt along with its action request. On `ALLOW`, proof consumption, receipt reservation and the protected query still share one transaction and roll back together on failure.

This task creates a durable action request; it does not execute suspension, revoke a certificate or mutate trust state. A later worker can consume requested actions with its own authorization, retry, outcome and audit controls.

After applying migrations, run:

```text
npm run policy-outcomes:verify
```

The gate covers protected-query denial, absence of action requests for `DENY`, correlated durable requests for `QUARANTINE`, persistence failure rollback, sensitive-operation ordering, PostgreSQL least privilege, certificate/tenant binding, idempotency and append-only behavior.
