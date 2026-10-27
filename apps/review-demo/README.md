# Tenant Trust security dashboard

This local frontend presents the implemented Tenant Trust security boundaries and the Phase 10 tenant certificate dashboard.

Start it from the repository root:

```text
npm run demo:review
```

Open `http://127.0.0.1:4173`. Switch among the deterministic Alpha and Beta personas, inspect tenant-scoped subjects, certificates and records, and run the access-boundary scenarios. Members receive self scope. Tenant administrators receive same-tenant scope. Issue, renew and revoke controls are rendered from server-calculated permissions, and every submitted operation re-resolves the certificate persona, tenant, role, target ownership, certificate state and renewal window before changing the in-memory review inventory.

The controls demonstrate the application authorization and lifecycle state transitions without loading a private key or contacting a certificate authority. Their state resets when the local server restarts. Production certificate issuance, renewal and revocation remain implemented and verified in the dedicated PKI packages and Docker-backed verification commands.

Run the focused dashboard gate with:

```text
npm run tenant-dashboard:verify
```
