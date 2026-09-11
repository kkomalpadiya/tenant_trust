# Cross-tenant negative testing

`npm run cross-tenant:verify` is the fail-closed regression gate for tenant switching, guessed identifiers and reused runtime connections. It runs against the provisioned Tenant Alpha and Tenant Beta demonstration data and retains no database changes or runtime test values.

## Covered boundaries

The API-facing checks exercise the trusted tenant-context resolver directly because the HTTP API is not implemented yet. They submit Tenant Beta identifiers through header, path, query, body and resource claims while authenticated to Tenant Alpha, then verify every internal context failure becomes the same external response: `403 ACCESS_DENIED`. The response contains no tenant identifier, resource hint or internal reason code. Future HTTP routes must call this boundary and add endpoint-level negative cases to the same command.

The PostgreSQL check uses one `tenant_trust_app` backend session. Tenant Alpha and Tenant Beta administrators guess the other tenant's identity, resource, issuer, evidence-source, trust-configuration and policy identifiers. Reads return no rows, updates affect no rows and cross-tenant inserts fail row-level security. The same connection is then reused without actor context and must expose no tenant rows. Malformed identifiers and cross-tenant subject bindings are rejected. Every transaction rolls back.

The Redis check creates expiring values only. A Tenant Alpha context given a guessed Tenant Beta resource identifier still derives an Alpha-prefixed key and cannot retrieve or overwrite the Beta value. Resolver branding rejects forged contexts, URI encoding separates delimiter-bearing segments, and cache and lock namespaces cannot collide. The verifier deletes all probe keys in a `finally` block.

The NATS check first proves the messaging helper rejects an event whose envelope names another tenant. It then connects with each tenant's demonstration credential and verifies that the broker denies both subscription and publication to the other tenant's exact subject prefix.

## Running the gate

Start, migrate and provision the local stack, then run:

```powershell
npm run cross-tenant:verify
```

A pass is intentionally narrow: it proves the currently implemented boundary helpers, protected PostgreSQL tables, Redis key construction and demonstration NATS grants fail closed. It does not claim endpoint coverage for the planned HTTP API or tenant isolation for future tables and services. Every new tenant-owned route, table, key, event subject and credential grant must extend this suite before it is considered complete.
