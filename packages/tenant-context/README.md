# Trusted tenant context

This package defines the application boundary that turns authenticated identity plus authoritative PostgreSQL identity state into an immutable tenant context. It does not authenticate a certificate or session and must never receive a principal constructed from request headers, path parameters, query strings or request bodies.

`resolveTenantContext` accepts only an authentication adapter result whose source is `mtls-certificate` or `trusted-session`. The result must already bind one subject to one tenant. The resolver then requires matching active tenant, subject and membership records, positive state versions and at least one tenant role. Platform roles are not tenant roles.

`assertNoTenantSwitch` treats tenant IDs found in headers, paths, queries, bodies and loaded resources as consistency checks only. A matching ID confirms the existing context; a missing tenant claim contributes no authority; a conflicting or malformed claim denies the request. Load tenant-owned resources through the trusted tenant scope first, then compare any stored tenant ID before use.

`tenantSafeDenial` maps every internal context failure to the same external `403 ACCESS_DENIED` response. Internal audit may retain the bounded `TenantContextError.reasonCode`, correlation ID and trusted tenant/subject identifiers, but responses and ordinary logs must not reveal whether a foreign tenant or resource exists.

Run the focused tests with:

```powershell
npm test --workspace @tenant-trust/tenant-context
```

The package is a contract for later API, database, cache, messaging and policy work. It does not implement certificate validation, signed session issuance, database row-level security, Redis/NATS isolation or OPA authorization.
