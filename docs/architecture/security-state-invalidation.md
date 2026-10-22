# Session and cached security-state invalidation

T9.5 ensures that a completed subject suspension or certificate revocation promptly removes server-issued sessions and subject-scoped derived security state. PostgreSQL remains authoritative: a cache miss never grants access, and the existing protected API still revalidates current certificate, tenant and membership state on every request.

## Durable handoff

Migration `037_security_state_invalidation.sql` adds an invalidation outbox beside the T9.3 action queue. An `AFTER UPDATE` trigger inserts one job in the same transaction that changes a `suspend-subject` or `revoke-certificate` action to `succeeded`. Restriction and renewal-only actions do not revoke sessions. Each job retains the exact tenant, subject, certificate, action, correlation, resulting security-state version and action-success time.

The dedicated worker role has function-only access. Claims use 30-second leases, stable action IDs and unique tokens. Expired claims become visible failures; retries retain attempt history and use bounded exponential delay. A per-subject advisory lock and partial unique index prevent concurrent invalidations for one subject.

## Atomic Redis effect

Session and security-cache writers register their exact keys under tenant-and-subject-scoped Redis sets. The invalidator runs one Lua script that validates every registered key prefix, deletes all registered session and cache keys, removes both registries and writes a seven-day action marker atomically. The marker makes a retry after an uncertain database acknowledgement a no-op instead of a second effect.

The invalidator never scans Redis and never accepts a caller-selected tenant prefix. State for a neighboring subject in the same tenant and the same subject identifier in another tenant uses different registries and remains untouched. Registries expire with their longest registered entry, so they do not outlive their sessions or caches indefinitely.

The current protected API is deliberately stateless and rejects ambient cookie or bearer sessions. The registration API is the required boundary for future server-issued dashboard sessions: a session or subject-scoped cache that is not registered cannot claim T9.5 invalidation guarantees.

## Enforcement-delay measurement

The target is five seconds from durable action success to the Redis invalidation timestamp. Completion stores the exact session/cache delete counts, measured milliseconds and a `within_target` result. The worker is designed for a one-second poll interval. A late result is retained honestly instead of rewriting its timestamp; Redis or worker outages remain visible and retryable.

Run `npm run security-state-invalidation:verify`. It runs all orchestrator tests, applies migrations, proves atomic enqueue and least-privilege retry behavior in a rollback-only PostgreSQL scenario, then uses the live Redis service to invalidate a target session/cache while preserving same-tenant and foreign-tenant neighbors. The live check also records its wall-clock invalidation time and requires it to remain within five seconds.
