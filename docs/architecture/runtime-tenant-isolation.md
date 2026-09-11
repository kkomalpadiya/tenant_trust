# Redis and NATS tenant isolation

Tenant-scoped runtime state is derived from the immutable context returned by `@tenant-trust/tenant-context`. A caller-provided tenant ID may be checked against that context, but it cannot select a Redis key or NATS subject.

## Redis cache and lock keys

Use the `@tenant-trust/tenant-context/redis` helpers for every tenant-owned cache entry and distributed lock:

```text
tenant:<tenantId>:cache:<namespace>:<encoded-segment>[:<encoded-segment>...]
tenant:<tenantId>:lock:<namespace>:<encoded-segment>[:<encoded-segment>...]
```

`tenantCacheKey` and `tenantLockKey` accept only a resolver-branded context, require a bounded lowercase namespace and URI-encode each dynamic segment. The explicit tenant, purpose and namespace fields prevent cross-tenant, cache/lock and delimiter collisions. Do not construct tenant keys by string concatenation or accept a complete key from a request.

Redis uses one local service password and does not enforce per-key access control. Application code must expose Redis only through context-requiring adapters, use short expirations for cache entries and locks, and treat PostgreSQL as authoritative. A cache hit never repairs an invalid or stale tenant context.

## NATS subjects and consumers

Tenant events use:

```text
tenant.<tenantId>.events.<versionedEventType>
```

`subjectForEvent(context, event)` derives the tenant token from the resolved context and rejects an envelope whose tenant differs. `durableConsumerConfig(context, options)` always prefixes the filter with that same tenant. Callers may select an exact versioned event type, a terminal event prefix such as `trust.>`, or all event types inside that one tenant with `>`; they cannot provide `*` or a complete subject.

The local NATS configuration has a broad platform/service account plus fixed Tenant Alpha and Tenant Beta demonstration accounts. Each tenant account can publish and subscribe only below its exact event prefix. Cross-tenant subscriptions are rejected by the broker. Tenant credentials do not have JetStream administration permissions; a trusted platform worker creates tenant-filtered durable consumers with the messaging helper and distributes data only to the authorized tenant workflow.

The broad service account remains a privileged boundary. Production deployment must issue service-specific credentials, separate JetStream administration from ordinary publishing and consumption, and prevent tenant-facing code from receiving the platform credential.

## Verification

Run `npm run runtime-isolation:verify` while the local stack is running. It proves that identical logical Redis cache and lock names create separate tenant keys, then connects with each tenant's NATS credentials to prove own-tenant delivery and broker rejection of cross-tenant subscriptions. The verification creates only expiring Redis values and removes them on completion.
