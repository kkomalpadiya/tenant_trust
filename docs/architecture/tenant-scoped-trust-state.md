# Tenant-scoped trust-state and version storage

## Storage model

T6.2 adds a persistence boundary for the complete normalized component vector defined by T6.1. It does not calculate that vector.

| Relation | Purpose |
| --- | --- |
| `trust.subject_trust_state_versions` | Append-only normalized component snapshots, model/configuration versions and observation/recording times. The key is tenant, subject and positive update version. |
| `trust.subject_trust_state_evidence` | Exactly one accepted evidence reference for each identity, device, behaviour, certificate and compliance component in a snapshot. |
| `trust.subject_trust_current` | A small pointer to the latest durable version for each tenant and subject. It contains no duplicated component values. |

The storage function writes the version, five evidence links and current pointer atomically. The first version expects previous version zero; every later write must name the current version. A stale expected version fails instead of overwriting state. T6.5 composes this writer with durable event idempotency and per-subject ordering; see [Concurrency-safe validated evidence consumption](validated-evidence-trust-consumption.md).

## Tenant and evidence binding

Each state belongs to an existing active tenant, active subject and active membership. Its configuration version must be the tenant's active configuration and its model version must match. Every evidence link must resolve to the accepted-evidence outbox and ingestion receipt for the same tenant, subject and evidence type. Foreign-tenant, different-subject, mismatched-type, duplicate, missing and invented references are rejected.

The five normalized components remain finite 0–100 values. Missing evidence cannot become a zero or a partial durable state. The observation time identifies the evidence snapshot; the database separately records when it committed the version.

## Access and history

All three relations use forced row-level security and expose no direct privileges to the SaaS application or trust-engine role. `tenant_trust_trust_engine` can execute only the security-definer store and exact current/version read functions. History and evidence links have append-only triggers. No policy decision, trust band or authorization outcome is stored in this task.

`services/trust/src/index.mjs` validates commands before database access, uses parameterized calls inside a local least-privilege role, confirms the returned version, and maps PostgreSQL numeric and time values into immutable objects. Run `npm run trust-state:verify` for focused unit and rolled-back database verification.
