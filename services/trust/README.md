# Tenant-scoped trust-state storage

`@tenant-trust/trust` owns the persistence boundary for normalized trust-component snapshots. T6.2 stores one immutable version per tenant and subject, records the model and configuration versions, observation and recording times, and exactly one accepted evidence reference for every canonical component. A separate current pointer advances only after the complete historical snapshot and its references have been inserted in the same transaction.

The database validates every evidence reference against the accepted-evidence outbox and receipt for the same tenant, subject and evidence type. History and evidence links are append-only. Direct table access is denied to application and trust-engine roles; the trust engine receives only the versioned store and exact read functions. Writes use an expected previous version so a stale writer cannot silently replace current state.

This service does not normalize raw claims, calculate the weighted score, smooth observations, consume JetStream events or expose policy-ready freshness decisions. Those responsibilities belong to later Phase 6 tasks.

Run `npm run trust-state:verify` from the repository root. The focused gate runs unit tests and a rolled-back PostgreSQL scenario.
