# Trust calculation and tenant-scoped state storage

`@tenant-trust/trust` owns the persistence boundary for normalized trust-component snapshots. T6.2 stores one immutable version per tenant and subject, records the model and configuration versions, observation and recording times, and exactly one accepted evidence reference for every canonical component. A separate current pointer advances only after the complete historical snapshot and its references have been inserted in the same transaction.

The database validates every evidence reference against the accepted-evidence outbox and receipt for the same tenant, subject and evidence type. History and evidence links are append-only. Direct table access is denied to application and trust-engine roles; the trust engine receives only the versioned store and exact read functions. Writes use an expected previous version so a stale writer cannot silently replace current state.

T6.3 also owns the deterministic weighted arithmetic mean over the five already-normalized component values. The calculation validates the complete component vector and model configuration, uses exact decimal products, rounds the final sum once to two places and returns immutable per-component contributions plus the normalization and rounding rules.

T6.4 applies a configured exponentially weighted average to complete observation scores. Cold start uses the tenant initial score; missing observations hold only within the freshness window; stale observations are withheld; and expired state decays toward a conservative baseline without improving a below-baseline score. The temporal anchor is retained so repeated evaluations do not compound decay.

T6.5 consumes producer-authenticated `evidence.accepted.v1` deliveries through the existing verification boundary. A trusted resolver converts the exact accepted raw envelope into one normalized component score; the metadata-only event never carries raw evidence. PostgreSQL records the consume-once receipt, locks the tenant-and-subject aggregate, stages only a newer component observation and appends a complete five-component state version in one transaction. Redelivery is a no-op, older evidence cannot roll state backward, and concurrent subject updates cannot overwrite one another.

T6.6 applies explicit transition controls after weighting and temporal smoothing. Low, medium and high bands use five-point hysteresis gaps. Deterioration is immediate; recovery needs two consecutive qualifying evaluations from at least two distinct sources and advances only one band at a time. An accepted receipt's source-influence fraction bounds the absolute score delta from ordinary evidence. A closed critical-evidence rule set may bypass that cap only to reduce trust and never restores trust automatically.

This service does not define raw-claim normalization rules or expose policy-ready freshness decisions. Those responsibilities belong to later Phase 6 tasks.

Run `npm run trust-state:verify` from the repository root. The focused gate runs unit tests and a rolled-back PostgreSQL scenario.
Run `npm run trust-score:verify` for weighted-score unit tests and independent hand-calculated examples.
Run `npm run trust-smoothing:verify` for EWA, cold-start, missing, stale and decay examples.
Run `npm run trust-evidence-consumer:verify` for verified delivery, durable idempotency, subject ordering, version advancement and tenant-isolation checks.
Run `npm run trust-controls:verify` for band boundaries, hysteresis, source influence, corroborated recovery and critical overrides.
