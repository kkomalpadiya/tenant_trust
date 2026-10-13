# Trust calculation and tenant-scoped state storage

`@tenant-trust/trust` owns the persistence boundary for normalized trust-component snapshots. T6.2 stores one immutable version per tenant and subject, records the model and configuration versions, observation and recording times, and exactly one accepted evidence reference for every canonical component. A separate current pointer advances only after the complete historical snapshot and its references have been inserted in the same transaction.

The database validates every evidence reference against the accepted-evidence outbox and receipt for the same tenant, subject and evidence type. History and evidence links are append-only. Direct table access is denied to application and trust-engine roles; the trust engine receives only the versioned store and exact read functions. Writes use an expected previous version so a stale writer cannot silently replace current state.

T6.3 also owns the deterministic weighted arithmetic mean over the five already-normalized component values. The calculation validates the complete component vector and model configuration, uses exact decimal products, rounds the final sum once to two places and returns immutable per-component contributions plus the normalization and rounding rules.

T6.4 applies a configured exponentially weighted average to complete observation scores. Cold start uses the tenant initial score; missing observations hold only within the freshness window; stale observations are withheld; and expired state decays toward a conservative baseline without improving a below-baseline score. The temporal anchor is retained so repeated evaluations do not compound decay.

T6.5 consumes producer-authenticated `evidence.accepted.v1` deliveries through the existing verification boundary. A trusted resolver converts the exact accepted raw envelope into one normalized component score; the metadata-only event never carries raw evidence. PostgreSQL records the consume-once receipt, locks the tenant-and-subject aggregate, stages only a newer component observation and appends a complete five-component state version in one transaction. Redelivery is a no-op, older evidence cannot roll state backward, and concurrent subject updates cannot overwrite one another.

T6.6 applies explicit transition controls after weighting and temporal smoothing. Low, medium and high bands use five-point hysteresis gaps. Deterioration is immediate; recovery needs two consecutive qualifying evaluations from at least two distinct sources and advances only one band at a time. An accepted receipt's source-influence fraction bounds the absolute score delta from ordinary evidence. A closed critical-evidence rule set may bypass that cap only to reduce trust and never restores trust automatically.

T6.7 exposes trust-configuration changes only through an administrator service and constrained PostgreSQL lifecycle functions. Draft creation validates every range and the five-weight total, activation atomically replaces the active version, and rollback copies historical values into a new active version. Configuration rows and lifecycle events remain append-only, while durable confirmations are checked before the service reports success.

T6.8 assembles the weighted, temporal and transition-control results into one immutable explanation for every state change. It binds prior/new state, five component contributions, accepted-evidence references and model/configuration versions, then hashes canonical explanation bytes and creates the existing `trust.updated.v1` event. PostgreSQL verifies those bindings and atomically stores the append-only explanation, contributions, event and current transition pointer.

T6.9 exposes that current transition through a context-bound internal lookup. PostgreSQL computes age from its own statement time and the transition's exact configuration. Fresh state returns a policy score plus age and versions; stale state withholds the policy score but retains the last-known value for audit; missing or stale state requires `DENY`. The application role can execute only the zero-argument lookup function and cannot read the underlying trust tables.

This service does not define raw-claim normalization rules or make the final authorization decision. Those responsibilities belong to the trusted evidence resolvers and policy layer.

Run `npm run trust-state:verify` from the repository root. The focused gate runs unit tests and a rolled-back PostgreSQL scenario.
Run `npm run trust-score:verify` for weighted-score unit tests and independent hand-calculated examples.
Run `npm run trust-smoothing:verify` for EWA, cold-start, missing, stale and decay examples.
Run `npm run trust-evidence-consumer:verify` for verified delivery, durable idempotency, subject ordering, version advancement and tenant-isolation checks.
Run `npm run trust-controls:verify` for band boundaries, hysteresis, source influence, corroborated recovery and critical overrides.
Run `npm run trust-configuration:verify` for authorization, validation, atomic activation, immutable history, copy-forward rollback and tenant isolation.
Run `npm run trust-explanations:verify` for contract-valid events, canonical digests, exact component/evidence binding, atomic transition storage, idempotency and append-only history.
Run `npm run trust-score-lookup:verify` for actor binding, fresh score/version output, exact freshness-boundary behavior, stale score withholding and conservative missing/stale denial.
