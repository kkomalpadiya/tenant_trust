# Durable trust transition explanations

T6.8 joins the existing weighted score, temporal smoothing and transition-control results into one deterministic explanation for every durable trust-state version. The explanation is an audit record of how the score changed; it is not an authorization decision.

## Recorded transition

`@tenant-trust/trust` accepts only a complete five-component state with exact accepted-evidence references, the immutable model/configuration version, a causating evidence event and either the preceding transition or an explicit cold start. The builder records:

- the prior and new score, internal band, recovery streak and temporal state;
- each normalized component, configured weight, weighted contribution, evidence ID and source event ID;
- the weighted calculation, smoothing phase and calculation terms;
- source-influence limits, hysteresis/recovery details and any closed critical override; and
- the observation/evaluation times plus model and configuration versions.

Objects are serialized with the `tenant-trust-json-v1` sorted-key profile and hashed with SHA-256. The exact canonical explanation text is retained, so a verifier can recompute the digest instead of trusting a reconstructed object.

## Event binding

The same operation constructs a contract-valid `trust.updated.v1` event. Its aggregate is the server-generated transition ID, its cause must be one of the five source evidence events, and its payload carries the five evidence IDs and explanation hash. Internal calculation bands map to the shared transport vocabulary as follows:

| Internal band | Event band |
| --- | --- |
| Low | `restricted` |
| Medium | `conditional` |
| High | `trusted` |

Cold start alone uses `uninitialized` as the previous event band. The canonical event text also receives a SHA-256 digest. This records a transport-ready event without treating delivery as complete; a later publisher can deliver the retained event bytes through the established outbox/messaging boundary.

## Atomic storage and ordering

Migration `023_trust_transition_explanations.sql` adds four tenant-bound relations:

| Relation | Purpose |
| --- | --- |
| `trust.subject_trust_transitions` | Append-only prior/new state, versions, calculation totals and canonical explanation. |
| `trust.subject_trust_transition_contributions` | Exactly five state/evidence-bound component contributions. |
| `trust.subject_trust_transition_current` | Current transition pointer for each tenant and subject. |
| `trust.trust_transition_events` | Append-only canonical `trust.updated.v1` event and digest. |

`trust.record_subject_trust_transition` obtains a per-subject transaction lock, confirms that the referenced state is current, verifies the active configuration and exact component values/weights/evidence links, checks ordering against the prior transition, recomputes both digests, and writes the transition, five contributions, event and pointer atomically. An exact retry is idempotent; a changed identity, digest, prior state, contribution or cross-tenant reference fails closed.

The tables use forced row-level security with no runtime policies or direct application/trust-engine privileges. Only the constrained security-definer function is executable by the trust engine, and history tables reject updates and deletes.

## Verification

Run `npm run trust-explanations:verify`. The gate runs the trust unit suite, validates a generated event against the shared JSON Schema, then uses a rolled-back PostgreSQL scenario to prove least privilege, exact contribution binding, atomic persistence, idempotent retry, forged-contribution rejection, digest linkage and append-only history.
