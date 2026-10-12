# Versioned trust configuration lifecycle

## Administrative boundary

T6.7 turns tenant trust settings into a constrained lifecycle instead of permitting broad table writes. An active `tenant-admin` may create a draft, activate a draft, roll back to historical settings and inspect configuration history. Ordinary tenant members are denied every lifecycle operation. Tenant and actor identities always come from `identity.set_tenant_actor_context`; request fields cannot choose either identity.

Application roles have no direct `INSERT`, `UPDATE` or `DELETE` privilege on `trust.trust_configurations`. They can use only the security-definer lifecycle functions introduced by migration `022_versioned_trust_configuration_lifecycle.sql`:

- `trust.create_trust_configuration_draft` validates a complete configuration and allocates the tenant's next version.
- `trust.activate_trust_configuration` atomically supersedes the current active version and activates one draft.
- `trust.rollback_trust_configuration` copies one superseded version into a new active version and supersedes the current version.
- `trust.list_trust_configuration_history` returns tenant-bound history with its latest lifecycle event.

Each mutation takes a tenant-scoped transaction advisory lock. Concurrent administrators therefore cannot allocate the same version or leave two active configurations.

## Validation and immutable history

A draft requires a strict semantic model version, initial score from 0 through 100, smoothing alpha greater than zero through one, maximum source influence greater than zero through one, a positive staleness interval and exactly five weights from zero through one whose total is exactly one. The service repeats these checks before database access, rejects unknown or caller-owned authority fields and verifies the database's durable confirmation.

Configuration contents cannot be edited after insertion and historical rows cannot be deleted. Activation changes only lifecycle metadata. Rollback never reactivates or rewrites an old row: it appends a new configuration version containing the selected historical values. That new version identifies the administrator who requested the rollback and becomes the sole active configuration.

`trust.trust_configuration_events` records draft creation, activation and rollback activation. The ledger is append-only, forced through row-level security and inaccessible through direct application-role table writes. Rollback events record both the previous active version and selected target version so reviewers can reconstruct intent without inferring it from values.

## Verification

Apply migration `022_versioned_trust_configuration_lifecycle.sql`, then run `npm run trust-configuration:verify`. The gate runs the trust-service tests and a rolled-back PostgreSQL scenario covering administrator authorization, member denial, ranges and weight totals, direct-write denial, atomic activation, copy-forward rollback, lineage, tenant isolation and append-only history. `npm run security-configuration:verify` remains the regression gate for the wider tenant security-configuration boundary.
