# Tenant policy bundle versioning

## Ownership and artifact contract

T7.3 extends the tenant-owned `trust.policy_versions` registry rather than introducing a second policy authority. A newly published bundle contains canonical JSON with:

- server-derived tenant and `pol_<UUID>` identities;
- a tenant-local, monotonically increasing bundle version;
- the fixed `tenant_trust/authorization/decision` entrypoint;
- one or more bounded Rego v1 modules restricted to the `tenant_trust.authorization` package;
- bounded JSON data containing tenant thresholds and sensitivity rules; and
- the exact OPA engine/version, Rego version and validation time.

The management service normalizes line endings and module order, rejects unsafe paths, unknown request fields, invalid JSON values and oversized content, invokes a trusted OPA compiler adapter, and then calculates SHA-256 over deterministic canonical JSON. The tenant administrator supplies policy content and a reason, but cannot supply tenant identity, publisher identity, policy-version ID, bundle digest, validation receipt or lifecycle state.

## Durable lifecycle

Migration `025_tenant_policy_bundle_lifecycle.sql` adds the canonical bundle document and validation provenance to `trust.policy_versions`, plus append-only publication, activation and supersession events. Direct runtime inserts, updates and deletes are revoked. Security-definer functions re-derive tenant and actor from transaction context and require an active tenant administrator for publication and activation.

Publication takes an advisory transaction lock for `(tenant, policy name)` and accepts only the next bundle number. Activation takes the same lock, requires a validated `published` row, supersedes the previous active row and selects the target in one transaction. The existing partial unique index independently permits at most one active version of a policy name per tenant. Immutable triggers prevent bundle, digest, compiler and lineage rewrites; delete triggers preserve version and event history.

The original T2.7 deterministic rows contain metadata only. They remain as historical bootstrap records, are excluded from validated lifecycle history and cannot be activated. The first validated `access-control` bundle therefore uses version 2 for each seeded tenant.

## Decision provenance and rollout safety

An active database row is the tenant's policy authority. Before calling OPA, the API loads that active row using the already trusted tenant context. After OPA responds, it verifies all four provenance fields:

| OPA output | Active tenant bundle |
| --- | --- |
| `policyVersionId` | Exact `pol_<UUID>` |
| `bundleVersion` | Exact tenant-local version |
| `bundleHashSha256` | Exact canonical artifact digest |
| `decisionPath` | Exact configured entrypoint |

Any mismatch is a non-allowing policy response. This makes deployment skew safe: activation is atomic in PostgreSQL, and a still-old or incorrectly loaded OPA instance cannot authorize requests because its provenance will not match. Policy distribution is an operational adapter, not a second source of truth, and application callers still do not use OPA management APIs.

T7.4 now supplies and validates that executable tenant data. `access-control` publication rejects cross-tenant data, incomplete or duplicate action rules, sensitivity downgrades, broader role eligibility and removal of mandatory step-up. Thresholds remain explicitly unvalidated prototype defaults and can be changed only by publishing a new tenant-scoped bundle version.

## Verification

Run `npm run policy-bundles:verify` after migrations and demo provisioning. It proves:

- tenant-administrator-only publication and activation;
- caller authority and direct-write rejection;
- bounded canonical artifacts and digest verification;
- pinned OPA Rego v1 acceptance and invalid-syntax rejection;
- monotonic tenant-local versions and atomic replacement;
- Alpha/Beta isolation and active lookup behavior;
- append-only bundle and event history; and
- API denial when OPA reports anything other than the exact active bundle provenance.

All database scenarios run in transactions and roll back their fixture changes.
