# Policy source

OPA loads reviewed Rego policy from this directory in local development. The bootstrap package provides a small deterministic query used to prove that the policy service loaded repository policy; it does not make an access decision.

The application-side RBAC eligibility and sensitivity contract is defined in `packages/authorization`; it does not replace an OPA decision and treats operations that require later controls as non-allowing. The versioned Data API request and response contract is defined in `packages/contracts/schemas/policy` and documented in `docs/architecture/opa-decision-contract.md`.

Tenant bundle publication and activation are defined in `services/policy` and documented in `docs/architecture/tenant-policy-bundle-versioning.md`. A bundle must use `tenant_trust/authorization/decision`, remain tenant-scoped, compile as Rego v1 with the pinned OPA version and carry immutable content/version provenance. PostgreSQL is the active-version authority; the API rejects a decision whose policy ID, version, digest or path differs from that tenant's active row. Application callers use only the Data API decision path and do not modify policy through OPA management APIs.

Run `npm run policy:test` for checked-in service policy and `npm run policy-bundles:verify` for bundle validation, lifecycle and API provenance enforcement. T7.4 adds the actual score and resource-sensitivity decision rules; T7.3 does not assign authorization thresholds.
