# Repository layout

Use a single repository with explicit component boundaries. The paths below are the agreed locations for implementation; create each component when its work starts rather than adding empty application scaffolds.

| Path | Responsibility |
| --- | --- |
| `apps/api/` | SaaS API, tenant and subject management, protected resources, request enforcement and internal service adapters |
| `apps/web/` | Tenant dashboard, certificate controls, trust explanations and audit views |
| `services/evidence/` | Source enrollment, signature and freshness validation, accepted evidence delivery |
| `services/trust/` | Score calculation, temporal smoothing, state transitions and explanations |
| `services/orchestrator/` | Security action state machine, certificate actions and governed recovery |
| `services/audit/` | Durable audit delivery, Fabric integration, reconciliation and verification |
| `packages/contracts/` | Versioned request, event and decision schemas shared by producers and consumers |
| `policies/` | OPA policy source and policy test cases |
| `database/migrations/` | Ordered application schema changes, including tenant isolation controls |
| `database/seeds/` | Idempotent synthetic development data with deterministic identifiers and no credentials |
| `infra/compose/` | Local container service definitions and safe configuration templates |
| `infra/pki/` | Tenant issuer provisioning scripts and certificate profile templates |
| `infra/fabric/` | Fabric network definitions and lifecycle scripts, excluding generated identities and channel artifacts |
| `chaincode/audit/` | Audit commitment contract source and contract tests |
| `tests/` | Integration and end-to-end tests, synthetic fixtures and isolation checks |
| `evaluation/` | Baseline configurations, reproducible workloads and measurement scripts |
| `scripts/` | Developer setup, verification and operational scripts |
| `docs/` | Scope, architecture decisions, API documentation, operational procedures and evaluation conclusions |
| `runtime/` | Ignored local volumes, generated identities and other service state |

## Boundary rules

- The API derives tenant identity from authenticated context. Every store, cache key, event and policy lookup preserves tenant scope.
- Shared contracts describe interfaces without exposing component internals. Schema changes must account for both producers and consumers.
- Component paths define responsibilities, not a requirement to run every component in a separate process. Deployment granularity will follow the local resource budget.
- Certificate validation and policy enforcement gate protected operations. Trust computation supplies versioned input to policy decisions.
- Durable off-chain state supports runtime decisions. Fabric delivery runs asynchronously and exposes pending, committed and failed audit states.
- Keep unit tests with their components when the selected language convention supports that. Place cross-component tests under `tests/`.

## Version-control boundary

Track reproducible project inputs: source, schemas, migrations, policy bundles, network definitions, safe example configuration, lockfiles, scripts and documentation. Ignore generated artifacts and local machine state through the root `.gitignore`.

Generated certificates and private material must use ignored runtime locations. Public synthetic certificate fixtures, if required later, need narrowly scoped ignore exceptions and an explicit description of their test purpose.
