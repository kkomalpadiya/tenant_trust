# Tenant Trust

An adaptive security research prototype for multi-tenant SaaS. The project combines tenant-bound X.509 identities, continuously updated trust scores, context-aware authorization and verifiable security audit records.

A valid certificate establishes identity. Access also depends on tenant membership, role, resource ownership, request context and current trust. A high trust score cannot override an invalid certificate or a cross-tenant access violation.

## Current status

All ten phases and 100 tracked implementation tasks are complete. The repository contains the runnable two-tenant prototype, tenant-bound certificate lifecycle, signed evidence processing, explainable adaptive trust, context-aware OPA authorization, controlled certificate actions, asynchronous Fabric commitments, tenant-scoped review dashboards, reproducible evaluation workloads and measured comparison reports. The final release package adds a consolidated architecture overview, API reference, demo script, final report, updated presentation and an executable release-package check. The initial weights and thresholds remain explicitly unvalidated prototype defaults.

T10.3 adds a tenant-scoped audit-operations view for Fabric delivery, causal-chain verification and retryable quarantine/action failures. It exposes operational metadata only and excludes evidence content and credentials.

T10.4 adds evaluation-only Baseline A: bounded EdDSA JWT authentication plus the existing RBAC matrix, with one immutable two-tenant workload catalog shared by Baseline A, Baseline B and the proposed framework. The production SaaS API remains mTLS-only.

T10.5 pre-registers a reproducible comparison protocol with separate calibration and evaluation partitions, closed ground-truth labels, fixed sample counts and repetitions, three concurrency levels, rotating mode order, exact reference hardware and failure-preserving metric denominators. The verified Review 2 slide map is bound to the source deck hash, and no benchmark result is claimed yet.

T10.6 adds the deterministic workload runner for all ten scenarios and all three modes. It replays normal access, context and behaviour attacks, sensitive exports, cross-tenant attempts, forged and replayed evidence, audit tampering, ledger outage/recovery and corroborated revocation while retaining unsupported, timeout and error observations. Its focused profile verifies orchestration only; measurements remain deferred.

T10.7 reports functional effectiveness and isolation outcomes from 36,900 measured trials with explicit denominators and 10,000-resample cluster-bootstrap uncertainty. It includes detection, false restriction, tenant isolation, replay rejection, audit modification, ledger verification and revocation enforcement. Unsupported baseline controls remain failures, and the report clearly separates deterministic functional results from T10.8 performance work.

T10.8 reports a live single-host performance run of 3,780 decisions across all modes and registered load caps. Authentication, adaptive trust, authorization and end-to-end latency are separated from 30 real Fabric commit-delay observations. It also records throughput, Node.js CPU/RSS and three reversible peer-outage recovery measurements that preserve authorization continuity and reconcile to zero delivery gaps.

T10.9 compares both baselines with the proposed framework and adds executable ablations for smoothing, terminal certificate feedback and ledger placement. The conclusions report the measured security/performance tradeoffs, preserve the closed-catalog and single-host limitations, and describe the work as an evaluated integration of established mechanisms rather than claiming novel primitives or universally optimal parameters.

T10.10 packages the final demonstration and release material, closes the review dashboard at 100/100 tasks and adds `npm run release:verify`. That release gate starts and removes a disposable clean environment, runs the complete regression suite through the foundation verifier, and checks the final documentation, slide deck and completion markers.

## Implemented capabilities

- Issue, renew and revoke certificates through tenant-specific issuing authorities.
- Collect signed evidence about identity, device, behaviour, certificate state and compliance.
- Compute explainable trust scores with temporal smoothing and controlled recovery.
- Use OPA policies to allow access, require additional authentication, deny an operation or quarantine a subject.
- Feed security outcomes and certificate actions back into trust without repeated or self-amplifying actions.
- Record selected event commitments on a private Hyperledger Fabric network. Store raw evidence off-chain and submit audit records asynchronously.

## Project documents

- [Prototype scope and demonstration](docs/scope.md)
- [System architecture overview](docs/architecture/system-overview.md)
- [API reference](docs/api-reference.md)
- [Final demonstration script](docs/demo-script.md)
- [Final project report](docs/reports/final-project-report.md)
- [Release checklist](docs/release-checklist.md)
- [Repository layout and component boundaries](docs/architecture/repository-layout.md)
- [Technology stack and resource budget](docs/architecture/technology-stack.md)
- [Local development setup and environment checks](docs/local-development.md)
- [Shared service contracts](packages/contracts/README.md)
- [Reliable event delivery](docs/architecture/event-delivery.md)
- [Tenant, subject and role data model](docs/architecture/tenant-identity-model.md)
- [Trusted tenant-context resolution](docs/architecture/tenant-context-resolution.md)
- [Database tenant isolation](docs/architecture/database-isolation.md)
- [Tenant resource and membership authorization](docs/architecture/resource-membership-authorization.md)
- [Tenant-owned security configuration](docs/architecture/tenant-security-configuration.md)
- [Tenant suspension and teardown controls](docs/architecture/tenant-lifecycle-controls.md)
- [Tenant isolation phase verification](docs/architecture/tenant-isolation-verification.md)
- [Redis and NATS tenant isolation](docs/architecture/runtime-tenant-isolation.md)
- [Tenant certificate-authority model](docs/architecture/tenant-pki.md)
- [PKI key protection and issuer recovery](docs/operations/pki-key-protection-and-recovery.md)
- [Complete certificate lifecycle verification](docs/architecture/certificate-lifecycle-verification.md)
- [Certificate identity profile and request contract](docs/architecture/certificate-identity-profile.md)
- [Certificate request and issuance](docs/architecture/certificate-issuance.md)
- [Certificate inventory and lifecycle records](docs/architecture/certificate-inventory.md)
- [Certificate renewal and key rotation](docs/architecture/certificate-renewal.md)
- [Certificate status validation](docs/architecture/certificate-status-validation.md)
- [Authorized certificate revocation](docs/architecture/certificate-revocation.md)
- [Signed certificate lifecycle events](docs/architecture/signed-certificate-events.md)
- [Signed evidence envelope](docs/architecture/signed-evidence-envelope.md)
- [Signed evidence ingestion](docs/architecture/evidence-ingestion.md)
- [Threat model and failure policy](docs/security/threat-model.md)
- [Cross-tenant negative testing](docs/security/cross-tenant-negative-testing.md)
- [Role, action and resource-sensitivity matrix](docs/architecture/role-action-sensitivity-matrix.md)
- [Sensitive export and administration demonstration operations](docs/architecture/sensitive-demo-operations.md)
- [PKI plus RBAC baseline mode](docs/architecture/pki-rbac-baseline-mode.md)
- [Per-request certificate and tenant-state revalidation](docs/architecture/request-state-revalidation.md)
- [Request outcome and correlation audit](docs/architecture/request-outcome-audit.md)
- [Session, timeout and replay safeguards](docs/architecture/request-safeguards.md)
- [Protected SaaS baseline verification](docs/architecture/protected-saas-baseline-verification.md)
- [Normalized trust components and initial weights](docs/architecture/trust-score-components.md)
- [Tenant-scoped trust-state and version storage](docs/architecture/tenant-scoped-trust-state.md)
- [Deterministic weighted trust score](docs/architecture/deterministic-weighted-trust-score.md)
- [Temporal trust smoothing and cold start](docs/architecture/temporal-trust-smoothing.md)
- [Concurrency-safe validated evidence consumption](docs/architecture/validated-evidence-trust-consumption.md)
- [Trust transition controls](docs/architecture/trust-transition-controls.md)
- [Versioned trust configuration lifecycle](docs/architecture/versioned-trust-configuration.md)
- [Durable trust transition explanations](docs/architecture/trust-transition-explanations.md)
- [Internal trust-score lookup and freshness contract](docs/architecture/internal-trust-score-lookup.md)
- [OPA decision contract](docs/architecture/opa-decision-contract.md)
- [OPA policy enforcement](docs/architecture/opa-policy-enforcement.md)
- [Tenant policy bundle versioning](docs/architecture/tenant-policy-bundle-versioning.md)
- [Adaptive score and resource-sensitivity policy](docs/architecture/adaptive-authorization-policy.md)
- [DENY and QUARANTINE enforcement](docs/architecture/deny-quarantine-enforcement.md)
- [Policy outage and state-freshness controls](docs/architecture/policy-outage-state-freshness.md)
- [Adaptive policy matrix verification](docs/architecture/policy-matrix-verification.md)
- [Policy decision provenance](docs/architecture/policy-decision-provenance.md)
- [Context-aware authorization verification](docs/architecture/context-aware-authorization-verification.md)
- [Fabric topology and tenant audit permissions](docs/architecture/fabric-topology-and-audit-permissions.md)
- [Backend Fabric Gateway integration](docs/architecture/backend-fabric-gateway.md)
- [Causal audit verification](docs/architecture/causal-audit-verification.md)
- [Fabric ledger privacy and tamper detection](docs/security/fabric-ledger-privacy-and-tamper-detection.md)
- [Fabric outage and recovery](docs/architecture/fabric-outage-recovery.md)
- [Security action state machine](docs/architecture/security-action-state-machine.md)
- [Idempotent security-action orchestration](docs/architecture/idempotent-security-action-orchestration.md)
- [Certificate lifecycle trust feedback](docs/architecture/certificate-lifecycle-trust-feedback.md)
- [Session and cached security-state invalidation](docs/architecture/security-state-invalidation.md)
- [Governed security recovery and re-enrollment](docs/architecture/governed-security-recovery.md)
- [Security-action and recovery audit anchoring](docs/architecture/security-action-audit-anchoring.md)
- [Security-action adversarial verification](docs/architecture/security-action-adversarial-verification.md)
- [Security-action operational failure handling](docs/architecture/security-action-operational-failure-handling.md)
- [Tenant certificate dashboard](docs/architecture/tenant-certificate-dashboard.md)
- [Tenant trust and decision history dashboard](docs/architecture/tenant-trust-decision-dashboard.md)
- [Tenant audit verification and operations dashboard](docs/architecture/tenant-audit-operations-dashboard.md)
- [JWT plus RBAC evaluation baseline](docs/architecture/jwt-rbac-evaluation-baseline.md)
- [Reproducible evaluation protocol and labels](docs/architecture/reproducible-evaluation-protocol.md)
- [Benign and attack workload runner](docs/architecture/benign-attack-workload-runner.md)
- [Effectiveness and isolation evaluation](docs/reports/effectiveness-and-isolation-evaluation.md)
- [Latency, throughput and recovery evaluation](docs/reports/latency-throughput-and-recovery-evaluation.md)
- [Ablation study and research conclusions](docs/reports/ablation-study-and-research-conclusions.md)
- [Adaptive trust-engine verification and calibration fixtures](docs/architecture/trust-engine-verification.md)
- [Phase 6 adaptive trust-engine implementation report](docs/reports/phase-6-adaptive-trust-engine-report.md)

Bootstrap the core services with `npm run infra:init`, `npm run pki:init`, `npm run policy:test`, `npm run infra:up`, `npm run infra:migrate` and `npm run demo:provision`, then run `npm run tenant-isolation:verify` for the Phase 2 gate, `npm run certificate-lifecycle:verify` for the Phase 3 gate, `npm run protected-saas:verify` for the complete Phase 4 gate, `npm run trust-engine:verify` for the complete Phase 6 gate and `npm run context-aware-authorization:verify` for the complete Phase 7 gate. The individual Phase 7 boundary commands remain available for diagnosis, including `npm run adaptive-authorization-scenario:verify` for T7.10 alone. Run `npm run foundation:check` for the complete foundation and `npm run foundation:clean` to verify a disposable first start without touching normal development data. Full commands, local ports, safe shutdown and deliberate reset steps are in the development guide.

## Review console

Run `npm run demo:review` and open `http://127.0.0.1:4173` for the local security dashboard. It uses deterministic synthetic tenants and the repository's tenant-context, trust-model and authorization boundaries. Tenant members see only their own subject history; tenant administrators see same-tenant certificate and trust history. Issue, renew and revoke demo controls are authorized again by the backend and update only in-memory review state, which resets on restart. Infrastructure-heavy mTLS, certificate-authority and gateway checks remain replayed as labelled review scenarios; the dashboard never loads private keys or production credentials. Run `npm run tenant-dashboard:verify` for T10.1 and `npm run trust-dashboard:verify` for T10.2.

The Audit operations view also shows tenant-scoped Fabric delivery, causal verification and security-action health without raw evidence or credentials. Run `npm run audit-operations-dashboard:verify` for T10.3.

## Infrastructure

The application uses TypeScript on Node.js 24 LTS, Fastify for the API and React with Vite for the dashboard. PostgreSQL holds durable application state, Redis holds short-lived runtime state, NATS delivers events, step-ca provides certificate services, OPA makes policy decisions and Hyperledger Fabric records audit commitments. Docker Desktop with WSL2 runs Linux services locally. See the technology stack document for version targets and component bootstrap boundaries.

## Configuration and generated files

Commit application source, infrastructure definitions, migrations, policy source, tests, dependency lockfiles and project documentation. Use `.env.example` files with placeholders to document configuration. Keep credentials, private keys, generated identities, local database contents and raw telemetry outside version control. Generated local service data belongs under `runtime/` unless a component explicitly documents another ignored location.

Synthetic test fixtures may live under `tests/fixtures/`. Never copy real tenant evidence or production credentials into fixtures.

## Evaluation

Compare the proposed framework with JWT plus RBAC and tenant-scoped X.509 PKI plus RBAC on equivalent workloads. Measure decision latency, security outcomes, false restrictions, revocation enforcement, tenant isolation and audit verification. Trust weights and thresholds are initial design choices until evaluated.

Run `npm run evaluation-protocol:verify` to check the pre-registered partitions, labels, sample plan, hardware declaration, metric denominators and verified source-slide map.
