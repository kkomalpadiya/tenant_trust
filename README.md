# Tenant Trust

An adaptive security research prototype for multi-tenant SaaS. The project combines tenant-bound X.509 identities, continuously updated trust scores, context-aware authorization and verifiable security audit records.

A valid certificate establishes identity. Access also depends on tenant membership, role, resource ownership, request context and current trust. A high trust score cannot override an invalid certificate or a cross-tenant access violation.

## Current status

The repository contains the initial scope, repository design, selected technology stack, shared event contracts, the tenant/subject/role data model, deterministic two-tenant identities, resources and security configuration, tested tenant-context, actor-aware PostgreSQL resource, membership, configuration and lifecycle authorization, audited tenant suspension and teardown, Redis key-scoping and NATS subject/consumer controls, and a runnable PostgreSQL, Redis, NATS JetStream, step-ca and OPA foundation. Application services and evaluation tools have not been implemented yet.

## Planned capabilities

- Issue, renew and revoke certificates through tenant-specific issuing authorities.
- Collect signed evidence about identity, device, behaviour, certificate state and compliance.
- Compute explainable trust scores with temporal smoothing and controlled recovery.
- Use OPA policies to allow access, require additional authentication, deny an operation or quarantine a subject.
- Feed security outcomes and certificate actions back into trust without repeated or self-amplifying actions.
- Record selected event commitments on a private Hyperledger Fabric network. Store raw evidence off-chain and submit audit records asynchronously.

## Project documents

- [Prototype scope and demonstration](docs/scope.md)
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
- [Redis and NATS tenant isolation](docs/architecture/runtime-tenant-isolation.md)
- [Tenant certificate-authority model](docs/architecture/tenant-pki.md)
- [Threat model and failure policy](docs/security/threat-model.md)
- [Cross-tenant negative testing](docs/security/cross-tenant-negative-testing.md)

Bootstrap the core services with `npm run infra:init`, `npm run pki:init`, `npm run policy:test`, `npm run infra:up`, `npm run infra:migrate` and `npm run demo:provision`, then run `npm run foundation:check`. Use `npm run foundation:clean` to verify a disposable first start without touching normal development data. Full commands, local ports, safe shutdown and deliberate reset steps are in the development guide.

## Planned infrastructure

The application uses TypeScript on Node.js 24 LTS, Fastify for the API and React with Vite for the dashboard. PostgreSQL holds durable application state, Redis holds short-lived runtime state, NATS delivers events, step-ca provides certificate services, OPA makes policy decisions and Hyperledger Fabric records audit commitments. Docker Desktop with WSL2 runs Linux services locally. See the technology stack document for version targets and component bootstrap boundaries.

## Configuration and generated files

Commit application source, infrastructure definitions, migrations, policy source, tests, dependency lockfiles and project documentation. Use `.env.example` files with placeholders to document configuration. Keep credentials, private keys, generated identities, local database contents and raw telemetry outside version control. Generated local service data belongs under `runtime/` unless a component explicitly documents another ignored location.

Synthetic test fixtures may live under `tests/fixtures/`. Never copy real tenant evidence or production credentials into fixtures.

## Evaluation

Compare the proposed framework with JWT plus RBAC and tenant-scoped X.509 PKI plus RBAC on equivalent workloads. Measure decision latency, security outcomes, false restrictions, revocation enforcement, tenant isolation and audit verification. Trust weights and thresholds are initial design choices until evaluated.
