# Tenant Trust

An adaptive security research prototype for multi-tenant SaaS. The project combines tenant-bound X.509 identities, continuously updated trust scores, context-aware authorization and verifiable security audit records.

A valid certificate establishes identity. Access also depends on tenant membership, role, resource ownership, request context and current trust. A high trust score cannot override an invalid certificate or a cross-tenant access violation.

## Current status

The repository contains the initial scope and repository design. Application services, infrastructure configuration and evaluation tools have not been implemented yet. There is no runnable application at this stage.

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

## Planned infrastructure

The initial design uses PostgreSQL for durable application state, Redis for short-lived runtime state, NATS for event delivery, step-ca for certificate services, OPA for policy decisions and Hyperledger Fabric for audit commitments. Application languages, runtime versions and local deployment configuration will be selected before implementation.

## Configuration and generated files

Commit application source, infrastructure definitions, migrations, policy source, tests, dependency lockfiles and project documentation. Use `.env.example` files with placeholders to document configuration. Keep credentials, private keys, generated identities, local database contents and raw telemetry outside version control. Generated local service data belongs under `runtime/` unless a component explicitly documents another ignored location.

Synthetic test fixtures may live under `tests/fixtures/`. Never copy real tenant evidence or production credentials into fixtures.

## Evaluation

Compare the proposed framework with JWT plus RBAC and tenant-scoped X.509 PKI plus RBAC on equivalent workloads. Measure decision latency, security outcomes, false restrictions, revocation enforcement, tenant isolation and audit verification. Trust weights and thresholds are initial design choices until evaluated.
