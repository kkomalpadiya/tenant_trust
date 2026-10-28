# System architecture overview

## Purpose and scope

Tenant Trust is a local research prototype for adaptive security in a multi-tenant SaaS system. It combines tenant-bound X.509 identity, authoritative tenant state, signed security evidence, deterministic trust scoring, OPA policy decisions, controlled certificate actions and tamper-evident audit commitments. The prototype uses two synthetic tenants and intentionally keeps raw evidence off the ledger.

This document is the release-level architecture map. Detailed design records remain in the linked component documents.

## Runtime components

| Boundary | Responsibility | Primary implementation |
| --- | --- | --- |
| Review console | Demonstrates tenant-scoped certificate, trust, authorization and audit views with synthetic data | `apps/review-demo` |
| SaaS API | Exposes protected profile, record, export, administration, step-up and evidence routes | `apps/api` |
| Identity and tenant context | Accepts authenticated gateway identity, revalidates certificate and tenant state, then derives immutable tenant context | `packages/gateway-identity`, `packages/tenant-context`, `packages/certificate-status` |
| Evidence pipeline | Validates signed envelopes, source authority, freshness and replay state, then stores encrypted off-chain evidence and publishes bounded events | `services/evidence`, `packages/evidence-sources`, `packages/evidence-events` |
| Trust engine | Normalizes components, calculates weighted and smoothed scores, persists tenant-scoped versions and records explanations | `services/trust`, `packages/trust-model` |
| Authorization | Applies role eligibility and live OPA policy to certificate state, tenant context, resource sensitivity, request context and current trust | `packages/authorization`, `packages/policy`, `apps/api/src/policy-enforcement.mjs` |
| Security orchestration | Converts corroborated outcomes into idempotent restrictions, quarantine, revocation or governed recovery | `services/orchestrator` |
| Audit delivery | Builds canonical commitments, writes a durable outbox and reconciles asynchronous Fabric submissions | `services/audit`, `apps/api/src/fabric-audit-gateway.mjs` |
| Infrastructure | Supplies PostgreSQL, Redis, NATS JetStream, step-ca, OPA and the two-channel Fabric network | `infra`, `database`, `policies`, `chaincode` |

## Request and feedback flow

1. The gateway completes mutual TLS and forwards only its authenticated certificate result over the trusted internal boundary.
2. The API rejects session credentials, revalidates the certificate and current tenant state, and derives tenant and subject identity from trusted state.
3. The repository loads resources through tenant scope. Caller-provided tenant identifiers can only act as consistency checks.
4. For adaptive mode, the API assembles a complete policy input from authoritative certificate, tenant, resource, request and trust state.
5. OPA returns `ALLOW`, `STEP_UP`, `DENY` or `QUARANTINE` with policy and state provenance. The API enforces the result before the operation runs.
6. Signed evidence enters through a separate bounded endpoint. Validation covers schema, source enrollment, tenant and subject binding, Ed25519 signature, time window, sequence and replay state.
7. Accepted evidence updates the explainable trust state. Corroborated severe outcomes can request an idempotent security action.
8. Certificate lifecycle results feed back into trust exactly once. Terminal events cannot recursively trigger another certificate action.
9. Request, evidence, trust, decision and action records produce canonical commitments. A durable outbox submits them to the tenant's Fabric channel after the request path completes.
10. The causal verifier rebuilds off-chain commitments and checks exact ledger values, missing links, tenant placement and modification.

## Authoritative state and privacy

- PostgreSQL holds durable tenant, identity, certificate, evidence metadata, trust, decision, action and audit-delivery state. Row-level and actor-aware controls preserve tenant scope.
- Redis holds short-lived tenant-prefixed runtime state. Security actions invalidate relevant session and cache entries.
- NATS JetStream uses tenant-scoped subjects and consumers. Every consumer still validates the event and tenant binding.
- Raw evidence remains encrypted and off-chain. Fabric receives hashes and selected bounded metadata, never credentials or evidence payloads.
- Tenant Alpha and Tenant Beta use separate Fabric channels. Writer and verifier identities have different permissions.

## Availability and failure policy

Authentication, certificate validity, tenant authority, policy input integrity and state freshness fail closed. A missing or stale trust score cannot silently become a trusted score. OPA unavailability and request-state failures return a generic service-unavailable response.

Fabric remains outside the authorization path. When a peer is unavailable, authorization continues, the durable outbox retains pending commitments, and the worker retries after recovery. Operational views surface stuck, failed and quarantined work without exposing evidence content or credentials.

## Deployment and verification scope

The release target is a single Windows workstation using Docker Desktop with WSL2. It is a reproducible prototype, not a production topology. `npm run foundation:clean` verifies a disposable first start, migrations, demo provisioning, services, security gates, tests and dependency audit, then removes only its isolated resources. `npm run release:verify` adds final-package checks.

The complete boundary designs are documented in the repository index. Start with [repository layout](repository-layout.md), [protected SaaS verification](protected-saas-baseline-verification.md), [trust-engine verification](trust-engine-verification.md), [context-aware authorization](context-aware-authorization-verification.md), [causal audit verification](causal-audit-verification.md) and [complete security feedback loop verification](complete-security-feedback-loop-verification.md).
