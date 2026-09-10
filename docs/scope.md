# Prototype scope and demonstration

## Objective

Build and evaluate a local multi-tenant SaaS prototype in which validated evidence changes trust, trust informs authorization, and justified security actions feed back into trust. Preserve a verifiable causal history of selected security events without putting raw evidence on-chain.

## Demonstration tenants and identities

Use two synthetic tenants, `tenant-alpha` and `tenant-beta`, with separate members, records, certificate issuers, evidence sources, trust settings and policy versions. Each tenant has at least one administrator and one ordinary member. The demonstration subject Alice belongs to `tenant-alpha`.

| Role | Intended authority |
| --- | --- |
| Platform administrator | Provision and suspend tenants and operate platform infrastructure. This role does not automatically grant access to tenant business records. |
| Tenant administrator | Manage members and certificate actions within the administrator's tenant, subject to current policy and additional authentication where required. |
| Tenant member | Access the member's profile and permitted records within the member's tenant. |

## SaaS operations

| Operation | Scope and intended restriction |
| --- | --- |
| Read own profile | Subject and tenant must match the authenticated identity. The initial policy example requires trust of at least 55. |
| Read tenant records | Membership, role and resource ownership must pass alongside the applicable trust policy. |
| Create or update tenant records | Only roles granted write access may act. Evaluate trust and request context for each operation. |
| Export tenant records | Treat as sensitive. Evaluate export size, current context, role and trust, with additional authentication or denial when policy requires it. |
| Manage membership and certificates | Tenant administration only, with strict subject and issuer binding and an audit record. |
| Rotate an administrative key | The initial policy example requires trust of at least 90 plus additional authentication. |

The exact permissions and score boundaries will be implemented as a tested policy matrix. These initial examples do not imply a universal allow threshold for every operation.

## Certificate and security states

- Issuance establishes an authorized, tenant-bound identity with an X.509 certificate.
- Renewal and key rotation must respect membership, tenant state and certificate lifecycle rules.
- Suspension or quarantine restricts access through application security state and may be reversible after governed recovery.
- Revocation permanently invalidates that certificate. Recovery, when authorized, requires fresh issuance rather than restoring the revoked certificate.
- A valid certificate alone never guarantees access. An invalid, expired, revoked or foreign-tenant certificate is rejected regardless of trust score.

Revocation is the certificate action covered by the project alongside issuance and renewal. The implementation must distinguish permanent revocation from temporary suspension of access.

## Trust inputs and initial model

Use signed, tenant-scoped evidence for identity, device, behaviour, certificate state and compliance. Start with weights 0.20, 0.25, 0.25, 0.15 and 0.15 respectively, as proposed in the project slides. Apply temporal smoothing and explicitly define missing evidence, stale evidence, cold start, source influence and recovery rules before implementing score-driven enforcement.

Device and compliance signals may come from deterministic simulators in this prototype. Label those signals synthetic; do not claim a real device attestation or compliance integration. A signature authenticates the source of a statement but does not prove that the statement is true.

## Access outcomes

The policy engine returns `ALLOW`, `STEP_UP`, `DENY` or `QUARANTINE` using trust, role, tenant policy and request context. Additional authentication must use a real selected second factor, with proof bound to the subject, tenant, session and requested action. A frontend confirmation button alone does not satisfy this requirement.

Low trust may restrict sensitive operations. Permanent certificate revocation requires explicit severity and corroboration rules; it must not follow automatically from every small score decrease.

## Audit scope

Select certificate lifecycle events, trust transitions/checkpoints, policy changes, access decisions and resulting security actions for commitment recording. Link each selected chain through evidence references, model/configuration version, policy version, decision ID and action ID.

Keep raw evidence and detailed application state in tenant-scoped off-chain storage. Store canonical hash commitments and the minimum state anchors needed for verification on Hyperledger Fabric. Submit them through durable asynchronous delivery. Treat pending and failed ledger writes as visible states, and verify commit confirmation before reporting a record committed.

Hash verification can detect changes to the committed record. It cannot establish the truth of originally false evidence or compensate for an unspecified trust boundary between ledger operators.

## End-to-end demonstration

1. Provision both tenants, roles, records and tenant-bound certificates.
2. Alice accesses an allowed record from the registered device with normal evidence.
3. Produce signed synthetic evidence for an unknown device and repeated failed authentication attempts, then request a sensitive export using the same otherwise valid certificate.
4. Show the trust transition, component explanation and exact policy version. The policy requires additional authentication, denies the export or quarantines the subject according to the scenario.
5. In a separate severe scenario, trigger a justified certificate action. Confirm its effect on subsequent requests and existing security state.
6. Verify the causal audit records. Change an off-chain test record and show a verification failure.
7. Attempt cross-tenant access, replay evidence and flood a source. Show rejection or bounded influence without contaminating the other tenant.
8. Interrupt Fabric, show pending durable audit delivery, restore it and reconcile commitments. Runtime authorization follows its defined failure policy throughout.
9. Demonstrate governed recovery while keeping any revoked certificate permanently invalid.

## Evaluation boundary

Compare JWT plus RBAC, tenant-scoped PKI plus RBAC and the proposed framework on the same resources, tenant constraints and workloads. Use separately defined calibration and evaluation scenarios. Report latency distributions, detection and false restriction rates with denominators, revocation enforcement delay, isolation outcomes and audit verification results.

## Outside the initial prototype

Production high availability, billing/subscriptions, external customer onboarding, hardware device attestation, commercial compliance certification and an automatically trained machine-learning trust model are outside the initial scope. The project delivers a deterministic, explainable research prototype and reports its limitations.

## Remaining implementation decisions

Application languages, frontend framework, runtime targets and initial resource budgets are defined in [the technology stack](architecture/technology-stack.md). The second factor, certificate status mechanism, Fabric topology, detailed thresholds and reporting deadline remain decisions for their respective tasks. This document does not claim those components are already implemented or experimentally validated.
