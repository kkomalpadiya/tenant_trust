# Local development setup

## Tools

Use Git, Node.js 24.20.0, npm, Docker Desktop with Linux containers, Docker Compose v2 and Ubuntu under WSL2. The tested local Docker baseline is Desktop 4.41.2 / Engine 28.1.1 / Compose 2.35.1 with WSL 2.3.26 and Ubuntu 24.04. Newer supported releases should be verified with the same checks before use.

The application image is `node:24.20.0-bookworm-slim`. `.node-version` records the host target, but it does not install or switch Node by itself. Upgrade host Node to that target before running application dependency installs. The basic checker can run on an earlier Node 24 patch and reports the mismatch explicitly. No host Go installation is needed for the selected TypeScript chaincode.

Keep host npm dependencies and container Linux dependencies separate. Install the committed npm workspaces from the lockfile with `npm ci`; the API workspace uses the pinned Fastify and node-postgres versions recorded in `config/toolchain.json`.

## Verify the environment

From the repository root in PowerShell:

```powershell
node scripts/check-environment.mjs
docker pull node:24.20.0-bookworm-slim
node scripts/check-environment.mjs --smoke
```

The pull downloads a project runtime image. The smoke test uses no network and removes its container on exit. It checks Linux, the selected Node version and an Ed25519 signing round trip. It does not start application services.

Before bootstrapping core infrastructure, run:

```powershell
node scripts/check-environment.mjs --profile=core
```

Before running the Fabric demonstration, use `--profile=fabric`. A resource failure is a real failed check; a successful smoke test does not clear it.

## Fabric audit network

T8.2 adds a separately managed Fabric Compose project. Run the Fabric resource check, then start and verify the private audit network:

```powershell
npm run check:environment -- --profile=fabric
npm run fabric:up
npm run fabric:verify
npm run ledger-privacy:verify
npm run fabric:status
```

`fabric:up` uses digest-pinned Fabric 2.5.16 peer, orderer and tools images plus Fabric CA 1.5.17. It creates ignored organization identities and channel blocks under `runtime/fabric`, preserves them on repeated starts, and joins the platform peer to both tenant channels while each tenant peer joins only its own. Fabric enrollment and TLS certificates are issued by four Fabric CAs and never reuse the step-ca SaaS certificate hierarchy. `ledger-privacy:verify` adds live cross-tenant auditor probes and off-chain tamper tests after the normal network gate. See [Reproducible private Fabric network](architecture/reproducible-private-fabric-network.md) and [Fabric ledger privacy and tamper detection](security/fabric-ledger-privacy-and-tamper-detection.md).

`npm run fabric-outage-recovery:verify` is the Phase 8 recovery gate. It performs a real stop/start of the Alpha tenant peer, proves the authorization scenario continues while Fabric is unavailable, observes the queued access-decision commitment as a visible failed delivery, then restores the peer and verifies the exact event commits with no remaining gap. The script restores the peer on failure. See [Fabric outage and recovery](architecture/fabric-outage-recovery.md).

Stop only the Fabric services while retaining their identities and ledgers:

```powershell
npm run fabric:down
```

## Docker and Ubuntu

Start Docker Desktop and wait for the Linux engine. Enable the WSL2 engine and Ubuntu integration in Docker settings if Ubuntu cannot access Docker. Confirm:

```powershell
docker version
docker compose version
wsl -d Ubuntu -- docker version
```

Docker documents WSL 2.1.5 as the minimum, with current WSL recommended. The existing WSL2 installation satisfies that minimum. [Docker WSL setup](https://docs.docker.com/desktop/features/wsl/)

## Increase memory before core service bootstrap

If the checker reports about 2 GiB for Docker, update the existing `memory` entry under `[wsl2]` in `%UserProfile%\.wslconfig` to `4GB` for core development. Preserve other settings and avoid adding a second `[wsl2]` section. For the later Fabric phase, start with `6GB` and measure memory usage.

This is a global WSL setting. Save work in every WSL session and stop running containers through their project's normal procedure before applying it. Quit Docker Desktop, run `wsl --shutdown`, then reopen Docker Desktop. This interrupts all WSL distributions, so do it at a convenient time. Rerun the core check afterward. [Microsoft WSL configuration](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

Close unneeded applications if host free memory is low. Keep project database and ledger contents in Docker named volumes; retain source code in the chosen checkout. Do not delete or prune other projects' images, containers or volumes as part of setup.

## PostgreSQL, Redis and NATS

Create the ignored local environment file once, start both services and apply migrations:

```powershell
npm run infra:init
npm run pki:init
npm run policy:test
npm run infra:up
npm run infra:migrate
npm run demo:provision
npm run infra:check
npm run demo:verify
npm run database-isolation:verify
npm run resource-membership:verify
npm run security-configuration:verify
npm run trust-configuration:verify
npm run cross-tenant:verify
npm run tenant-lifecycle:verify
npm run tenant-isolation:verify
npm run pki-definition:verify
npm run certificate-profile:verify
npm run certificate-issuance:verify
npm run certificate-inventory:verify
npm run certificate-renewal:verify
npm run certificate-status:verify
npm run certificate-revocation:verify
npm run certificate-events:verify
npm run pki-recovery:verify
npm run certificate-lifecycle:verify
npm run evidence-envelope:verify
npm run evidence-sources:verify
npm run evidence-simulators:verify
npm run evidence-ingestion:verify
npm run trust-explanations:verify
npm run trust-score-lookup:verify
npm run trust-engine:verify
npm run mtls-gateway:verify
npm run gateway-spoofing:verify
npm run profile-record-api:verify
npm run role-action-matrix:verify
npm run sensitive-operations:verify
npm run pki-rbac-baseline:verify
npm run request-state:verify
npm run request-outcomes:verify
npm run request-safeguards:verify
npm run protected-saas:verify
npm run policy-resilience:verify
npm run policy-matrix:verify
npm run policy-provenance:verify
npm run adaptive-authorization-scenario:verify
npm run context-aware-authorization:verify
npm run security-action-state-machine:verify
npm run security-action-rules:verify
npm run security-action-orchestration:verify
npm run security-action-adversarial:verify
npm run certificate-trust-feedback:verify
npm run security-state-invalidation:verify
npm run test:tenant-context
npm run messaging:verify
npm run runtime-isolation:verify
npm run security-services:verify
npm run foundation:check
```

PostgreSQL listens on `127.0.0.1:55432`, Redis on `127.0.0.1:56379`, NATS on `127.0.0.1:55022`, step-ca on `https://127.0.0.1:59000` and OPA on `127.0.0.1:58181`. The non-default ports avoid other local projects, while loopback binding prevents LAN access. Application containers use the Compose names `postgres:5432`, `redis:6379`, `nats:4222`, `step-ca:9000` and `opa:8181` on the backend network.

The generated `.env` contains local credentials and is ignored by Git. `.env.example` contains safe placeholders and the digest-pinned images. `npm run infra:init` also creates the ignored `runtime/secrets/step-ca-password.txt` file when it is absent. Rerunning the command adds newly documented settings, including the Tenant Alpha and Tenant Beta NATS credentials, without replacing existing secrets. Recreate NATS after adding those settings so its mounted permission configuration is reloaded.

`npm run pki:init` initializes step-ca only when its named volume has no CA configuration. Repeated runs preserve the same CA identity. The `--force` option for `infra:init` rotates environment credentials but deliberately preserves the step-ca password file. CA key-password rotation requires a separate rekey procedure; deleting or replacing the password file alone can make the encrypted intermediate key unusable.

Migrations are ordered SQL files under `database/migrations`. `npm run infra:migrate` records each successful filename in `platform.schema_migrations` and skips it on later runs. Add a new numbered file for every schema change instead of editing an already-applied migration.

Tenant-scoped database code must start a transaction and call `identity.set_tenant_actor_context` with tenant and subject IDs from the resolved trusted context before querying. Forced row-level security then rechecks active membership and roles while limiting identity, resource and security-configuration rows to that actor. `npm run database-isolation:verify` proves tenant isolation and connection reuse. `npm run resource-membership:verify` proves owner-only member access, tenant-wide administrator access, role-change behavior, suspended-membership denial and last-administrator protection. `npm run security-configuration:verify` proves that issuer mappings, evidence sources, trust settings and policy versions remain tenant-owned and administrator-controlled.

`npm run cross-tenant:verify` is the combined negative gate for client-selected tenant claims, guessed identifiers and reused connections across the shared resolver, PostgreSQL, Redis and NATS. The profile and tenant-record routes add endpoint and live database cases in `npm run profile-record-api:verify`; future routes must extend the same negative coverage. See [Cross-tenant negative testing](security/cross-tenant-negative-testing.md).

Platform tenant lifecycle operations use the separate `tenant_trust_platform_admin` privilege set and transaction-local `identity.set_platform_actor_context` binding. `npm run tenant-lifecycle:verify` proves that suspension immediately blocks existing and new database activity, reactivation is audited, and irreversible soft teardown removes tenant roles while retaining referenced identities, memberships, resources, configuration and append-only audit history. See [Tenant suspension and teardown controls](architecture/tenant-lifecycle-controls.md).

`npm run demo:provision` applies every ordered SQL seed under `database/seeds`. It creates the deterministic Tenant Alpha and Tenant Beta subjects, memberships, role assignments, synthetic resources, planned issuer mappings, planned synthetic evidence sources, active trust settings and published policy metadata used by the prototype scenarios. It is safe to rerun and does not reactivate suspended rows or overwrite changed lifecycle versions. It fails when a deterministic identity, ownership or configuration identifier conflicts with different data. `npm run demo:verify` checks the mapping and exercises lifecycle persistence in a transaction that is rolled back.

`npm run trust-explanations:verify` validates the generated `trust.updated.v1` event and runs the T6.8 transition ledger against PostgreSQL inside a rolled-back transaction. Apply migration `023_trust_transition_explanations.sql` with `npm run infra:migrate` before running it in an environment that has not yet been migrated.

`npm run trust-score-lookup:verify` is the T6.9 internal lookup gate. It proves that the application receives the current actor's fresh score, age, transition and model/configuration versions; that the exact freshness boundary remains usable; and that stale or missing state requires `DENY` without exposing a stale score as policy input. Apply migration `024_internal_trust_score_lookup.sql` with `npm run infra:migrate` first. See [Internal trust-score lookup and freshness contract](architecture/internal-trust-score-lookup.md).

`npm run policy-bundles:verify` is the T7.3 tenant policy lifecycle gate. It runs the policy-service tests, checks valid and invalid Rego v1 fixtures with the pinned OPA image, exercises publication/activation/isolation/history against PostgreSQL and verifies that API decisions match the exact active bundle provenance. Apply migration `025_tenant_policy_bundle_lifecycle.sql` first. Database fixtures roll back. See [Tenant policy bundle versioning](architecture/tenant-policy-bundle-versioning.md).

`npm run adaptive-policy:verify` is the T7.4 score and resource-sensitivity policy gate. It tests tenant policy-data validation, all exact Rego boundaries with the pinned OPA image, a real decision against the API output schema and canonical input digest, and protected-route enforcement regression tests. The checked-in thresholds are explicitly unvalidated prototype defaults. See [Adaptive score and resource-sensitivity policy](architecture/adaptive-authorization-policy.md).

`npm run policy-outcomes:verify` is the T7.6 DENY/QUARANTINE enforcement gate. It proves ordinary denial cannot reach protected data or emit an action, quarantine cannot reach protected data but commits one correlated append-only action request, persistence failures roll back, and sensitive-operation receipts are not reserved for quarantined work. Apply migration `027_policy_denial_quarantine_enforcement.sql` first. See [DENY and QUARANTINE enforcement](architecture/deny-quarantine-enforcement.md).

`npm run policy-resilience:verify` is the T7.7 outage and state-freshness gate. It proves OPA timeout and response failures cannot reuse an allow, stale or in-flight-expiring trust cannot reach protected data, the API exposes only a non-cacheable generic unavailable response, and the actor-bound certificate lookup serializes lifecycle updates without granting the runtime role direct `UPDATE`. Apply migration `028_policy_state_freshness_controls.sql` first. See [Policy outage and state-freshness controls](architecture/policy-outage-state-freshness.md).

`npm run policy-matrix:verify` is the T7.8 adaptive-policy matrix gate. It verifies all supported actions plus exact and decimal score boundaries, roles, resource sensitivities, different valid tenant configurations and expired step-up proof through the pinned OPA image and API output contract. It requires Docker and `.env`, but does not require running services or mutate persistent infrastructure. See [Adaptive policy matrix verification](architecture/policy-matrix-verification.md).

`npm run policy-provenance:verify` is the T7.9 complete decision-provenance gate. It proves that every contract-valid adaptive decision is canonically hashed and durably bound to its server request, result, certificate and authority versions, trust transition and explanation digest, active policy bundle and canonical input digest. It also checks fail-closed persistence, exact-replay idempotency, cross-tenant rejection, least privilege and append-only enforcement. Apply migration `029_policy_decision_provenance.sql` first. Database fixtures roll back. See [Policy decision provenance](architecture/policy-decision-provenance.md).

`npm run adaptive-authorization-scenario:verify` is the focused T7.10 scenario. The same valid active certificate first receives normal access and an allowed, step-up-bound sensitive export at trust 69. New account-takeover behavior evidence creates a complete critical-override explanation, lowers controlled trust to 20 and changes a fresh sensitive-export request to `QUARANTINE`. The pinned OPA output passes the API contract and canonical provenance binds the result to the new transition and explanation digest. The fixture remains an unvalidated deterministic prototype case and makes no detection-effectiveness claim.

`npm run context-aware-authorization:verify` is the complete Phase 7 gate. It runs every Phase 7 contract, lifecycle, policy, step-up, outcome, resilience, matrix, provenance and scenario check in fail-fast order. Start the local stack, provision the demo and apply migrations through `029_policy_decision_provenance.sql` first. Database fixtures used by the component gates roll back. Use `--scenario-only` only for focused diagnosis. See [Context-aware authorization verification](architecture/context-aware-authorization-verification.md).

`npm run trust-engine:verify` is the Phase 6 completion gate. It runs the full repository suite and deterministic calibration fixtures, then verifies scoring boundaries, missing/stale behavior, recovery, replay/flood safeguards, tenant-scoped state/configuration, evidence consumption, explanations and the internal lookup against PostgreSQL. The fixtures remain explicitly labelled as unvalidated prototype defaults and do not establish effectiveness. See [Adaptive trust-engine verification and calibration fixtures](architecture/trust-engine-verification.md).

`npm run tenant-isolation:verify` is the Phase 2 completion gate. It reprovisions the deterministic Alpha/Beta scenario, then runs the identity, database-query, resource, membership, security-configuration, cross-tenant tampering, Redis cache, NATS event and tenant-suspension checks in a fixed fail-fast order. Run the individual commands while diagnosing a boundary, then rerun this complete gate before treating tenant isolation as verified. See [Tenant isolation phase verification](architecture/tenant-isolation-verification.md).

`npm run pki-definition:verify` is the T3.1 design gate. It validates the committed offline-root and per-tenant intermediate hierarchy, checks that Alpha and Beta do not share CA state, keys, provisioners, credentials or service principals, confirms issuer selection is derived from validated tenant context, and matches the planned manifest entries to the database seed mappings. This is a static boundary check; it does not start the two tenant authorities or claim live certificate issuance isolation. See [Tenant certificate-authority hierarchy](architecture/tenant-pki.md).

`npm run certificate-profile:verify` is the T3.2 contract gate. It validates the normalized issue/renew request schema and locks the client-certificate subject, URI SAN, key usages, algorithms, serial-number and validity rules. It also proves that callers cannot inject an issuer route, certificate identity or privilege extensions, validity timestamps or private-key material. The gate defines request behavior but does not perform cryptographic CSR verification or live issuance. See [Certificate identity profile and request contract](architecture/certificate-identity-profile.md).

`npm run certificate-issuance:verify` is the T3.3 enrollment gate. It runs the request authorization tests, then uses the pinned Smallstep image to generate ephemeral P-256 keys, signed CSRs, one platform root and distinct Alpha/Beta intermediates. It issues and parses real client certificates, verifies each immediate issuer signature, and rejects unauthorized subject enrollment, foreign membership, foreign issuer mapping and wrong-issuer signing. Private keys stay under ignored runtime storage and the gate removes them on exit. See [Certificate request and issuance](architecture/certificate-issuance.md).

`npm run certificate-inventory:verify` is the T3.4 durable inventory gate. It tests trusted inventory-record construction, then runs a rolled-back PostgreSQL scenario against the migrated and provisioned stack. The scenario proves complete certificate metadata, atomic initial lifecycle events, self/admin recording rules, member-own/admin-wide reads, cross-tenant denial, immutable event history, unique issuer serials and conflicting-idempotency rejection. See [Certificate inventory and lifecycle records](architecture/certificate-inventory.md).

`npm run certificate-renewal:verify` is the T3.5 renewal and rotation gate. It proves the final-quarter renewal window, active tenant/subject/membership and predecessor requirements, trusted pre-signing CSR key inspection, a different SPKI digest, real Smallstep certificate rotation, atomic successor activation and predecessor supersession, causal lifecycle events, idempotent replay and denial of early, suspended, revoked, superseded and foreign-tenant attempts. See [Certificate renewal and key rotation](architecture/certificate-renewal.md).

`npm run certificate-status:verify` is the T3.6 certificate-status contract gate. It selects the PostgreSQL application inventory as the authority instead of assuming the configured CA exposes CRL or OCSP, and proves exact tenant/certificate binding, X.509 validity checks, five-second source freshness, a 30-second maximum successful-cache lifetime, and fail-closed behavior for unknown, revoked, expired, superseded, malformed, stale, timed-out or unavailable status. See [Certificate status validation](architecture/certificate-status-validation.md).

`npm run certificate-revocation:verify` is the T3.7 authorized-revocation gate. It proves owner and same-tenant administrator authorization, exact certificate and issuer binding, approved permanent reasons, issuer-confirmation-before-persistence ordering, durable idempotent replay, active-to-revoked atomic state change, append-only reasoned events and denial of foreign, unauthorized, non-active or conflicting requests. The gate also issues and actively revokes a disposable Smallstep certificate and confirms it cannot renew. See [Authorized certificate revocation](architecture/certificate-revocation.md).

`npm run certificate-events:verify` is the T3.8 signed lifecycle-event gate. It proves lifecycle inserts create an outbox row in the same PostgreSQL transaction; only the constrained worker can claim, retry, expire or confirm delivery; issuance, renewal, revocation and expiry payloads preserve their source and causal identities; Ed25519 signatures cover deterministic canonical content; and JetStream acknowledgement precedes a published outbox state. The live broker check rejects tampered signed content before consumer acknowledgement. See [Signed certificate lifecycle events](architecture/signed-certificate-events.md).

`npm run pki-recovery:verify` is the T3.9 key-protection and recovery gate. It creates only disposable CA volumes, confirms root and intermediate key mode `0600`, makes an scrypt/AES-256-GCM authenticated backup outside the repository, rejects a wrong passphrase before creating restore state, restores into a distinct volume, compares the root identity, starts the recovered CA and proves new issuance. It removes all disposable containers, volumes and staging files. Operational backup, availability restore and issuer/root compromise steps are in [PKI key protection and issuer recovery](operations/pki-key-protection-and-recovery.md).

`npm run certificate-lifecycle:verify` is the T3.10 and Phase 3 completion gate. It runs the repository tests and every PKI implementation gate in a fixed fail-fast sequence. Its additional X.509 scenario accepts the exact active Alpha chain, rejects Beta's otherwise valid issuer under the shared platform root, rejects an untrusted look-alike issuer, rejects an Alpha certificate in Beta context, rotates the key during renewal, denies the superseded predecessor, denies the revoked successor and denies a correctly signed expired certificate before inventory lookup. See [Complete certificate lifecycle verification](architecture/certificate-lifecycle-verification.md).

`npm run mtls-gateway:verify` is the T4.1 boundary gate. It starts a disposable digest-pinned NGINX gateway and a TLS application receiver with generated test-only trust domains. NGINX requires and validates the tenant client chain, overwrites its identity headers and uses a dedicated client certificate while verifying the upstream server. The receiver accepts forwarded identity only from the exact pinned gateway certificate and re-verifies the leaf against the active tenant issuer. The gate rejects a missing client certificate, a platform-root-valid wrong-tenant issuer and an unauthenticated internal connection, then removes its container and private keys. See [mTLS gateway and application identity](architecture/mtls-gateway-identity.md).

`npm run gateway-spoofing:verify` is the T4.2 hostile-route gate. It runs the complete T4.1 path, then supplies a foreign certificate and tenant identity through every recognized and commonly spoofed header. The gate proves NGINX replaces or removes those values, rejects forged headers without a client certificate before proxying, rejects direct access without an internal client certificate before the handler, and rejects an internal-CA-valid non-gateway certificate at the exact gateway pin with the same uniform 401 response. See [mTLS gateway and application identity](architecture/mtls-gateway-identity.md).

`npm run profile-record-api:verify` is the T4.3 protected-read gate. It exercises the Fastify routes against provisioned PostgreSQL state and proves certificate-authenticated profile access, member ownership scope, same-tenant administrator visibility, Alpha/Beta separation, ignored forged identity headers, and uniform denial for invisible record IDs. Every operation binds the trusted tenant and actor inside a transaction before querying under forced RLS. See [Profile and tenant-record API](architecture/profile-tenant-record-api.md).

`npm run role-action-matrix:verify` is the T4.4 authorization-contract gate. It exhaustively checks the tenant-member and tenant-administrator rows for profile read, record read/write, export and administration; derives resource sensitivity from the action; rejects forged tenant contexts and unknown actions; and proves export/administration are non-allowing until their additional policy, bound step-up and audit controls exist. See [Role, action and resource-sensitivity matrix](architecture/role-action-sensitivity-matrix.md).

`npm run evidence-sources:verify` is the T5.2 evidence-source enrollment gate. It proves that only an authoritative tenant administrator can activate a pre-authorized source, that Ed25519 key material and fingerprints are validated, and that rotation, revocation and post-revocation recovery append key epochs without destroying historical verification material. The live PostgreSQL checks roll back their changes. See [Evidence source enrollment and key registry](architecture/evidence-source-key-registry.md).

`npm run evidence-simulators:verify` is the T5.3 deterministic fixture gate. It generates identity, device, behaviour, certificate and compliance envelopes twice, validates the shared contract, recomputes every digest, verifies each Ed25519 signature and confirms tenant separation plus explicit synthetic posture/compliance markers. Use `npm run evidence-simulators:generate -- --tenant alpha` to print a fixture set. See [Deterministic evidence simulators](architecture/deterministic-evidence-simulators.md).

`npm run evidence-ingestion:verify` is the T5.4 ingestion endpoint gate. It proves schema and byte limits precede authoritative lookup, all five fixture types verify against their exact enrolled key, tampering and key substitution fail, the source-authenticated route does not invoke human mTLS identity resolution, and public denials remain bounded. Its rolled-back PostgreSQL check proves exact active tenant/source/key/subject resolution, cross-binding invisibility and revoked-key denial. See [Signed evidence ingestion](architecture/evidence-ingestion.md).

`npm run trust-model:verify` is the T6.1 normalized-component contract gate. It proves that identity, device, behaviour, certificate and compliance use one finite 0–100 higher-is-more-trusted scale; locks the initial 0.20, 0.25, 0.25, 0.15 and 0.15 weights; accepts complete unit-sum tenant-tuned alternatives; and rejects missing, extra, non-finite, out-of-range or non-unit inputs. It does not calculate trust scores. See [Normalized trust components and initial weights](architecture/trust-score-components.md).

`npm run trust-state:verify` is the T6.2 persistence gate. It validates the trust repository adapter, then runs a rolled-back PostgreSQL scenario proving complete five-component snapshots, same-tenant and same-subject accepted-evidence binding, immutable version history, atomic current-pointer advancement, stale-version rejection and denial of direct table access. See [Tenant-scoped trust-state and version storage](architecture/tenant-scoped-trust-state.md).

`npm run trust-score:verify` is the T6.3 deterministic calculation gate. It checks the bounded weighted arithmetic mean against independent hand calculations, both 0–100 boundaries, tenant-tuned weights, exact decimal products, one final half-up rounding step and immutable per-component contribution details. See [Deterministic weighted trust score](architecture/deterministic-weighted-trust-score.md).

`npm run trust-smoothing:verify` is the T6.4 temporal-score gate. It checks configured EWA updates, initialization from the tenant initial score, missing-evidence holds, stale-observation withholding, path-independent exponential decay and the rule that absent evidence cannot improve a below-baseline score. See [Temporal trust smoothing and cold start](architecture/temporal-trust-smoothing.md).

`npm run trust-evidence-consumer:verify` is the T6.5 consumption gate. It verifies the signed accepted-evidence boundary before component normalization, then runs a rolled-back PostgreSQL scenario covering incomplete staging, complete snapshot creation, exact redelivery suppression, older-event withholding, successive subject updates, least-privilege access and cross-tenant denial. Migration `021_validated_evidence_trust_consumption.sql` must be applied first. See [Concurrency-safe validated evidence consumption](architecture/validated-evidence-trust-consumption.md).

`npm run trust-controls:verify` is the T6.6 transition-safety gate. It checks exact low, medium and high boundaries; hysteresis around both band boundaries; immediate deterioration; two-source, two-evaluation recovery; one-band recovery steps; accepted-receipt influence caps; and the closed downward-only critical-evidence overrides. See [Trust transition controls](architecture/trust-transition-controls.md).

`npm run security-action-state-machine:verify` is the T9.1 definition gate. It checks the shared OPA outcome and action-event contracts, exact QUARANTINE obligation mapping, reversible restriction/suspension/renewal blocking, irreversible certificate revocation, replacement-before-recovery ordering, idempotent repeats and fail-closed invalid states. It does not execute or persist actions. See [Security action state machine](architecture/security-action-state-machine.md).

`npm run security-action-rules:verify` is the T9.2 severity and recovery-rule gate. It proves that policy quarantine causes only reversible containment, a score dip alone can never revoke, uncorroborated severe evidence only blocks renewal, two fresh sources and two critical kinds plus a matching critical trust transition are required for revocation, and recovery inherits the T6.6 two-source/two-evaluation thresholds. It defines eligibility only; T9.3 consumes authorized actions and T9.6 applies the separate authorization boundary. See [Security action trigger severity and recovery rules](architecture/security-action-trigger-recovery-rules.md).

`npm run security-recovery:verify` is the T9.6 governed recovery gate. It proves tenant-admin and single-use step-up authorization, current trust and security-state binding, exact replay, fresh distinct replacement issuance, a separately authorized access restoration and permanent revocation of the original target certificate. The database scenario rolls back. Production wiring must provide the active severe-evidence loader and a T3.3 issuance adapter that verifies a new subject key/CSR. See [Governed security recovery and re-enrollment](architecture/governed-security-recovery.md).

`npm run security-action-audit:verify` is the T9.7 action/recovery anchoring gate. It checks the extended event contract and audit verifier, applies migrations, proves automatic immutable request/terminal capture and function-only projector privileges in a rollback-only database scenario, and confirms the two-stage recovery creates four authorization-bound expectations. Run `npm run security-action-audit:projector` with `npm run audit-outbox:worker` in deployed environments: the first process projects ready action events into PostgreSQL's Fabric outbox and the second submits and reconciles them on Fabric. See [Security-action and recovery audit anchoring](architecture/security-action-audit-anchoring.md).

`npm run security-action-adversarial:verify` is the T9.8 integrated safety gate. It tests trust oscillation, one-source compromise, repeated action triggers, certificate-feedback and Redis redelivery, competing recovery authorization and stale recovery state. Migration `040_security_action_conflict_safeguards.sql` makes redundant or stale work visible without allowing an external executor to reapply it. See [Security-action adversarial verification](architecture/security-action-adversarial-verification.md).

`npm run security-action-orchestration:verify` is the T9.3 durable execution gate. It runs the orchestrator unit tests, applies pending migrations and exercises a rollback-only PostgreSQL scenario covering stable action IDs, exact replay, lease ownership, retry state, attempt history and versioned terminal success. Run `npm run infra:migrate` separately when deploying the schema to another environment. See [Idempotent security-action orchestration](architecture/idempotent-security-action-orchestration.md).

`npm run certificate-trust-feedback:verify` is the T9.4 feedback gate. It verifies signed certificate lifecycle events before deriving trust evidence, independently requires the matching published outbox sequence and digest, retains lifecycle causation and a matching successful revocation action, and proves redelivery cannot apply a second trust effect. The evidence and trust callback share one transaction, and every derived lifecycle fact is ineligible to trigger another security action. See [Certificate lifecycle trust feedback](architecture/certificate-lifecycle-trust-feedback.md).

`npm run security-state-invalidation:verify` is the T9.5 invalidation gate. It proves successful suspension or revocation atomically queues one durable invalidation, uses leased function-only retries, atomically removes every registered subject session and security-cache key, preserves neighboring tenant/subject state, suppresses exact Redis replay and records action-to-invalidation delay against a five-second target. Run `npm run infra:migrate` in each other environment before starting an invalidation worker. See [Session and cached security-state invalidation](architecture/security-state-invalidation.md).

`npm run trust-configuration:verify` is the T6.7 versioned-configuration gate. It checks tenant-administrator authority, complete range and weight validation, direct-write denial, serialized version allocation, atomic activation, immutable lifecycle history and rollback by copying historical values into a new active version. Migration `022_versioned_trust_configuration_lifecycle.sql` must be applied first. See [Versioned trust configuration lifecycle](architecture/versioned-trust-configuration.md).

`npm run sensitive-operations:verify` is the T4.5 endpoint gate. It proves tenant members cannot reach export or administration data, tenant administrators can exercise an explicitly authorized verification path, exports are limited and all-or-nothing, Alpha cannot export Beta records or review a Beta subject, caller-supplied tenant controls are rejected, and successful operations receive unique server-generated IDs. The normal repository default remains denial until a trusted internal authorizer is configured. See [Sensitive export and administration demonstration operations](architecture/sensitive-demo-operations.md).

`npm run pki-rbac-baseline:verify` is the T4.6 Baseline B gate. It proves application startup requires the exact branded `pki-rbac-baseline-v1` selection, all ordinary API operations evaluate tenant-scoped certificate identity and the T4.4 role matrix, member/admin resource scopes remain separated across Alpha and Beta, no trust or evidence input is consumed, and caller-selected modes or missing sensitive controls fail closed. See [PKI plus RBAC baseline mode](architecture/pki-rbac-baseline-mode.md).

`npm run request-state:verify` is the T4.7 freshness gate. It reuses one authenticated identity and one PostgreSQL backend while changing current membership, tenant and certificate state between requests. The next request denies suspended membership, suspended tenant and revoked certificate state; the five-second policy permits no cross-request allow cache, and the verifier restores shared seed state and removes disposable certificate rows. See [Per-request certificate and tenant-state revalidation](architecture/request-state-revalidation.md).

`npm run request-outcomes:verify` is the T4.8 request-audit gate. It proves API startup requires the branded fail-closed recorder, server-generated request/correlation IDs override forged headers, authentication and access events retain trusted actor/tenant/action/resource-decision metadata, resource identifiers are hashed, sensitive successes carry their operation ID, and the constrained append-only PostgreSQL writer stores no raw headers, secrets or payloads. Both database scenarios roll back and disposable certificate rows are removed. See [Request outcome and correlation audit](architecture/request-outcome-audit.md).

`npm run request-safeguards:verify` is the T4.9 session, timeout and replay gate. It proves protected requests reject ambient cookie/bearer sessions, responses are not cacheable, bodies and exports remain bounded, PostgreSQL work honors the five-second request deadline, timeout rolls back, identical sensitive retries reuse one server operation ID, conflicting key reuse fails closed, and the runtime role cannot access durable receipt rows directly. The live verifier removes its receipts. See [Session, timeout and replay safeguards](architecture/request-safeguards.md).

`npm run protected-saas:verify` is the T4.10 and Phase 4 completion gate. It runs repository tests, then the gateway, protected-read, authorization-matrix, sensitive-operation, explicit Baseline B, current-state/revocation, request-audit and request-safeguard gates in a fixed fail-fast order. Together they prove allowed actions, role denial, Alpha/Beta separation, current certificate revocation and hostile gateway/direct-bypass denial. Live fixtures are rolled back or removed, and generated gateway keys and containers are deleted. See [Protected SaaS baseline verification](architecture/protected-saas-baseline-verification.md).

PostgreSQL, Redis, NATS and step-ca use separate named volumes. Redis enables append-only persistence and disables eviction. NATS enables JetStream file storage. `npm run runtime-isolation:verify` proves tenant-derived cache and lock keys plus tenant-specific NATS delivery permissions. See [Redis and NATS tenant isolation](architecture/runtime-tenant-isolation.md), [Reliable event delivery](architecture/event-delivery.md) and [Tenant certificate-authority model](architecture/tenant-pki.md).

## Foundation verification

Run `npm run foundation:check` when the normal development stack is running, migrated and provisioned. It validates the host resource budget, Compose configuration, container health, repository tests, the complete Tenant Alpha/Tenant Beta isolation phase gate, the complete Phase 3 certificate-lifecycle gate, the complete Phase 4 protected-SaaS gate, OPA policy, NATS delivery and replay, and the dependency audit.

Run `npm run foundation:clean` to prove a first start from empty service state. The command generates temporary credentials and free loopback ports, creates uniquely named containers, volumes and a network, initializes the CA, applies migrations, runs the complete foundation verification, and then removes those disposable resources. It does not reuse or delete the normal `tenant-trust-*` volumes or `runtime/secrets` files.

The GitHub Actions workflow at `.github/workflows/foundation.yml` runs the isolated clean check after `npm ci`. A local pass verifies the workflow commands and application behavior; the first GitHub run remains the authoritative check of runner permissions, image access and hosted-runner resources.

## Safe shutdown and restart

Stop containers while retaining the database, event stream, CA and cache data with:

```powershell
npm run infra:down
```

Restart the preserved environment with `npm run infra:up`. Reapplying `npm run infra:migrate` is safe because recorded migrations are skipped.

## Deliberate local reset

The following procedure permanently deletes this project's local PostgreSQL, Redis, NATS and step-ca volumes and rotates all generated development credentials. It does not prune Docker or touch another project's resources. Run it only when a complete Tenant Trust reset is intended:

```powershell
docker compose --env-file .env -f infra/compose/compose.yaml down --volumes --remove-orphans
Remove-Item -LiteralPath .\runtime\secrets\step-ca-password.txt -Force
npm run infra:init -- --force
npm run pki:init
npm run infra:up
npm run infra:migrate
npm run demo:provision
npm run foundation:check
```

Delete the step-ca password only in the same reset that deletes `tenant-trust-step-ca-data`; otherwise the remaining encrypted CA key can become unusable. Do not use global Docker prune commands for this project.
