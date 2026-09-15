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
npm run mtls-gateway:verify
npm run gateway-spoofing:verify
npm run profile-record-api:verify
npm run role-action-matrix:verify
npm run sensitive-operations:verify
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

`npm run sensitive-operations:verify` is the T4.5 endpoint gate. It proves tenant members cannot reach export or administration data, tenant administrators can exercise an explicitly authorized verification path, exports are limited and all-or-nothing, Alpha cannot export Beta records or review a Beta subject, caller-supplied tenant controls are rejected, and successful operations receive unique server-generated IDs. The normal repository default remains denial until a trusted internal authorizer is configured. See [Sensitive export and administration demonstration operations](architecture/sensitive-demo-operations.md).

PostgreSQL, Redis, NATS and step-ca use separate named volumes. Redis enables append-only persistence and disables eviction. NATS enables JetStream file storage. `npm run runtime-isolation:verify` proves tenant-derived cache and lock keys plus tenant-specific NATS delivery permissions. See [Redis and NATS tenant isolation](architecture/runtime-tenant-isolation.md), [Reliable event delivery](architecture/event-delivery.md) and [Tenant certificate-authority model](architecture/tenant-pki.md).

## Foundation verification

Run `npm run foundation:check` when the normal development stack is running, migrated and provisioned. It validates the host resource budget, Compose configuration, container health, repository tests including trusted tenant-context resolution and lifecycle revalidation, the complete Tenant Alpha/Tenant Beta isolation phase gate, the complete Phase 3 certificate-lifecycle gate, OPA policy, NATS delivery and replay, and the dependency audit.

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
