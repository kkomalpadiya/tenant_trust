# Local development setup

## Tools

Use Git, Node.js 24.20.0, npm, Docker Desktop with Linux containers, Docker Compose v2 and Ubuntu under WSL2. The tested local Docker baseline is Desktop 4.41.2 / Engine 28.1.1 / Compose 2.35.1 with WSL 2.3.26 and Ubuntu 24.04. Newer supported releases should be verified with the same checks before use.

The application image is `node:24.20.0-bookworm-slim`. `.node-version` records the host target, but it does not install or switch Node by itself. Upgrade host Node to that target before running application dependency installs. The basic checker can run on an earlier Node 24 patch and reports the mismatch explicitly. No host Go installation is needed for the selected TypeScript chaincode.

Keep host npm dependencies and container Linux dependencies separate. Initial npm workspaces and their lockfile will be created when application packages are introduced.

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
npm run test:tenant-context
npm run messaging:verify
npm run runtime-isolation:verify
npm run security-services:verify
npm run foundation:check
```

PostgreSQL listens on `127.0.0.1:55432`, Redis on `127.0.0.1:56379`, NATS on `127.0.0.1:54222`, step-ca on `https://127.0.0.1:59000` and OPA on `127.0.0.1:58181`. The non-default ports avoid other local projects, while loopback binding prevents LAN access. Application containers use the Compose names `postgres:5432`, `redis:6379`, `nats:4222`, `step-ca:9000` and `opa:8181` on the backend network.

The generated `.env` contains local credentials and is ignored by Git. `.env.example` contains safe placeholders and the digest-pinned images. `npm run infra:init` also creates the ignored `runtime/secrets/step-ca-password.txt` file when it is absent. Rerunning the command adds newly documented settings, including the Tenant Alpha and Tenant Beta NATS credentials, without replacing existing secrets. Recreate NATS after adding those settings so its mounted permission configuration is reloaded.

`npm run pki:init` initializes step-ca only when its named volume has no CA configuration. Repeated runs preserve the same CA identity. The `--force` option for `infra:init` rotates environment credentials but deliberately preserves the step-ca password file. CA key-password rotation requires a separate rekey procedure; deleting or replacing the password file alone can make the encrypted intermediate key unusable.

Migrations are ordered SQL files under `database/migrations`. `npm run infra:migrate` records each successful filename in `platform.schema_migrations` and skips it on later runs. Add a new numbered file for every schema change instead of editing an already-applied migration.

Tenant-scoped database code must start a transaction and call `identity.set_tenant_actor_context` with tenant and subject IDs from the resolved trusted context before querying. Forced row-level security then rechecks active membership and roles while limiting identity, resource and security-configuration rows to that actor. `npm run database-isolation:verify` proves tenant isolation and connection reuse. `npm run resource-membership:verify` proves owner-only member access, tenant-wide administrator access, role-change behavior, suspended-membership denial and last-administrator protection. `npm run security-configuration:verify` proves that issuer mappings, evidence sources, trust settings and policy versions remain tenant-owned and administrator-controlled.

`npm run demo:provision` applies every ordered SQL seed under `database/seeds`. It creates the deterministic Tenant Alpha and Tenant Beta subjects, memberships, role assignments, synthetic resources, planned issuer mappings, planned synthetic evidence sources, active trust settings and published policy metadata used by the prototype scenarios. It is safe to rerun and does not reactivate suspended rows or overwrite changed lifecycle versions. It fails when a deterministic identity, ownership or configuration identifier conflicts with different data. `npm run demo:verify` checks the mapping and exercises lifecycle persistence in a transaction that is rolled back.

PostgreSQL, Redis, NATS and step-ca use separate named volumes. Redis enables append-only persistence and disables eviction. NATS enables JetStream file storage. `npm run runtime-isolation:verify` proves tenant-derived cache and lock keys plus tenant-specific NATS delivery permissions. See [Redis and NATS tenant isolation](architecture/runtime-tenant-isolation.md), [Reliable event delivery](architecture/event-delivery.md) and [Tenant certificate-authority model](architecture/tenant-pki.md).

## Foundation verification

Run `npm run foundation:check` when the normal development stack is running, migrated and provisioned. It validates the host resource budget, Compose configuration, container health, repository tests including trusted tenant-context resolution, the tenant identity model, deterministic demo records and security configuration, actor-aware resource, membership and configuration rules, database row-level isolation and connection reuse, Redis key isolation, tenant-specific NATS permissions, OPA policy, NATS delivery and replay, step-ca issuance, and the dependency audit.

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
