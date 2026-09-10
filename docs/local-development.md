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
npm run infra:up
npm run infra:migrate
npm run infra:check
npm run messaging:verify
```

PostgreSQL listens on `127.0.0.1:55432`, Redis on `127.0.0.1:56379` and NATS on `127.0.0.1:54222`. The non-default ports avoid other local projects, while loopback binding prevents LAN access. Application containers should use the Compose service names `postgres:5432`, `redis:6379` and `nats:4222` on the backend network.

The generated `.env` contains local credentials and is ignored by Git. `.env.example` contains safe placeholders and the digest-pinned images. Rerunning `npm run infra:init` adds newly documented settings without replacing existing secrets. Running it with `--force` rotates credentials, so first stop the stack and remove its volumes only when deliberately resetting all local data.

Migrations are ordered SQL files under `database/migrations`. `npm run infra:migrate` records each successful filename in `platform.schema_migrations` and skips it on later runs. Add a new numbered file for every schema change instead of editing an already-applied migration.

PostgreSQL, Redis and NATS use separate named volumes. Redis enables append-only persistence and disables eviction. NATS enables JetStream file storage. See [Reliable event delivery](architecture/event-delivery.md) for subject, acknowledgement, retry, deduplication and replay rules. Stop containers while retaining data with:

```powershell
npm run infra:down
```

Do not add `-v` unless the intent is to delete the local database and cache contents.
