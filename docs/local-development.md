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

## Next implementation gates

Define the service contracts before starting PostgreSQL and Redis configuration. Exact infrastructure image patches/digests, service ports, health checks, migrations and secrets templates belong to their bootstrap tasks. No Compose stack is available yet.
