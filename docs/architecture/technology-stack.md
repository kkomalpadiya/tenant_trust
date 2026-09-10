# Application stack and local runtime

Decision date: 9 September 2026. This document selects the implementation stack. Dependency and infrastructure integration tests belong to the component bootstrap tasks.

## Application choices

| Component | Selected version or approach | Reason |
| --- | --- | --- |
| Application runtime | Node.js 24 LTS, initial target 24.20.0 | A supported LTS line shared by the API and workers |
| Language | TypeScript 5.9.3, strict type checking, ES modules | Shared contracts and explicit security-state types. Use a stable compiler compatible with the Fabric SDK toolchain. |
| Package management | npm workspaces and a committed package-lock.json when packages are introduced | One dependency workflow without another globally installed package manager |
| API | Fastify 5.12.3 | Request validation, lifecycle hooks and testable enforcement boundaries |
| Dashboard | React 19.2.8 with Vite 8.2.2 | A client-rendered dashboard with a separate protected API |
| Persistence | PostgreSQL 17.11, explicit SQL migrations and node-postgres | Tenant-qualified queries and row-level security remain visible and testable |
| Trust and evidence workers | TypeScript on the application Node runtime | Reuse schemas and deterministic scoring code across workers and tests |
| Policy | OPA 1.x and Rego v1 | Policy versions and decision tests remain separate from application routing |
| Event delivery | NATS 2.x with JetStream | Durable event consumption and replay with idempotent effects |
| Cache | Redis 7.4 line | Short-lived tenant-scoped state and invalidation |
| SaaS PKI | step-ca, one isolated issuing authority boundary per tenant | Certificate issuance and lifecycle management |
| Ledger | Hyperledger Fabric 2.5.16 LTS with LevelDB initially | Permissioned audit commitments without an extra CouchDB service for the initial query needs |
| Fabric client | @hyperledger/fabric-gateway 1.12.1 | Supported Gateway API for application-to-peer interaction |
| Audit chaincode | TypeScript compiled to JavaScript, fabric-contract-api/fabric-shim 2.5.8 | Keep the contract small and use the official Node contract libraries |
| Chaincode runtime | Node.js 22 in the matching Fabric nodeenv 2.5.8 image | The chaincode runtime is versioned separately from the Node 24 application runtime. |
| Verification | Node test runner for pure logic, Fastify injection for routes, OPA tests and Playwright for browser scenarios | Test security boundaries at the relevant layer |

Exact application package targets are recorded in `config/toolchain.json`. Infrastructure tasks must resolve, review and pin exact patches and image digests for Redis, NATS, OPA, step-ca and all Fabric images before starting them. Do not use floating `latest` tags. Recheck targets when a later phase begins rather than assuming this selection guarantees future support.

Fastify follows supported Node LTS lines. Vite accepts the selected Node version. The current Gateway package requires Node >=22.12. Node chaincode 2.5.8 uses a Node 22 runtime, so chaincode code and dependencies must also be tested under that runtime; application Node 24 validation does not establish chaincode compatibility. [Node release policy](https://nodejs.org/en/about/previous-releases), [Fastify support](https://fastify.dev/docs/latest/Reference/LTS/), [Vite prerequisites](https://vite.dev/guide/), [Gateway package metadata](https://www.npmjs.com/package/@hyperledger/fabric-gateway), [chaincode compatibility](https://github.com/hyperledger/fabric-chaincode-node/blob/main/COMPATIBILITY.md)

The PostgreSQL 17 line remains supported, and Fabric 2.5 is the selected LTS line. [PostgreSQL support](https://www.postgresql.org/support/versioning/), [Fabric 2.5 release](https://github.com/hyperledger/fabric/releases/tag/v2.5.16)

## Runtime and process boundaries

Keep the project checkout at its chosen Windows location. Use PowerShell for Git and host development tools, with Docker Desktop running Linux containers on WSL2. Ubuntu 24.04 provides Bash for Fabric scripts. Its Node installation is optional because the pinned Linux container can run Node tools.

Start with the API and one worker process that hosts the evidence, trust, orchestration and audit modules behind explicit contracts. Split workers only when failure isolation or workload measurements justify separate processes. Keep Fabric in a separately started profile. The repository's component directories remain logical ownership boundaries.

Use Docker named volumes for databases, event streams and ledger state. Bind-mount project source when needed, and use a Linux named volume for container node_modules so Windows and Linux native dependencies never share one dependency directory. Keep generated secret files in restricted runtime storage. Do not bind-mount a live database directory from a synchronized Windows folder.

## Resource budget

These are initial engineering budgets, not benchmarked requirements or production sizing.

| Mode | Suggested WSL allocation | Intended use |
| --- | --- | --- |
| Smoke | Existing 2 GB and 4 CPUs | One short-lived Node container and tool verification |
| Core | 4 GB and 4 CPUs | PostgreSQL, Redis, NATS, tenant CA services, OPA and small API/worker workloads |
| Fabric demonstration | Start at 6 GB and 4 CPUs, increase toward 8 GB if measurements require it | Core services plus the small permissioned network and chaincode |

The checker allows a small margin below the configured RAM cap because the engine reports usable memory. It requires 3.5 GiB for core and 5.5 GiB for Fabric. Reserve at least 15 GiB of free physical disk for core and 25 GiB for the Fabric phase, then measure actual growth. A WSL virtual disk's advertised maximum is not available physical disk space.

On a 16 GB class host, preserve room for Windows and the editor. Stop unused project services through their own documented workflow before expanding the workload. Do not change another project's containers, global WSL limits or storage to make this project fit automatically.

## Scope of this decision

No application dependency install or full service network is claimed by this task. The environment checker validates tools, resource thresholds and optionally a pinned Node container with a cryptographic sign/verify operation. Full tenant isolation, policy, PKI and ledger behavior remain separate implementation gates.
