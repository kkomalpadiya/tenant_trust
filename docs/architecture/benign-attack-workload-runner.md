# Benign and attack workload runner

T10.6 implements the executable runner for `tenant-trust-evaluation-protocol-v1`. It turns the ten pre-registered scenarios into ordered steps, schedules the three comparison modes with the fixed load and repetition plan, and records one raw observation for every executed step and concurrent lane. This task validates orchestration only; it does not publish security or performance measurements.

## Scenario replay catalog

The runner covers the complete protocol and makes the required T10.6 stimuli explicit:

| Scenario | Ordered replay |
| --- | --- |
| Normal legitimate access | Authorize an ordinary tenant-scoped request. |
| Unknown device and sensitive export | Ingest the device change, then attempt the export. |
| Failed logins and sensitive export | Ingest failed-login behaviour, then attempt the export. |
| Certificate and evidence replay | Accept a valid item, submit forged evidence, replay evidence and reuse an invalid certificate. |
| Cross-tenant access | Attempt foreign-tenant access and check that access precedes no data disclosure or foreign state change. |
| Evidence flooding | Submit a source flood and observe influence and tenant-capacity controls. |
| Policy version change | Change the active version, then attempt a stale-version decision. |
| Off-chain audit modification | Modify an audit record, then verify the causal chain. |
| Fabric outage and recovery | Stop ledger delivery, authorize on the off-critical path, restore delivery and reconcile pending commitments. |
| Corroborated revocation | Submit corroborated critical evidence, then reuse the revoked certificate. |

Each comparison mode is supplied through an `executeStep` adapter. The adapter boundary lets Baseline A, Baseline B and the proposed framework use the same schedule and fixtures while keeping their authentication and authorization implementations separate. Missing adapters fail setup; the runner never silently omits a mode.

## Deterministic scheduling

The default `full` plan is derived directly from the pre-registration: ten scenarios, three modes, concurrency 1/8/32, five warm-ups and thirty measured repetitions. That produces 450 warm-up and 2,700 measured scenario runs. Seeds are shared across modes for the same scenario, load and repetition, and the registered mode-order rotation is applied before each ten-scenario block.

The `verification` profile runs each scenario once at concurrency one through all three adapters. Its records are labelled `runner-verification-only` and cannot be mistaken for protocol evaluation results. It exists so the orchestration gate remains fast and deterministic.

## Observation contract and failure handling

Every raw observation binds the protocol, runner and sealed configuration hash to the mode, scenario, traffic class, load, repetition, seed, concurrent lane and ordered step. It also records the observed outcome, stable reason, access classification, expected/observed/missing controls and monotonic duration.

Adapter exceptions, malformed responses and timeouts become explicit `error` or `timeout` observations. Unsupported behavior must be returned as `unsupported`. These rows stay in the result so later measurement tasks can apply the pre-registered failure-preserving denominators; the runner does not discard them or invent successful defaults.

Run the focused gate with:

```text
npm run workload-runner:verify
```
