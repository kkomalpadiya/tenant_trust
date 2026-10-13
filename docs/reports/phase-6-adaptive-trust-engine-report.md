# Phase 6 Adaptive Trust Engine: Detailed Implementation Report

## 1. Purpose of this report

Phase 6 built and verified the adaptive trust engine for the Tenant Trust prototype. This report explains what was implemented, how the complete processing flow works, why each algorithm was selected, why alternative approaches were not used at this stage, how tenant isolation and failure handling are enforced, and why the project uses its selected technology stack.

The report uses everyday language wherever possible. Technical terms are introduced only when they help explain an important design or security decision.

Phase 6 is complete. Its algorithms are deterministic and thoroughly tested, but the initial weights and thresholds remain **unvalidated prototype defaults**. Passing the test suite proves that the software follows the documented rules. It does not prove that those rules are statistically optimal for real tenants.

## 2. Executive summary

The trust engine turns five kinds of already-validated security evidence into a current, explainable trust state for one subject inside one tenant.

The five trust components are:

1. identity assurance;
2. device posture;
3. behaviour risk;
4. certificate status; and
5. compliance posture.

Each component uses a common scale from 0 to 100, where a higher value means a more trusted posture. The engine then:

1. verifies that all five components are present and correctly scoped;
2. calculates a weighted score;
3. smooths short-term changes over time;
4. handles missing or stale information conservatively;
5. limits how much one evidence source can change the score;
6. uses hysteresis and corroborated recovery to prevent rapid band switching;
7. records every durable state and its evidence references;
8. creates a complete, hash-linked explanation for every transition; and
9. exposes only a fresh, actor-bound score to future policy consumers.

The trust score is deliberately **not** an authorization result. A high score cannot make an invalid certificate valid, restore a revoked certificate, create tenant membership, or permit cross-tenant access. Phase 7 will combine fresh trust information with identity, role, resource, action and request context in OPA policy decisions.

## 3. End-to-end flow in common terms

```text
Signed evidence accepted by Phase 5
                |
                v
Convert each evidence type to a normalized 0-100 component
                |
                v
Wait until all five components are available
                |
                v
Calculate a deterministic weighted score
                |
                v
Apply time smoothing, freshness and conservative decay
                |
                v
Apply source limits, hysteresis, recovery and critical rules
                |
                v
Store an immutable tenant/subject state version
                |
                v
Store a complete explanation and trust.updated.v1 event
                |
                v
Expose the score only while it is fresh
                |
                v
Future Phase 7 policy decision
```

In simpler terms, the engine does not react blindly to one new signal. It checks where the signal came from, combines it with the other required signals, limits its influence, considers recent history, records why the result changed, and refuses to present old or missing state as current policy input.

## 4. Design principles used throughout Phase 6

### 4.1 Deterministic behavior

The same inputs, configuration and timestamps always produce the same result. This makes the score reproducible during tests, audits and incident investigation.

### 4.2 Complete evidence rather than partial guesses

A durable score snapshot requires all five components. Missing evidence is not silently replaced with zero, the initial score or an assumed healthy value. This prevents a partial picture from looking complete.

### 4.3 Tenant and subject binding

Every state, evidence reference, configuration and lookup is bound to the authenticated tenant and subject. Callers cannot choose another tenant or subject by placing an identifier in a request.

### 4.4 Fail-closed behavior

Invalid, missing, inconsistent or stale state is not treated as permission. When the system cannot provide a current trustworthy score, the policy-facing result requires denial.

### 4.5 Immutable history

Historical state, configuration and explanation rows are append-only. New versions are added instead of silently rewriting the past.

### 4.6 Trust is an input, not authority

The score describes security posture. It does not replace certificate validation, tenant membership, role checks, resource ownership or policy evaluation.

### 4.7 Explainability before sophistication

The prototype uses explicit mathematical and state-transition rules that reviewers can calculate by hand. More complex statistical or machine-learning techniques are deferred until suitable labelled evaluation data exists.

## 5. Work completed in each Phase 6 task

| Task | Main result |
| --- | --- |
| T6.1 | Defined five normalized trust components and initial weights. |
| T6.2 | Added tenant-scoped, append-only trust-state versions with exact evidence references. |
| T6.3 | Implemented deterministic weighted-score calculation with exact decimal handling. |
| T6.4 | Added exponentially weighted smoothing, cold start, freshness and conservative decay. |
| T6.5 | Added consume-once processing of validated evidence with ordering and concurrency protection. |
| T6.6 | Added hysteresis, bounded source influence, corroborated recovery and critical negative overrides. |
| T6.7 | Added an administrator-only, immutable, versioned configuration lifecycle. |
| T6.8 | Added canonical transition explanations, hashes and contract-valid trust events. |
| T6.9 | Added a context-bound score lookup that withholds stale state from policy use. |
| T6.10 | Added deterministic calibration fixtures and the complete Phase 6 verification gate. |

### 5.1 T6.1: normalized components and initial weights

The engine accepts exactly five component values. Each value must be a finite number from 0 through 100.

| Component | Meaning | Initial weight |
| --- | --- | ---: |
| Identity | Strength and current validity of the subject's identity state | 0.20 |
| Device | Security posture and risk of the device | 0.25 |
| Behaviour | Risk indicated by observed activity | 0.25 |
| Certificate | Current certificate lifecycle and status posture | 0.15 |
| Compliance | Current control and compliance posture | 0.15 |

The weights total exactly 1.00. They are stored as immutable model version `1.0.0` defaults. A tenant may later create a new configuration and model version, but historical calculations keep the exact version that produced them.

Why a common 0-100 scale was used:

- it makes different evidence types comparable;
- it gives every calculation a clear minimum and maximum;
- it is easy to display and explain;
- it prevents one component from using an accidental larger numeric range; and
- it supports tenant-specific weights without changing the meaning of the component scale.

The scale is not a probability. A score of 80 does not mean there is an 80% chance that the subject is safe.

### 5.2 T6.2: tenant-scoped versioned state storage

The database stores three related forms of state:

- a complete immutable snapshot of the five components and its versions;
- one accepted evidence reference for each component; and
- a small pointer to the current snapshot.

The database writes these items atomically. “Atomically” means either the whole update succeeds or none of it is retained. A system failure cannot leave a new current pointer referring to an incomplete state.

Every update supplies the version it expects to replace. If another worker has already advanced the state, the stale writer is rejected instead of silently overwriting newer information. This is optimistic concurrency control.

The state writer also verifies that:

- the tenant, subject and membership are active;
- the configuration belongs to the same tenant;
- the model version matches the configuration;
- each evidence item belongs to the same tenant and subject;
- each evidence item matches the expected component type; and
- all component values remain within 0-100.

Direct application access to the underlying trust tables is denied. Runtime services can call only narrow database functions designed for their exact operation.

### 5.3 T6.3: deterministic weighted score

The initial aggregate score uses a weighted arithmetic mean:

```text
score = identity x 0.20
      + device x 0.25
      + behaviour x 0.25
      + certificate x 0.15
      + compliance x 0.15
```

For example, using component values of identity 100, device 80, behaviour 60, certificate 40 and compliance 20:

```text
100 x 0.20 = 20
 80 x 0.25 = 20
 60 x 0.25 = 15
 40 x 0.15 =  6
 20 x 0.15 =  3
-----------------
Weighted score = 64
```

JavaScript normally stores decimals as binary floating-point numbers, which can produce tiny intermediate differences. The implementation therefore converts decimal values into integer-and-scale pairs for multiplication and addition. It displays component contributions to six decimal places and rounds the final score once to two decimal places using half-up rounding.

This avoids a situation where displayed rounded contributions are added together and accidentally produce a different final score.

### 5.4 T6.4: temporal smoothing, cold start and decay

Security signals can change briefly because of network conditions, delayed reporting or one unusual action. Reacting fully to every single observation would make the score unstable. The engine therefore uses an exponentially weighted average:

```text
new score = alpha x new observation
          + (1 - alpha) x previous score
```

`alpha` controls responsiveness. A larger alpha follows the new observation more closely. A smaller alpha gives more weight to the previous score.

Example with an alpha of 0.30, a previous score of 60 and a new observation score of 80:

```text
new score = 0.30 x 80 + 0.70 x 60
          = 24 + 42
          = 66
```

Cold start uses the configured initial score as the prior score. This prevents the very first observation from defining the entire trust state unless the tenant explicitly configures alpha as 1.

Freshness is inclusive: an observation whose age is exactly equal to `stale_after_seconds` is still fresh. An older observation is stale and is not applied.

When no new observation is available:

- the last score is held while the last complete observation is still fresh;
- after the freshness window expires, the score decays toward a conservative baseline; and
- missing or stale evidence can never improve a below-baseline score.

The decay is exponential:

```text
decayed score = baseline
              + (anchor score - baseline)
              x 2 ^ (-elapsed beyond stale / stale interval)
```

The stale interval is also the decay half-life. If the anchor is 80, the baseline is 60 and exactly one half-life has passed beyond the freshness window, the result is 70: half of the original 20-point distance remains.

The calculation retains the original anchor score. Rechecking the score more frequently does not cause extra decay, so the result depends on elapsed time rather than polling frequency.

### 5.5 T6.5: safe consumption of validated evidence

Phase 5 publishes an authenticated `evidence.accepted.v1` event containing metadata rather than raw evidence. The trust consumer verifies the signed event before retrieving or normalizing the protected evidence.

For every accepted component update, the database:

1. binds the delivery to the exact accepted evidence record;
2. obtains the tenant, subject, source and evidence type from authoritative storage;
3. takes a short transaction lock for that tenant and subject;
4. records a durable consume-once receipt;
5. stages the component only if it is newer than the stored component; and
6. creates a new complete trust-state version only when all five components are available.

The ordering tuple uses observation time, JetStream sequence and delivery event ID. Older deliveries can be acknowledged as superseded but cannot move state backward.

Redelivery is safe. The consume-once receipt and the state effect commit in the same transaction. A repeated message returns `duplicate` and performs no second update. If the transaction fails, neither the receipt nor the partial effect remains, so the event can be retried.

### 5.6 T6.6: transition controls

The smoothed numeric score is converted into low, medium or high internal trust bands.

| Band | Base score interval | Deteriorates when | Recovers when |
| --- | ---: | ---: | ---: |
| Low | 0 to below 40 | Not applicable | Score is at least 45 |
| Medium | 40 to below 70 | Score falls below 35 | Score is at least 75 |
| High | 70 through 100 | Score falls below 65 | Not applicable |

The recovery and deterioration thresholds are intentionally different. This gap is called hysteresis. It stops a score near 40 or 70 from switching bands repeatedly after very small changes.

Deterioration is immediate because delaying a credible negative change would preserve access under an outdated posture. Recovery is deliberately slower:

- at least two distinct sources must support the recovery;
- two consecutive evaluations must qualify; and
- one evaluation can advance at most one band.

These rules make it harder for one noisy or compromised source to farm a rapid increase.

Ordinary evidence also has a maximum influence:

```text
maximum score movement = effective source influence x 100
```

If the effective influence is 0.10, that evidence can move the score by no more than ten points in either direction. The effective value is the lower of the source-specific limit and tenant-wide limit recorded when the evidence was accepted.

Critical negative evidence uses a small closed rule set. Identity compromise, device compromise, an account-takeover pattern, certificate revocation or a blocking compliance breach may bypass the ordinary influence cap only to reduce trust. Callers cannot invent new overrides or use an override to increase trust.

### 5.7 T6.7: versioned configuration lifecycle

Trust settings are security-sensitive. The application cannot update configuration rows directly.

An active tenant administrator can:

- create a validated draft;
- activate a draft;
- inspect configuration history; and
- roll back by copying an older configuration into a new version.

Rollback does not rewrite history or reactivate an old row. It creates a new active version containing the selected historical values. This preserves a complete record of what was active, who changed it and what target they selected.

Tenant-scoped transaction locks prevent two administrators from allocating the same version or leaving two active configurations.

### 5.8 T6.8: durable explanations and events

Every durable score transition receives a complete explanation containing:

- prior and new score, band and recovery state;
- all five component values;
- the five weights and weighted contributions;
- accepted evidence and source-event references;
- weighted-score and smoothing details;
- source influence, hysteresis and recovery details;
- any critical override;
- model and configuration versions; and
- observation, evaluation and recording times.

The explanation is serialized using a sorted-key canonical JSON profile. The canonical bytes are hashed with SHA-256. The exact canonical text is retained, allowing a later verifier to recompute the digest from the stored bytes.

The same operation builds a contract-valid `trust.updated.v1` event containing the transition identity, previous and new transport bands, versions, evidence IDs and explanation hash.

PostgreSQL checks all component, configuration, evidence, ordering and hash bindings before it atomically stores the transition, its five contributions, event and current pointer. An identical retry is idempotent. A retry with different content is rejected.

### 5.9 T6.9: freshness-aware internal lookup

Policy consumers do not read trust tables directly. They call a zero-argument database function after the application has bound the authenticated tenant and subject to the current transaction.

PostgreSQL uses its own statement time to calculate score age. This prevents a caller from supplying a false clock value.

The lookup has three possible results:

| State | Policy score | Last-known score | Can policy use it? | Required behavior |
| --- | --- | --- | --- | --- |
| Fresh | Present | Present | Yes | Continue to policy evaluation |
| Stale | Withheld | Available for audit only | No | Deny with `TRUST_STATE_STALE` |
| Missing | Absent | Absent | No | Deny with `TRUST_STATE_MISSING` |

Withholding the stale value from the `policyScore` field is intentional. It is safer than returning an old score with a separate warning that a later caller might ignore.

Fresh and stale results also identify the exact transition, update version, model version, configuration version, age, freshness limit, timestamps and explanation hash.

### 5.10 T6.10: calibration fixtures and the Phase 6 gate

The final task added a versioned fixture catalog covering:

- normalized score minimum and maximum;
- an independent weighted-score example;
- the exact freshness boundary;
- missing-signal holding;
- stale-signal withholding and decay;
- band boundaries;
- two-source, two-evaluation recovery;
- duplicate event, nonce and sequence replay;
- bounded flooding and automatic source suspension; and
- tenant-isolated replay and flood state.

The catalog contains machine-checked labels declaring that it is deterministic regression data and not an effectiveness claim.

The `npm run trust-engine:verify` gate runs the complete repository suite and then verifies the entire Phase 6 chain against PostgreSQL. At completion, all 305 repository tests and every Phase 6 database scenario passed. Database scenarios use transactions and roll back their synthetic changes.

## 6. Why these algorithms were selected

### 6.1 Weighted arithmetic mean

**Selected approach:** a weighted arithmetic mean over five normalized components.

**Why it fits this prototype:**

- Every contribution is visible and can be calculated by hand.
- The output remains inside 0-100 when inputs are in 0-100 and weights total one.
- Tenant-specific importance can be expressed through versioned weights.
- It is deterministic, fast and easy to test.
- It produces contribution details suitable for explanations and audit.

**Why not an unweighted average:** an unweighted average assumes all evidence types have equal importance. The project design intentionally gives device and behaviour more initial influence than certificate and compliance posture.

**Why not a geometric mean:** a geometric mean strongly penalizes a single low component and behaves awkwardly around zero. That may be useful for some risk models, but it would make the initial prototype harder to interpret and would embed a “weakest component dominates” policy without evaluation evidence.

**Why not minimum/maximum rules:** using only the weakest or strongest component discards most of the evidence and creates abrupt score changes. Critical conditions are handled more explicitly through closed negative override rules.

**Why not a machine-learning model:** no sufficiently representative labelled dataset exists yet. A learned model would risk hidden bias, unstable retraining behavior and explanations that are difficult to reproduce. The deterministic score provides a safe baseline for the later evaluation phase.

### 6.2 Exponentially weighted average

**Selected approach:** exponential smoothing using the tenant's configured alpha.

**Why it fits this prototype:**

- Recent observations matter more than older ones.
- Only the previous score is needed, so memory and storage remain bounded.
- The responsiveness is controlled by one understandable parameter.
- The result is deterministic and easy to reproduce.
- It avoids a single observation fully replacing the previous state.

**Why not a simple moving average:** a moving average requires storing or reconstructing a fixed window, treats all observations in that window equally and changes abruptly when an old sample leaves the window.

**Why not “last observation wins”:** this would be highly sensitive to noise and a single compromised source.

**Why not a Kalman filter:** a Kalman filter is valuable when measurement and process-noise models are known. Those distributions have not been measured for this prototype, so its additional complexity would create unjustified assumptions.

**Why not a recurrent or time-series machine-learning model:** it would need representative sequences, labels, drift monitoring and explainability controls that are not available in Phase 6.

### 6.3 Exponential stale-state decay

**Selected approach:** decay toward a conservative baseline using the freshness interval as a half-life.

**Why it fits this prototype:**

- It reduces confidence smoothly as evidence ages.
- A half-life has an understandable meaning.
- The retained anchor makes the result independent of polling frequency.
- It avoids treating old positive evidence as permanently current.
- It never improves a score that was already below the baseline.

**Why not a hard expiry to zero:** an immediate drop can create an unnecessary cliff caused by a short reporting delay. The separate policy lookup already denies stale state, while decay preserves an explainable internal trajectory.

**Why not linear decay:** linear decay requires an arbitrary end point and creates a sudden behavior change when it reaches that point. Exponential decay is smooth and naturally expresses decreasing confidence over time.

**Why not keep the last score indefinitely:** this could allow an old high score to survive long after its supporting evidence stopped arriving.

### 6.4 Hysteresis state machine

**Selected approach:** separate thresholds for deterioration and recovery.

**Why it fits this prototype:**

- It prevents band flapping near 40 and 70.
- It allows negative changes to take effect quickly.
- It makes recovery deliberately more cautious.
- Every transition has a clear, auditable reason.

**Why not direct band mapping on every score:** a score moving between 69.99 and 70.00 could repeatedly change the band and trigger unstable downstream behavior.

**Why not time-only cooldowns:** a cooldown reduces repeated actions but does not prove that recovery is supported by independent current evidence.

### 6.5 Corroborated, consecutive recovery

**Selected approach:** two distinct sources and two consecutive qualifying evaluations, advancing only one band.

**Why it fits this prototype:** it prevents one source from repeatedly submitting favorable evidence and immediately restoring a subject from low to high trust.

**Why not immediate recovery:** immediate recovery would make a short burst of favorable data as influential as a serious negative event.

**Why not require unanimous sources:** unanimous agreement would reduce availability and could allow one unavailable source to block recovery indefinitely.

The selected counts are prototype defaults and require later calibration.

### 6.6 Bounded source influence

**Selected approach:** cap the absolute score movement caused by ordinary evidence using the lower of tenant and source limits.

**Why it fits this prototype:** one noisy, faulty or compromised source cannot dominate the aggregate in one step. The cap used for scoring is snapshotted when evidence is accepted, so later configuration changes do not rewrite what the accepted evidence was allowed to influence.

**Why not trust every enrolled source equally:** enrollment proves that the source is recognized, not that every statement is accurate.

**Why not allow unlimited negative changes:** ordinary source errors could create denial-of-service effects. Closed critical rules provide a safer, explicit path for exceptional negative evidence.

### 6.7 Closed downward-only critical overrides

**Selected approach:** a small fixed list of serious negative conditions may bypass the ordinary cap only to reduce trust.

**Why it fits this prototype:** certificate revocation and credible compromise indicators should not take many ordinary updates to affect posture. A fixed list prevents request data from inventing a new override or score ceiling.

**Why not a generic administrator override:** broad manual score controls would weaken reproducibility, allow privilege misuse and make explanations less trustworthy.

**Why not positive overrides:** a special path that increases trust could bypass normal corroboration and be used to rescue unsafe state.

### 6.8 Optimistic versioning plus per-subject locks

**Selected approach:** expected-version checks protect ordinary writes, while short transaction-scoped advisory locks serialize evidence updates for one tenant and subject.

**Why it fits this prototype:** it prevents lost updates without locking unrelated subjects. Two updates for the same subject are processed in order, while updates for different subjects can proceed independently.

**Why not last-write-wins:** a slower old worker could overwrite newer state.

**Why not one global lock:** it would preserve correctness but unnecessarily serialize every tenant and subject, reducing throughput.

### 6.9 Durable idempotency and replay protection

**Selected approach:** event identities, source sequences, nonces, stream sequence and consume-once receipts are recorded with the state-changing effect.

**Why it fits this prototype:** message brokers can redeliver after timeouts or restarts. Exactly-once network delivery cannot be assumed, so the consumer makes repeated delivery have one durable effect.

**Why not rely only on broker acknowledgements:** a process can crash after committing the database change but before acknowledging the message. Without a durable receipt, redelivery could apply the effect twice.

### 6.10 Canonical JSON and SHA-256

**Selected approach:** stable sorted-key serialization followed by SHA-256 hashing.

**Why it fits this prototype:** ordinary JSON objects can be serialized with different key orders while representing the same data. Canonical serialization creates one byte representation, and the hash provides a compact integrity link for events and later audit commitments.

**Why not hash ordinary `JSON.stringify` output:** object construction order could change the digest without changing the logical explanation.

**Why not store only the hash:** retaining the canonical explanation bytes allows independent recomputation and human inspection.

### 6.11 Fresh-score withholding

**Selected approach:** stale state is returned for audit as `lastKnownScore`, but the policy-facing score field is null.

**Why it fits this prototype:** it makes accidental use of stale state harder. A consumer must explicitly receive a fresh score before continuing.

**Why not return the old score with a warning:** warnings are easy to ignore, especially when different consumers are added later.

## 7. Technology stack and why it was chosen

### 7.1 Phase 6 implementation stack

| Technology | Role in Phase 6 | Why selected |
| --- | --- | --- |
| Node.js 24 LTS | Runs trust logic, workers, scripts and tests | One supported runtime across the API and workers; strong standard library; fast deterministic test execution. |
| ES modules (`.mjs`) | Current executable module format | Native Node module loading, explicit imports and no transpilation requirement for the implemented prototype logic. |
| TypeScript 5.9.3 target | Selected project language for typed application boundaries | Strict types are useful for security-state contracts as the application grows. Current Phase 6 modules are executable ES modules, while the wider stack retains TypeScript as the application target. |
| npm workspaces | Organizes packages and services | One dependency and script workflow for contracts, evidence, trust and application packages. |
| PostgreSQL 17.11 | Durable trust state, configuration, receipts and explanations | Strong transactions, row-level security, constraints, locking, append-only enforcement and explicit SQL that can be independently reviewed. |
| node-postgres | Node-to-PostgreSQL adapter | Mature parameterized-query support and direct transaction control without hiding security-critical SQL behind a large ORM. |
| Node built-in test runner | Unit and integration tests | Dependency-light, fast, works directly with ES modules and supports deterministic test isolation. |
| JSON and JSON Schema | Versioned event and fixture formats | Human-readable, language-neutral and suitable for strict closed schemas. |
| Ajv | Runtime JSON Schema validation | Compiles and enforces shared event contracts before events cross service boundaries. |
| SHA-256 | Explanation and event integrity digests | Widely supported, deterministic and suitable for compact audit commitments; it is used for integrity, not password storage. |
| Docker Compose on WSL2 | Local PostgreSQL and supporting services | Reproducible Linux services on the Windows development host without requiring every database or broker tool to be installed globally. |
| NATS JetStream boundary | Durable accepted-evidence delivery | Supports explicit acknowledgement, redelivery and durable consumers; the trust consumer is designed around idempotent effects rather than assuming perfect delivery. |

### 7.2 Why PostgreSQL was preferred over alternatives

PostgreSQL was chosen over a document database for the trust system because the important relationships are strict: tenant, subject, evidence, component, configuration, version and transition must all agree. Foreign keys, check constraints, transactions and row-level security express these relationships directly.

It was chosen over an in-memory-only store because trust history, replay receipts and configuration lineage must survive restarts.

Redis remains useful for short-lived cache data, but it is not the durable authority for trust state. A cache miss or stale cache cannot safely decide access.

An ORM was not placed over the critical storage functions because explicit SQL makes privilege boundaries, locks, row-level security and atomic operations easier to inspect and test.

### 7.3 Why Node.js was preferred for trust workers

The rest of the application and event contracts already use the Node ecosystem. Reusing the runtime avoids maintaining the same schemas and identifiers across another language boundary. Node also provides sufficient performance for the prototype's small deterministic calculations, while PostgreSQL performs the durable coordination work.

Python would be a natural option for later data analysis or model calibration, but the runtime scoring algorithm does not currently require scientific-computing libraries. Introducing Python into the online decision path would add deployment and contract complexity without improving the present deterministic model.

Java or Go could provide strong service-runtime options, but using them would split the application stack and duplicate model/event definitions for no demonstrated prototype benefit.

### 7.4 Wider project stack and how Phase 6 fits

| Technology | Project role | Reason for selection | Phase 6 relationship |
| --- | --- | --- | --- |
| Fastify 5.12.3 | Protected HTTP API | Schema validation, lifecycle hooks and injection-based tests | Later APIs will obtain current trust through the T6.9 lookup. |
| NGINX 1.31.3 | Client-mTLS gateway | Mature certificate verification and controlled identity forwarding | Trust cannot override the identity established at this boundary. |
| React 19.2.8 and Vite 8.2.2 | Dashboard | Modern component UI and fast development tooling | Future views can display score history and explanations through protected APIs. |
| Redis 7.4 line | Short-lived cache | Efficient tenant-scoped ephemeral state | It may cache derived state, but PostgreSQL remains authoritative. |
| NATS 2.14.6 with JetStream | Durable events | Explicit acknowledgement, replay and persistent streams | Carries accepted evidence into the trust-processing boundary. |
| step-ca 0.30.2 | Tenant certificate authorities | Automated certificate lifecycle with isolated tenant issuer boundaries | Certificate validity remains a prerequisite independent of trust score. |
| OPA 1.20.2 and Rego v1 | Authorization policy | Keeps versioned policy decisions separate from application routing | Phase 7 will combine identity, role, action, resource, context and fresh trust. |
| Hyperledger Fabric 2.5.16 LTS | Permissioned audit commitments | Multi-organization, verifiable audit records | Later phases can commit hashes of selected trust events while raw evidence stays off-chain. |

### 7.5 Why OPA is separate from the trust engine

The trust engine answers, “What is the subject's current security posture, and how was it calculated?” OPA will answer, “Given this identity, role, resource, action, context and trust state, what outcome is allowed?”

Keeping those responsibilities separate prevents a numeric score or band from becoming an implicit permission system. It also allows policy changes to be versioned and tested without changing score history.

### 7.6 Why Hyperledger Fabric is not the live trust database

Fabric is intended for selected audit commitments, not per-request score calculation. PostgreSQL provides lower-latency transactional reads and writes for the application. Fabric can later prove that approved commitment bytes were recorded under the network's endorsement rules, while detailed evidence and explanations remain off-chain.

## 8. Security and tenant-isolation controls

### 8.1 Trusted context instead of caller-selected scope

Services require a branded tenant context resolved from authenticated identity and current authority state. The score lookup accepts no tenant or subject arguments. It reads the transaction-bound actor.

### 8.2 Least-privilege database roles

Application and trust-engine roles do not receive broad table access. They execute narrow security-definer functions with validated parameters and controlled search paths.

### 8.3 Forced row-level security

Tenant-owned tables use forced row-level security where applicable. Database checks remain active even if application code accidentally constructs a broad query.

### 8.4 Exact evidence binding

Every component links to accepted evidence for the same tenant, subject and evidence type. An identifier from another tenant cannot be substituted.

### 8.5 Conservative failure decisions

| Failure | Engine behavior |
| --- | --- |
| Missing component | Do not create a partial durable score. |
| Invalid score/configuration | Reject before persistence. |
| Older evidence | Record or acknowledge as superseded; do not roll state backward. |
| Duplicate delivery | Return duplicate with no second effect. |
| Stale policy lookup | Withhold policy score and require denial. |
| Missing policy lookup | Return no score or versions and require denial. |
| Cross-tenant result | Reject as invalid. |
| Database transaction failure | Roll back the effect and leave the event retryable. |

## 9. Verification completed

The final Phase 6 gate is:

```powershell
npm run trust-engine:verify
```

It covers:

- normalized component and model validation;
- weighted-score arithmetic and rounding;
- smoothing, cold start, missing state, staleness and decay;
- transition boundaries, hysteresis and recovery;
- critical negative rules;
- replay, ordering and flood controls;
- source influence limits;
- tenant-scoped state and version storage;
- configuration authorization and immutable history;
- validated evidence consumption and idempotency;
- canonical explanations and event schema validation;
- fresh, stale and missing score lookup; and
- cross-tenant and least-privilege database behavior.

The completion run passed all 305 repository tests. Live PostgreSQL verification used synthetic scenarios inside transactions and rolled them back after each gate.

The Phase 6 commits were:

| Task | Commit | Summary |
| --- | --- | --- |
| T6.1 | `e1fb43a` | Define normalized components and initial weights |
| T6.2 | `13a37f8` | Add tenant-scoped versioned trust-state storage |
| T6.3 | `4502ce7` | Add deterministic weighted-score calculation |
| T6.4 | `45309d6` | Add temporal smoothing and cold-start policy |
| T6.5 | `9b21665` | Consume validated evidence safely |
| T6.6 | `353e37c` | Add hysteresis and source-influence controls |
| T6.7 | `66e1b7b` | Add versioned configuration lifecycle |
| T6.8 | `f43d766` | Add durable transition explanations |
| T6.9 | `3b27a38` | Add freshness-aware score lookup |
| T6.10 | `f0eec8c` | Verify the adaptive trust engine |

## 10. Important limitations and remaining work

### 10.1 The defaults are not calibrated

The weights, alpha values, freshness windows, influence limits and band thresholds are design defaults. Real calibration requires representative labelled data and measurements of false allows, false restrictions, detection delay and recovery behavior.

### 10.2 Raw-claim normalization remains a trusted boundary

Phase 6 defines what a valid normalized component looks like, but evidence-type-specific logic must still explain how raw device, behaviour, identity, certificate or compliance claims become a 0-100 component.

### 10.3 Final authorization is Phase 7

The trust engine does not yet produce `ALLOW`, `STEP_UP`, `DENY` or `QUARANTINE`. OPA policy must combine fresh trust with identity, membership, role, action, resource and request context.

### 10.4 Production performance is not established

The phase verifies correctness on the local prototype. It does not establish production throughput, high availability, multi-region behavior or service-level objectives.

### 10.5 Model accuracy and fairness are not established

Deterministic behavior is not the same as accurate risk prediction. Later evaluation must examine whether evidence definitions, weights and thresholds produce acceptable outcomes across relevant subjects and tenant conditions.

### 10.6 The event is prepared, not yet a complete audit-ledger workflow

Phase 6 creates and stores a canonical `trust.updated.v1` event. Later phases still need selected event delivery, Fabric commitment, reconciliation and user-facing audit views.

## 11. Practical operating notes

Before running the full Phase 6 gate in another environment:

```powershell
npm run infra:up
npm run infra:migrate
npm run demo:provision
npm run trust-engine:verify
```

Migrations through `024_internal_trust_score_lookup.sql` must be applied. The gate intentionally stops on the first failed boundary. Individual trust verification commands remain available for diagnosis.

## 12. Key implementation locations

- Trust model contract: [`packages/trust-model`](../../packages/trust-model/)
- Trust service: [`services/trust`](../../services/trust/)
- Trust migrations 020-024: [`database/migrations`](../../database/migrations/)
- Database verification: [`database/tests`](../../database/tests/)
- Phase 6 verification runner: [`scripts/verify-trust-engine-phase.mjs`](../../scripts/verify-trust-engine-phase.mjs)
- Calibration fixtures: [`test/fixtures/trust-engine-calibration-v1.json`](../../test/fixtures/trust-engine-calibration-v1.json)
- Calibration tests: [`test/trust-engine-calibration.test.mjs`](../../test/trust-engine-calibration.test.mjs)

## 13. Related design documents

- [Normalized trust components and initial weights](../architecture/trust-score-components.md)
- [Tenant-scoped trust-state and version storage](../architecture/tenant-scoped-trust-state.md)
- [Deterministic weighted trust score](../architecture/deterministic-weighted-trust-score.md)
- [Temporal trust smoothing and cold start](../architecture/temporal-trust-smoothing.md)
- [Concurrency-safe validated evidence consumption](../architecture/validated-evidence-trust-consumption.md)
- [Trust transition controls](../architecture/trust-transition-controls.md)
- [Versioned trust configuration lifecycle](../architecture/versioned-trust-configuration.md)
- [Durable trust transition explanations](../architecture/trust-transition-explanations.md)
- [Internal trust-score lookup and freshness contract](../architecture/internal-trust-score-lookup.md)
- [Adaptive trust-engine verification and calibration fixtures](../architecture/trust-engine-verification.md)
- [Application stack and local runtime](../architecture/technology-stack.md)

## 14. Final conclusion

Phase 6 produced a complete, deterministic and tenant-isolated trust-processing foundation. It accepts only validated evidence, requires a complete component set, calculates a transparent weighted score, smooths short-term changes, treats stale information conservatively, limits single-source influence, makes deterioration faster than recovery, preserves immutable history and exposes only fresh state to future policy consumers.

The main strength of the design is not mathematical complexity. It is the combination of understandable algorithms with strict scope binding, versioning, idempotency, append-only explanations and fail-closed behavior. This provides a reliable baseline that can be measured and calibrated later without losing the ability to explain how any historical score was produced.
