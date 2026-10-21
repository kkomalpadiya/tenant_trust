# Fabric commit confirmation and reconciliation

An endorsed chaincode response is not proof that an audit commitment was committed. The worker therefore persists the Fabric transaction ID immediately after submission, keeps the row in `confirming`, and moves it to `committed` only when Fabric reports validation code `0`. The final row records the validation code, block number, confirmation source and confirmation time. Every submitted transaction is also retained in `audit.fabric_commitment_attempt` so retries do not erase earlier ledger attempts.

There are two confirmation paths:

1. An active worker waits on the Gateway `SubmittedTransaction` commit status.
2. If that response is lost or the worker stops, the durable row becomes or is recovered to `submitted`. A restarted worker claims it and uses QSCC `GetTransactionByID` and `GetBlockByTxID` with the verifier identity to recover the same validation result and block.

Submission failures and non-zero validation codes remain `failed` during bounded exponential backoff. A status-query outage remains `submitted`, because the transaction outcome is unknown and must not be represented as either committed or rejected. Abandoned submission and confirmation claims are independently recovered after five minutes.

The worker role has no direct access to either audit table. It can only use narrowly scoped security-definer functions for claiming, recording state transitions and reading a bounded delivery summary/gap list. Operators can run `npm run audit-outbox:status`; `npm run audit-outbox:verify` simulates a submission outage and a lost commit response, then constructs a fresh worker and proves QSCC reconciliation before the database becomes `committed`.
