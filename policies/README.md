# Policy source

OPA loads reviewed Rego policy from this directory in local development. The bootstrap package provides a small deterministic query used to prove that the policy service loaded repository policy; it does not make an access decision.

Access policy added in later tasks must remain tenant-scoped and default-deny. Test policy with `npm run policy:test` before starting or restarting the service. Application callers use only documented Data API decision paths and do not modify policy through OPA's management APIs.
