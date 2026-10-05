# Tenant Trust review console

This temporary, read-only frontend presents the repository's completed Phase 1-4 work during a review.

Start it from the repository root:

```text
npm run demo:review
```

Open `http://127.0.0.1:4173`. Switch among the deterministic Alpha and Beta personas, inspect tenant-scoped records and run the access-boundary scenarios. Authorization decisions use the real `@tenant-trust/tenant-context` and `@tenant-trust/authorization` packages. The browser does not receive or store private keys.
