# Phase 1 and Phase 2 foundation gates

Updated 30 October 2026 (Asia/Kolkata). After the local foundation pass, the user authorized beginning Phase 3 integration development. Outstanding acceptance gates below remain open.

| Gate | Local evidence | Remaining work |
| --- | --- | --- |
| Database and publication | Nine integration tests run without skips: review revisions, public/private isolation, signed publication, withdrawals, source cursor rollback, concurrent alias handling, leases/budgets, static lifecycle and atomic completion | Repeat the gate on the deployment source/database version |
| Static analysis | Discovery replay creates one job; artifact resolution and inspection create private candidates; review alone publishes them; stale leases cannot commit effects; corrupt/unavailable/budget-limited work stays explicit | Observe configured live npm/PyPI discovery, worker throughput, retries, skips and operator review |
| Archive boundaries | Gzip trailer verification, bounded trailing tar padding, empty ZIP rejection, path controls, duplicate paths and size/entry budgets | Broader labeled package corpus; no real-world detection-quality claim |
| Trust and freshness | Both clients reject equivocation; Go QueryAt and Rust use the same fixed-clock corpus; missing/future source evidence degrades | Healthy live signed publication and broad hosted/local agreement with corrections/withdrawals |
| Reproduction | `make ci` requires a database; `make test-db-local` creates its own disposable private Unix-socket cluster | Hosted CI and homelab deployment evidence |

Reproduce locally with PostgreSQL tools installed:

```sh
GOMAXPROCS=2 make test-db-local
```

For the full gate against an existing **dedicated test database**, set `ZOLI_TEST_DATABASE_URL` and run `GOMAXPROCS=2 make ci`. Production credentials, signing keys, feeds and tables are not needed. The local helper creates and removes only its own temporary cluster and exposes no TCP listener.

Deployment remains a separate gate: retain the existing signing key and publication history, copy the current source, run the dedicated database tests, rebuild feed/worker, then record configured source freshness and completed worker/review cycles. npm discovery 404s or size-limit failures remain visible errors until specifically resolved; they are not relabeled healthy by this work. Do not equate `/healthz` success with ingestion readiness.

Zoli's independent Phase 2 guard now implements explicit `zoli wrap npm -- ci` for npm 10: full pre-execution assessment, a 24-hour minimum publish age, metadata/archive integrity binding and an invocation-private offline cache. Real npm tests cover the warm-cache bypass, changed feed/input rejection and normal lifecycle output/status. Broader commands/managers, shims/doctor and healthy deployed-feed acceptance remain open while Phase 3 adapters are developed.
