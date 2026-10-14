# Local validation

Validated during implementation:

- Go build, unit tests with the race detector, and `go vet` passed.
- Three offline npm-lock tests passed: local archive pinning, conflicting-version rejection, and unsafe-name rejection.
- Deployment shell scripts and the npm lock helper passed syntax checks.
- PostgreSQL 18 standalone mode accepted the schema and prepared source-conflict/job-claim/budget queries. A synthetic job was claimed once and a reservation exceeding the daily budget was denied.
- The synthetic evaluation generated three true-positive signals, two true negatives and one false positive. It does not measure real-world malware detection accuracy.

Local PostgreSQL lifecycle integration tests were skipped because the workspace cannot create TCP or Unix sockets. The CI workflow supplies PostgreSQL 17 and sets `ZOLI_TEST_DATABASE_URL` for those tests. Docker and Podman execution and live source ingestion were not exercised locally because container and shell network access are unavailable.

Before operating live runtime analysis, complete the controlled sandbox checks in `sandbox.md`, run CI's database tests, and verify a full initial source backfill and signed client update against the deployed service.
