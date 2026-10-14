# Zoli Intel Feed

An open source package threat intelligence pipeline for Zoli. It imports attributed malware reports, discovers new PyPI/npm releases, inspects artifacts, queues findings for review, and publishes signed intelligence that Zoli can query locally or through an API.

**This repository builds the feed.** Zoli's package-manager interception and installation policy belong in the client project. A missing finding is not a safety verdict.

## What is implemented

- OSV `MAL-*` and explicit GitHub malware ingestion, historical bootstrap, incremental updates, retries, daily reconciliation, private original reports, and per-source checkpoints.
- Pinned OpenSSF npm/PyPI release feeds, watchlists, gap reporting, durable artifact jobs, bounded archive inspection, public static rules, and a separate gVisor runtime runner.
- Revision-bound operator review, rejected findings, corrections, withdrawals, and complete report history.
- Public signed JSONL snapshots, ecosystem files, ordered deltas, attribution, coverage and freshness; hosted lookup and an offline Go client.
- PostgreSQL state, container deployment, scheduling, CI, synthetic evaluation and security-boundary regression tests.

PyPI supports pip, Poetry and Pipenv identities; npm supports npm/pnpm identities. Cargo and Maven initially receive published reports. Conda supports reviewed reports with channel, subdirectory and build selectors; its version ranges are retained as uncertain rather than evaluated.

## Start locally

Requirements: Go 1.26+, PostgreSQL, or Docker Compose. Network access is needed for dependency downloads and live ingestion.

```sh
make build
cp .env.example .env
# Set a random database password and distinct random operator/runner tokens in .env.
./bin/zoli-intel keygen --key secrets/feed.key
./bin/zoli-intel publickey --key secrets/feed.key
```

Record the public key in Zoli's client configuration through a trusted channel. The signing key is created with mode `0600`; when using the supplied container, make its directory and file readable by container uid 10001 while keeping access restricted. For example, on Linux:

```sh
sudo chown -R 10001:10001 secrets
docker compose up --build -d
```

Compose binds the API to `127.0.0.1:8080`. Put a TLS reverse proxy in front of it before exposing it remotely. Run the sandbox runner on a separate host; [the sandbox guide](docs/sandbox.md) describes its setup. Runtime analysis defaults to disabled until that host is configured.

For a native deployment, set `DATABASE_URL` and `ZOLI_OPERATOR_TOKEN`, change `listen` to loopback if needed, and run:

```sh
./bin/zoli-intel serve --config config.yaml
./bin/zoli-intel worker --config config.yaml
```

Initial OSV bootstrap downloads ecosystem archives containing both vulnerabilities and malware, imports only `MAL-*` reports, and can take longer than the hourly update target. The initial feed reports sources as incomplete until ingestion succeeds. Server timers continue to run when GitHub Actions scheduling is delayed.

## Review a finding

Export `ZOLI_OPERATOR_TOKEN` in your operator shell, then:

```sh
./bin/zoli-intel list --status pending
./bin/zoli-intel inspect --id ZOLI-example
./bin/zoli-intel history --id ZOLI-example
./bin/zoli-intel review --id ZOLI-example --action approve \
  --revision 1 --reviewer your-name --rationale 'Observed credential exfiltration' \
  --classification malicious
```

Use the inspected revision, not the example value. `reject` and `withdraw` are available through the same command. Review all Zoli-generated findings. Trusted source imports can publish automatically only when source policy accepts them; borderline reports and conflicting scopes require review.

Corrections are submitted with `import --file corrected-record.json`, preserving the record ID and source identity. A changed report becomes pending again and its previous public revision is withdrawn until review. Replaying an unchanged source record preserves its approval. See [the review policy](docs/review.md) for evidence and appeal requirements.

## Consume the feed

- `GET /feed/latest.json`: signed manifest envelope.
- Signed artifact paths are relative to `/feed/` and identify immutable compressed snapshots and deltas.
- `POST /v1/query`: one package identity.
- `POST /v1/querybatch`: `{ "packages": [...] }`, limited to 100 identities.
- `GET /v1/status`: publication sequence, source state and coverage.

```sh
curl -s http://127.0.0.1:8080/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"ecosystem":"npm","name":"example","version":"1.0.0"}'
```

Responses distinguish `known_match`, `no_known_match`, and `insufficient_information`. Findings carry a `malicious` or `suspicious` classification and `exact`, `range`, or `uncertain` matching. Stale source data is visible. Zoli decides how those results affect installation.

The Go client in [pkg/client](pkg/client) verifies signatures, compressed artifact checksums, delta continuity and the resulting record hash. It atomically saves a cache and authenticates cached content before local lookup. Feed downloads require no account. Set `ZOLI_API_KEYS` to a comma-separated list of keys to restrict hosted lookups; each key must contain at least 32 characters.

Read [the feed format](docs/feed-format.md) and [OpenAPI specification](api/openapi.yaml) for integration details.

## Reproduce and evaluate

```sh
./bin/zoli-intel analyze --artifact package.tgz --ecosystem npm \
  --rules rules/rules.yaml
./bin/zoli-intel evaluate --corpus testdata/evaluation/corpus.json
make test vet
```

Use the artifact SHA-256 and recorded rules revision when reproducing a finding. Original archives and complete analysis output stay private. Public evidence contains file locations, rule IDs, explanations and bounded runtime observations rather than package binaries or credentials.

The initial held-out synthetic corpus produces 3 true-positive signals, 2 true negatives and 1 false positive in a documentation example. These are regression measurements, **not real-world accuracy estimates**. This is why Zoli detections require review. Add independently labeled samples before making detection-quality claims. Metadata and runtime rule behavior is described in [the rule catalog](rules/README.md).

Set `ZOLI_TEST_DATABASE_URL` to a dedicated PostgreSQL database to run lifecycle integration tests. They create and remove isolated test schemas. CI runs those tests with PostgreSQL and the Go race detector. Live registry collection and container execution require suitable network and sandbox infrastructure and are separate from unit tests.

## Operating and growing

Defaults are 1 GiB/day of conservative static-download reservations, 20 MiB per artifact, 100 MiB expanded content, 100 runtime jobs/day and one concurrent runtime job. Each download reserves its maximum size; this bounds consumption and may defer work before actual bytes reach the daily limit. Increase limits and add workers through configuration.

Rolling upstream release feeds can lose events. Watchlists help recover selected packages, but the feed does not claim registry-wide coverage. Unavailable, oversized and unsafe archives have explicit skipped results. An empty or failed sandbox run never publishes a safe verdict. Dependency prefetch is bounded and reports unsupported aliases, conditional requirements and platform-specific wheels.

Private raw reports and artifact evidence use content-addressed filesystem storage under `data/private`; keep that volume restricted and back it up to private object storage. Public downloads live separately under `data/feed`. Unchanged snapshots are reused. Deltas are retained for 30 days; older clients fetch a full snapshot. PostgreSQL retains operator history and publication metadata.

See [the operations guide](docs/operations.md) for monitoring, backup, restore and staged rollout. No hosting account, domain, production deployment or GitHub repository is created by this code.

## License

Pipeline code and original detection rules: [Apache 2.0](LICENSE). Original intelligence: [CC BY 4.0](DATA-LICENSE.md). Imported intelligence retains the license and attribution in each record. Included upstream source revisions and changes are recorded in [NOTICE](NOTICE).
