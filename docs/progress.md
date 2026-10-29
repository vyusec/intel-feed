# Threat intel feed progress

Updated: 30 October 2026 (Asia/Kolkata). Audience: feed maintainers and Zoli integrators.

Phase 1 and Phase 2 foundations were hardened locally on 30 October. All nine PostgreSQL integration tests now execute successfully, including controlled discovery → static analysis → review → signed publication → withdrawal. The full race suite passes 60 top-level tests (84 including subtests), with no test skips. Live healthy ingestion and deployed worker/review acceptance remain open; The user subsequently resumed Phase 3 integration development, with low local CPU usage.

## Phase 3 integration kickoff — 30 October

Zoli's first Python slice consumes the existing feed contract: normalized PyPI identities, concrete exact/event matching and optional artifact SHA-256 selectors. Its generated corpus now includes 6,084 comparisons against this Go source and 15 PyPI query-response cases. Unsupported constraint-string matching refuses in Rust until parity is implemented. See the [Python handoff](zoli-python-integration.md). This adds no feed endpoint or schema and does not establish live feed health or guarded pip installation.

## Foundation hardening — 30 October

- Static completion now commits the lease check, private candidate and follow-up jobs in one transaction. Expired/superseded workers cannot change review state. Failed completion rolls back all database effects.
- Publication reads public records and source freshness in one PostgreSQL statement snapshot, preventing older records being paired with a newly completed import's timestamps.
- Skipped artifacts have a visible `skipped` queue state. Missing downloads, malformed archives, integrity failures and exhausted budgets are covered on PostgreSQL; none produces a clean finding.
- Archive inspection verifies gzip trailers and bounded tar padding, rejects appended hidden payloads, empty ZIPs, duplicate directory paths and control-character paths.
- Go and Rust now reject same-sequence manifest equivocation. Queries share explicit clock semantics: missing sources and timestamps more than five minutes ahead are degraded; the one-hour maximum age is unchanged.
- `make test-db-local` provisions and removes a disposable PostgreSQL cluster. `make test-db` and `make ci` require a dedicated database URL instead of silently skipping the database gate. Hosted CI uses the same `make ci` entry point.

See [validation](validation.md#foundation-hardening--30-october-2026) and [remaining gates](foundations.md). No homelab deployment, production database change or runtime activation was performed.

## Continuous update work — 22 October

- Fixed OSV/GitHub imports stopping on historical package names the identity model does not support. Skips preserve private originals and expose bounded source gaps and operator events. Malformed data and failed writes still fail the source without advancing its checkpoint.
- Package-less withdrawals retain the existing affected identity for retraction. OSV's separate `[EMPTY]` export is included in bootstrap and incremental polling.
- Report sources refresh independently; shared-alias import decisions take ordered transaction locks so parallel sources cannot both auto-publish conflicting scopes. Successful timestamps record completion. GitHub backfill prioritizes recently updated advisories and reports rate exhaustion with actionable guidance.
- Default report ingestion is every 15 minutes; release discovery and publication run every minute. Protected packages get individual recovery polls as well as rolling npm/PyPI feeds. Exact discovered versions are queued; partial queue failures preserve their checkpoint.
- [Continuous Compose overlay](../deploy/continuous.compose.yaml) enables the static worker with existing storage/key mounts and runtime disabled. [Client timer templates](../deploy/client/zoli-feed-update.timer) prepare five-minute client refreshes; they are not installed or active yet.
- Validation: 48 top-level tests passed with the race detector; 6 PostgreSQL integration tests skipped. The complete downloaded OSV npm/PyPI/Cargo/Maven archives yielded 234,540 supported malware records and 132 unsupported identities with zero parser/record validation failures. A captured 100-record GitHub page passed; the specific historical GitHub failure is now a coverage skip. These are parser replay results, not completed database ingestion.

See the [dated validation entry](validation.md#continuous-update-repair--22-october-2026) and [rollout instructions](operations.md#continuous-threat-and-release-updates). Registry-wide coverage and automatic publication of generated findings are not claimed.

## Capability baseline

| Area | Implemented | Evidence | Remaining gate |
| --- | --- | --- | --- |
| Upstream reports | OSV `MAL-*` and explicit GitHub malware imports, bootstrap, incremental checkpoints, retries, reconciliation, private originals | `internal/ingest`, source configuration, parser and checkpoint tests | Complete configured backfills and replay an incremental cycle against live sources |
| Release discovery | OpenSSF npm/PyPI feeds, watchlists, gap tracking, durable artifact jobs | `internal/discovery`, discovery tests | Observe real discovery and queue processing with explicit coverage gaps |
| Static analysis | Bounded archive inspection, static and metadata signals, budgets, retries, private artifact evidence | `internal/analysis`, rule catalog, evaluation corpus | Controlled PostgreSQL lifecycle passes; observe deployed real worker/review cycles |
| Runtime analysis | Separate runner, digest-pinned images, gVisor isolation, bounded telemetry and evidence | Runner implementation and [sandbox guide](sandbox.md) | Controlled isolation checks on the separate runtime host; disabled by default |
| Operator review | Revision-bound approval/rejection, corrections, withdrawals, history | Store/API implementation and lifecycle tests | Nine local database tests pass; repeat on deployed source/database |
| Publication | Ed25519 manifests, immutable compressed snapshots, ordered deltas, attribution, coverage, freshness | `internal/feed`, feed tests, [format](feed-format.md) | Publish a real backfill and verify correction/withdrawal delivery |
| Consumption | Hosted single/batch lookup and verified Go cache/client | `pkg/client`, API/client tests, [OpenAPI](../api/openapi.yaml) | Verified HTTPS download, cache reload, hosted/local agreement and incremental update |
| Operations | Compose deployment, scheduling, health/status, queue statistics, backup script, CI workflow | [Operations guide](operations.md), deployment files, workflow definitions | Staging deployment, observed CI pass, monitoring, restart and restore exercise |

PyPI and npm have selective analysis support. Cargo and Maven initially consume published reports. Conda supports reviewed reports and selectors; Conda ranges remain uncertain. Release discovery does not establish registry-wide coverage.

## Validation record

### Historical readiness pass — 16 October

Earlier implementation notes reported a successful build, race tests, vet, offline npm-lock tests, shell syntax checks, a PostgreSQL standalone schema/query check, and synthetic evaluation. Those notes did not demonstrate database lifecycle tests, a CI run, live ingestion, container execution, or deployed client delivery.

The current pass rebuilt the binary and passed 32 top-level Go tests with the race detector, vet, all three offline npm-lock checks, shell/helper syntax checks, and the six-case synthetic evaluation. A fresh PostgreSQL standalone check accepted the schema, a single job claim and the budget boundary. All four database lifecycle tests remain pending: they skipped without a URL, and a targeted retry with a URL failed at socket creation.

Added client regression checks cover verified snapshots, missing-delta fallback, cache save/reload, tampering, correction/withdrawal deltas and unchanged publications. Added API checks cover incomplete/failed/stale sources and missing versions. These are offline fixture results, not live delivery evidence.

The [live and synthetic validation runbook](validation.md#complete-live-report-ingestion-and-delivery), isolated example configurations and [client-check command](../examples/client-check/main.go) are ready to run in an environment with sockets, DNS and a trusted HTTPS endpoint. See [validation evidence](validation.md) for exact commands, results and limits.

## Current blockers

| Gate | Latest recorded observation (historical dates retained) | Next action |
| --- | --- | --- |
| PostgreSQL lifecycle | Closed locally on 30 October: all nine integration tests pass against a dedicated PostgreSQL instance | Repeat the dedicated database gate with the deployed source on the homelab |
| Live source backfill | The laptop's old image failed on unsupported historical names. Parser fixes pass downloaded archives locally. A later GitHub probe exhausted the anonymous API limit | Deploy the patch, configure `GITHUB_TOKEN` if needed, complete each source and replay incrementally |
| Deployed client verification | HTTPS download and pinned-key authentication succeeded for publication 2 (17,423 records), with source freshness degraded. Normal public HTTPS verification was subsequently demonstrated in Zoli on 29 October against a degraded publication | Repeat a normal client update and hosted/local comparison after healthy source completion; verify the five-minute timer installed on 29 October |
| Live runtime analysis | Separate gVisor host and image digests have not been validated | Complete the controlled checks in the sandbox guide in the final rollout phase |

These environment failures do not establish whether the blocked application paths pass or fail. Keep the associated gates open. Historical observations above remain dated evidence, not current deployment claims.

## Zoli handoff contract

- Feed base URL ends in `/feed`; the Go client appends `/latest.json`. Use an HTTPS host with a valid trusted certificate on the default port and a public address. The downloader rejects private/loopback destinations.
- Distribute the Ed25519 public key through trusted Zoli configuration. Persist the last verified snapshot/sequence; save a replacement only after signature, artifact and resulting record checks succeed.
- Normalize ecosystem, package name, registry and version; include available hashes and Conda selectors. Registry identities and ecosystems are not interchangeable.
- Preserve `known_match`, `no_known_match`, and `insufficient_information`, plus classification, matching certainty, coverage and freshness. No known match is not a safety verdict.
- Handle correction/withdrawal updates and stale or unavailable intelligence. Installation policy belongs in Zoli and requires a separate product decision.
- Keep generated findings subject to review. Use the synthetic corpus for regression checks, not real-world accuracy claims.

See the [roadmap](roadmap.md) for phase dependencies, today's execution order and acceptance gates. Update this file after every completed gate with the date and a link to its validation evidence.
