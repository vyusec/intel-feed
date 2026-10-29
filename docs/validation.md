# Validation evidence and reproduction

## Phase 3 integration kickoff — 30 October 2026

The user resumed Phase 3 development with low CPU usage. Zoli generated 6,084 PyPI comparison/error cases and 15 new exact-response PyPI query cases from this Go source, then passed Rust comparison and query parity checks. All seven fixture families reproduce exactly. The [Python handoff](zoli-python-integration.md) records the supported subset, artifact selectors and remaining constraint/installer gates.

No feed service code, schema, live source or database changed. Go/database/container suites were not repeated; heavy oracle work ran sequentially under a 50%-of-one-core quota with `GOMAXPROCS=1` and `-p=1`. Existing healthy-source and deployed-delivery gates remain open.

## Foundation hardening — 30 October 2026

The previously skipped PostgreSQL gates now run on a dedicated disposable PostgreSQL 18.6 instance. This pass changes local source only; production data, keys, publications and the homelab deployment were not changed. Phase 3 expansion remains on hold until the [foundation acceptance gates](foundations.md) pass.

| Check | Result and evidence |
| --- | --- |
| Full race suite with a dedicated `ZOLI_TEST_DATABASE_URL` | **60 top-level tests passed (84 with subtests), 0 failures, 0 skips**, including all **9 PostgreSQL tests**; `go test -race -count=1 -json ./...` |
| Controlled discovery lifecycle | Replayed npm discovery creates one job; resolution → artifact worker → private candidate → operator approval → signed publication → verified lookup → withdrawal succeeds on real PostgreSQL |
| Static completion fencing | Expired/superseded leases cannot commit candidates or follow-up jobs; candidate/job effects roll back together on failure; stale workers cannot revise approved records |
| Worker failure states | Unsupported archives are explicit `skipped` jobs; unavailable/bad-digest artifacts retry; exhausted budgets do not report completed work |
| Publication consistency | Public rows and source freshness are read from one statement snapshot; the signed lifecycle exercises this publication path |
| Archive limits | Corrupt/truncated gzip trailers, hidden nonzero trailing tar data, empty ZIPs, duplicate directories, traversal/control paths and invalid/overflow budgets reject |
| Query/client trust | Fixed-clock query boundaries include missing sources and timestamps beyond five-minute future tolerance; same-sequence altered manifests reject in Go and Rust |
| Required quality checks | `make ci` passed with a dedicated test database; final-source formatting, `make vet build evaluate` and race suite passed after changes. Offline npm lock checks remain 3/3 |
| Disposable local database helper | `GOMAXPROCS=2 make test-db-local` passed; helper creates only its own private Unix-socket cluster and cleans it up. `make test-db` without a URL rejects instead of silently skipping |
| Cross-language regression | Zoli regenerated all six oracle families from this source and reproduced them exactly; 36 query cases and 16 Rust caches authenticated by Go |

Environment: Linux/amd64, Go 1.26.10-X:nodwarf5, PostgreSQL 18.6, Node v22.23.1. Synthetic evaluation remains 3 true-positive signals, 2 true negatives, 1 false positive and 0 false negatives; these are regression fixtures, not estimated detection accuracy. Source still has no Git metadata, so no commit identity or hosted CI result is inferred.

`CompleteStatic` now commits a lease-fenced job result, private candidate and follow-up jobs in one transaction. Files written to private artifact storage remain evidence blobs; only the fenced transaction can affect review/publication state. Generated findings still require operator review. Publication input reads prevent old records being paired with a separately read, newer source-success timestamp.

Working evidence is in `/tmp/zoli-foundations-20261030`: `go-final.json`, `feed-final-quality.log`, `ephemeral-db.log`, and `missing-db.log`. The durable results above supersede historical database-skip observations below. Reproduce with `make test-db-local`, or `make ci` against a dedicated test database.

Remaining gates: deploy the source to the homelab, observe healthy configured source completion and incremental replay, process live discovery/worker/review cycles, and verify broad hosted/Go/Rust agreement plus correction/withdrawal delivery. Runtime detonation stays disabled and separate. Zoli now has a locally tested locked npm ci guard with a 24-hour age floor and private offline cache; broader entry points and healthy-feed operation remain open.

## Continuous update repair — 22 October 2026

This pass repairs the two import failures observed on the self-hosted laptop and prepares continuous npm/PyPI release tracking. It does not establish that the laptop is running the patch. This workspace still has no usable Git metadata and cannot create TCP/Unix database sockets. HTTPS downloads through the provided curl execution path work; direct Rust/Python DNS remains restricted.

| Check | Result | Evidence/limit |
| --- | --- | --- |
| Full Go race suite | Passed, with explicit skips | `go test -buildvcs=false -race -count=1 -json ./...`: 48 top-level tests passed, no failures, 6 PostgreSQL integration tests skipped without a dedicated URL |
| Regression coverage | Passed | Unsupported OSV/GitHub identities continue pagination/bootstrap with private originals and visible gaps; malformed input preserves checkpoints; package-less withdrawals retain prior identities; OSV incremental polling includes `[EMPTY]` |
| Scheduling/discovery | Passed | Slow report/registry sources do not block independent peers; protected/watchlist names normalize; prereleases retain exact versions; partial queue failure preserves its cursor and replay does not duplicate jobs; uninitialized sources remain incomplete |
| Exact-version resolution | Passed | Controlled npm and PyPI HTTP fixtures resolve the discovered version, including prereleases, without executing artifacts |
| `go vet -buildvcs=false ./...` | Passed | Includes the new read-only `examples/source-check` command |
| `make build evaluate` | Passed | Synthetic corpus remains 3 true-positive signals, 2 true negatives, 1 false positive and 0 false negatives; no real-world detection-quality claim |
| Complete downloaded OSV archive parser replay | Passed | npm: 222,597 accepted, 132 unsupported; PyPI: 11,920 accepted; Cargo: 21 accepted; Maven: 2 accepted; no parser/record-validation failures. The downloaded `[EMPTY]` archive contained no `MAL-*` reports |
| Captured GitHub parser replay | Passed, limited | 100 captured public malware advisories accepted; `GHSA-qqfx-rpxc-ghp4` is now an explicit unsupported-identity skip. This is not a complete GitHub backfill |
| Live latest GitHub page | Rate limited | HTTP 403, `X-RateLimit-Remaining: 0` with anonymous limit 60. Configure the server's `GITHUB_TOKEN` if its backfill encounters the same limit; do not call that source healthy until a full cycle completes |
| Compose overlays | Passed, configuration only | Docker Compose 5.3.1 resolves continuous and validation overlays. Both runtime services mount `deploy/continuous.yaml`; data, rules, signing-key mount and base ports are preserved. The validation service targets a dedicated database and mounts only source/module files. No container rollout or PostgreSQL test execution was performed here |
| Client timer | Prepared, inactive | Five-minute calendar expression parses. Full `systemd-analyze verify --user` is blocked by sandbox socket/credential operations; installation and activation remain a normal-terminal step |
| Pinned self-hosted delivery | Passed, limited | Prior publication 2 (17,423 records) was downloaded over HTTPS, authenticated by the Go manifest verifier, then passed through Rust `Store::update` using a local downloaded-file transport. Rust `status` reloads the cache and reports degraded sources. This does not establish a normal direct-DNS update or hosted/local query agreement |

The six pending database tests are `TestReviewPublicationLookupAndWithdrawal`, `TestJobsLeasesBudgetsAndRuntimeOutbox`, `TestPrivateReplacementNeverLeaksThroughWithdrawal`, `TestSourceCursorDoesNotAdvanceAfterPartialFailure`, `TestSourceSkipsUnsupportedIdentityAndAppliesEmptyWithdrawal`, and `TestConcurrentSourcesDoNotAutoPublishConflictingAliasScopes`. The last two exercise the new skip/withdrawal behavior and transaction-level alias conflict fencing on real PostgreSQL. In-memory regressions do not replace them.

Working logs are under `/tmp/zoli-refresh-validation-20261022`: `tests-final.jsonl`, `vet-final.log`, `build-evaluate-final.log`, `source-check-final.jsonl`, `compose.json` and `timer-calendar.log`. Archive inputs are temporary `/tmp/zoli-osv-*-all.zip` files downloaded from the documented OSV ecosystem export URLs. The durable summary above distinguishes parser replay from database ingestion and live deployment.

Reproduce the parser replay using already downloaded upstream archives and a captured GitHub advisory-array response:

```sh
GOCACHE=/tmp/zoli-go-cache CCACHE_DISABLE=1 GOPROXY=off \
  go run -buildvcs=false ./examples/source-check \
  /path/to/npm-all.zip /path/to/pypi-all.zip \
  /path/to/cargo-all.zip /path/to/maven-all.zip /path/to/empty-all.zip \
  /path/to/github-advisories.json
```

The checker uses the production parsers and record validator. Unsupported identities are counted separately; malformed records cause a nonzero exit. It does not write a database, publish findings or run package contents. Use the [continuous rollout](operations.md#continuous-threat-and-release-updates), then complete database, healthy source/replay and worker/review gates before accepting Phases 1–2.

## Readiness pass — 16 October 2026

Environment: Linux/amd64, Go `1.26.8-X:nodwarf5`, Node `v22.23.1`, PostgreSQL `18.6`. This workspace has no Git metadata, so there is no commit or observed CI run to attach. A workflow definition is not a CI result.

| Check | Result | Evidence/limit |
| --- | --- | --- |
| `make build evaluate` | Passed | Six synthetic cases: 3 true-positive signals, 2 true negatives, 1 false positive, 0 false negatives |
| `go test -buildvcs=false -race -count=1 -json ./...` | Offline tests passed | 32 top-level tests passed; all 4 PostgreSQL lifecycle tests skipped because no database URL was configured |
| `make vet` | Passed | Includes the client-check example |
| Offline npm-lock checks | Passed | All 3 cases passed when run directly with Node; the CI-style `node --test` command also exited successfully |
| Shell and npm helper syntax | Passed | `bash -n deploy/backup.sh deploy/sandbox/*.sh`; `node --check deploy/sandbox/npm-lock.cjs` |
| Readiness configs and runbook | Passed, limited | Both example configs parse before database access; all shell blocks pass syntax checks; 31 local documentation links/anchors resolve |
| PostgreSQL standalone checks | Passed, limited | All 9 tables created; source-conflict/claim/budget queries prepare; a job is claimed once; a reservation above the budget is denied |
| Database lifecycle with a URL set | Blocked | Targeted lifecycle test fails before application execution: `dial tcp 127.0.0.1:15432: socket: operation not permitted` |
| Upstream access | Blocked | Both source probes fail: `curl: (6) Could not resolve host: storage.googleapis.com` / `api.github.com` |
| Deployed HTTPS client check | Prepared; not executed live | Example builds and its help command runs; no deployed endpoint/key is configured |
| Docker/Podman/gVisor execution | Unverified | No container/package execution was performed; runtime analysis remains disabled |

Compiler tools initially hit `ccache: error: Read-only file system`. Retrying with writable temporary cache paths and `CCACHE_DISABLE=1` passed. This is an environment workaround, not an application change.

Local logs are under `/tmp/zoli-readiness-20261016-I0A0ks`: `tests-final.jsonl`, `vet-final.log`, `build-evaluate.log`, `npm-lock-direct.log`, `postgres-standalone.log`, `standalone.sql`, `database-blocker.log`, and `client-check-help.log`. These are temporary working files; the results above are the durable record.

The evaluation rules SHA-256 is `c726027a19781f1f785747bd1426986301153aa8e141d7da5e58d9784494bfd6`. Synthetic measurements do not estimate real-world detection quality.

### What the offline checks demonstrate

- Existing tests cover parsing/matching, archive bounds, feed authentication, delta withdrawals and rollback rejection.
- Added client tests exercise full snapshot fetching, missing-chain fallback, cache save/reload and file permissions, unchanged manifests, and rejection of forged manifests, changed compressed bytes, changed record sets and changed cache files.
- Signed fixture deltas correct the affected version and then withdraw the finding. Cached lookups change accordingly without mutating the prior verified cache.
- Added API tests preserve report-only coverage and distinguish current, incomplete, failed and stale sources, including missing package versions.
- All new transport fixtures run in memory. They do not prove live upstream behavior, database lifecycle correctness, deployed TLS delivery or runtime isolation.

Pending database tests: `TestReviewPublicationLookupAndWithdrawal`, `TestJobsLeasesBudgetsAndRuntimeOutbox`, `TestPrivateReplacementNeverLeaksThroughWithdrawal`, and `TestSourceCursorDoesNotAdvanceAfterPartialFailure`. Single-user SQL checks cannot replace multi-connection lifecycle, transaction or lease behavior.

Earlier implementation notes reported the same evaluation and successful offline checks, with database lifecycle and live execution skipped. The current pass confirms the results above rather than assuming that earlier claims establish readiness.

## Reproduce the offline checks

Run all commands from the repository root. Dependencies must already be cached when using `GOPROXY=off`; omit that setting on a network-capable host when downloads are needed.

```sh
readiness_tmp="$(mktemp -d /tmp/zoli-readiness.XXXXXX)"
export GOCACHE="$readiness_tmp/go-cache"
export CCACHE_DISABLE=1
export CCACHE_DIR="$readiness_tmp/ccache"
export GOPROXY=off
make build evaluate
go test -buildvcs=false -race -count=1 -v ./...
make vet
node --test testdata/sandbox/offline-lock.test.cjs
node testdata/sandbox/offline-lock.test.cjs
bash -n deploy/backup.sh deploy/sandbox/*.sh
node --check deploy/sandbox/npm-lock.cjs
```

Inspect skips explicitly. An overall successful `go test` exit does not close a skipped database gate.

## Complete the database gate

Use a socket-capable development host with PostgreSQL 17+ and its command-line tools. These commands create a disposable loopback-only cluster with trust authentication for development. Use an unused port 15432 and the same shell throughout.

```sh
readiness_pg="$(mktemp -d /tmp/zoli-readiness-pg.XXXXXX)"
initdb -D "$readiness_pg/db" -A trust -U zoli
pg_ctl -D "$readiness_pg/db" -l "$readiness_pg/server.log" \
  -o "-h 127.0.0.1 -p 15432 -k $readiness_pg" -w start
createdb -h 127.0.0.1 -p 15432 -U zoli zoli_test
createdb -h 127.0.0.1 -p 15432 -U zoli zoli_readiness_live
createdb -h 127.0.0.1 -p 15432 -U zoli zoli_readiness_synthetic
export ZOLI_TEST_DATABASE_URL='postgres://zoli@127.0.0.1:15432/zoli_test?sslmode=disable'
go test -buildvcs=false -race -count=1 -v ./internal/store
```

Require all six lifecycle tests to run and pass without skips. CI supplies PostgreSQL 17 and the database URL; capture an actual run before marking CI verified. Docker-only hosts can use the dedicated [validation Compose service](operations.md#continuous-threat-and-release-updates).

## Complete live report ingestion and delivery

The [live readiness configuration](../examples/readiness/live.yaml) uses the configured OSV/GitHub sources, disables analysis and isolates development data. Do not put synthetic reports in this database/feed.

```sh
umask 077
export ZOLI_READINESS_DATABASE_URL='postgres://zoli@127.0.0.1:15432/zoli_readiness_live?sslmode=disable'
export ZOLI_OPERATOR_TOKEN="$(openssl rand -hex 32)"
./bin/zoli-intel keygen --key data/readiness/live/feed.key
./bin/zoli-intel ingest --config examples/readiness/live.yaml
./bin/zoli-intel publish --config examples/readiness/live.yaml
psql "$ZOLI_READINESS_DATABASE_URL" -X -c 'SELECT name,state FROM source_state ORDER BY name'
psql "$ZOLI_READINESS_DATABASE_URL" -X -c "SELECT source,record->>'status' AS status,count(*) FROM reports GROUP BY source,status ORDER BY source,status"
psql "$ZOLI_READINESS_DATABASE_URL" -X -c "SELECT id,content_hash,record->>'revision' AS revision FROM reports ORDER BY id" > data/readiness/live/revisions-before.txt
./bin/zoli-intel ingest --config examples/readiness/live.yaml
./bin/zoli-intel publish --config examples/readiness/live.yaml
psql "$ZOLI_READINESS_DATABASE_URL" -X -c 'SELECT name,state FROM source_state ORDER BY name'
psql "$ZOLI_READINESS_DATABASE_URL" -X -c "SELECT id,content_hash,record->>'revision' AS revision FROM reports ORDER BY id" > data/readiness/live/revisions-after.txt
diff -u data/readiness/live/revisions-before.txt data/readiness/live/revisions-after.txt
```

Reuse the development key when resuming; `keygen` deliberately refuses to overwrite it. Backfill can exceed the day's time budget. Require both sources to have a successful timestamp, checkpoint and empty error. On replay, unchanged upstream reports must keep their revisions; genuine upstream changes can produce a diff and require inspection. Database totals and deduplicated public counts can differ.

Start `./bin/zoli-intel serve --config examples/readiness/live.yaml` in a separate terminal with the same environment. Expose its loopback port 18080 through a development HTTPS reverse proxy with a trusted certificate and public address. The downloader rejects private/loopback destinations and explicit ports. Get the public key on the trusted service host using `publickey --key data/readiness/live/feed.key`, then distribute it independently of manifests.

```sh
export ZOLI_FEED_URL='https://your-development-feed-host'
export ZOLI_FEED_PUBLIC_KEY='replace-with-the-trusted-base64-public-key'
curl --fail --silent --show-error "$ZOLI_FEED_URL/healthz"
curl --fail --silent --show-error "$ZOLI_FEED_URL/v1/status"
go run -buildvcs=false ./examples/client-check \
  --feed-url "$ZOLI_FEED_URL/feed" --public-key "$ZOLI_FEED_PUBLIC_KEY" \
  --cache data/readiness/live/client-cache.json \
  --query '{"ecosystem":"npm","name":"readiness-absent-fixture","version":"1.0.0"}'
```

The [client-check example](../examples/client-check/main.go) verifies downloaded signatures/artifacts/records, compares local and hosted lookup at one sequence, saves and reloads the verified cache, then repeats lookup. It exits nonzero on disagreement. If publication advances during comparison, rerun. Set `ZOLI_READINESS_API_KEY` if hosted lookup requires a client key; feed downloads remain public.

Repeat with an exact affected package/version from an imported **published** report and `--expect-status known_match`. Repeat after a new publication using the same cache. Capture previous/current sequences, source state and query outputs. An absent-package query is not a safety verdict and may return insufficient information when sources are degraded.

## Complete the isolated review/update exercise

The [synthetic readiness configuration](../examples/readiness/synthetic.yaml) uses a separate database, key, storage directory and port, with no upstream sources. First create its key and start the service in another terminal with the same operator token and synthetic database environment:

```sh
export ZOLI_SYNTHETIC_DATABASE_URL='postgres://zoli@127.0.0.1:15432/zoli_readiness_synthetic?sslmode=disable'
./bin/zoli-intel keygen --key data/readiness/synthetic/feed.key
# In the separate terminal, run:
# ./bin/zoli-intel serve --config examples/readiness/synthetic.yaml
```

Expose port 18081 through its own trusted development HTTPS endpoint and configure its public key. Reuse one client cache throughout the following transitions:

```sh
export ZOLI_SYNTHETIC_FEED_URL='https://your-synthetic-feed-host'
export ZOLI_SYNTHETIC_PUBLIC_KEY='replace-with-the-synthetic-public-key'
synthetic_check() {
  go run -buildvcs=false ./examples/client-check \
    --feed-url "$ZOLI_SYNTHETIC_FEED_URL/feed" --public-key "$ZOLI_SYNTHETIC_PUBLIC_KEY" \
    --cache data/readiness/synthetic/client-cache.json \
    --query "{\"ecosystem\":\"npm\",\"name\":\"zoli-controlled-example\",\"version\":\"$1\"}" \
    --expect-status "$2"
}
./bin/zoli-intel import --url http://127.0.0.1:18081 --file examples/record.json
./bin/zoli-intel review --url http://127.0.0.1:18081 --id ZOLI-controlled-example \
  --action approve --revision 1 --reviewer readiness-check \
  --rationale 'Controlled synthetic exercise' --classification suspicious
./bin/zoli-intel publish --config examples/readiness/synthetic.yaml
synthetic_check 1.0.0 known_match
python3 - <<'PY'
import json, pathlib
record = json.loads(pathlib.Path('examples/record.json').read_text())
record['summary'] = 'Controlled correction: affected version is 2.0.0'
record['affected'][0]['versions'] = ['2.0.0']
record['sources'][0]['revision'] = 'example-v2'
pathlib.Path('data/readiness/synthetic/correction.json').write_text(json.dumps(record))
PY
./bin/zoli-intel import --url http://127.0.0.1:18081 --file data/readiness/synthetic/correction.json
./bin/zoli-intel publish --config examples/readiness/synthetic.yaml
synthetic_check 1.0.0 no_known_match
./bin/zoli-intel inspect --url http://127.0.0.1:18081 --id ZOLI-controlled-example
```

On a fresh synthetic database the correction is pending at revision 3 and the old public claim is withdrawn. Confirm the inspected revision; if resuming, use the actual value. Approval with revision 2 must fail with a revision mismatch (HTTP 409); an authentication or network error does not satisfy this check. For a fresh exercise:

```sh
if ./bin/zoli-intel review --url http://127.0.0.1:18081 --id ZOLI-controlled-example \
  --action approve --revision 2 --reviewer readiness-check \
  --rationale 'Expected stale revision rejection' --classification suspicious; then
  printf '%s\n' 'FAIL: stale review was accepted' >&2
  exit 1
fi
./bin/zoli-intel review --url http://127.0.0.1:18081 --id ZOLI-controlled-example \
  --action approve --revision 3 --reviewer readiness-check \
  --rationale 'Approved controlled version correction' --classification suspicious
./bin/zoli-intel publish --config examples/readiness/synthetic.yaml
synthetic_check 1.0.0 no_known_match
synthetic_check 2.0.0 known_match
./bin/zoli-intel review --url http://127.0.0.1:18081 --id ZOLI-controlled-example \
  --action withdraw --revision 4 --reviewer readiness-check \
  --rationale 'End of controlled exercise'
./bin/zoli-intel publish --config examples/readiness/synthetic.yaml
synthetic_check 2.0.0 no_known_match
./bin/zoli-intel history --url http://127.0.0.1:18081 --id ZOLI-controlled-example
```

Capture sequence changes and client outputs. The offline client tests separately assert that correction/withdrawal updates request delta artifacts. Also query without a version and require `insufficient_information` before withdrawal.

Stop both development services and reverse proxies after validation. Stop only the disposable cluster above with `pg_ctl -D "$readiness_pg/db" -m fast -w stop`. Preserve evidence before removing temporary data. Runtime host checks, staging monitoring/restart/restore and Zoli installation policy remain separate [roadmap](roadmap.md) gates.
