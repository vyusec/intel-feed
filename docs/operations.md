# Operations

Roll out in stages: report ingestion and signed delivery, then static workers, then the separate sandbox runner. Keep human review enabled for all Zoli-generated findings. Verify the initial source backfill before using the feed for installation policy.

## Continuous threat and release updates

The continuous configuration refreshes malware reports every 15 minutes, polls npm/PyPI releases every minute and publishes signed intelligence every minute. Each report source has an independent scheduler, so a long OSV bootstrap does not stop GitHub refreshing. GitHub bootstrap visits recent advisories first. Successful timestamps record completion, and failed or partial cycles retain their prior checkpoints.

On an existing laptop deployment, first apply the source update. Run the PostgreSQL acceptance suite in a temporary Go container, using a dedicated database rather than production tables. Create the test database once; if it already exists, reuse it. The test container mounts only source and module files and receives the test database URL:

```sh
sudo docker compose up -d db
sudo docker compose exec -T db createdb -U zoli zoli_readiness_test
sudo docker compose -f compose.yaml -f deploy/validation.compose.yaml run --rm validation
```

Require all nine database tests to pass without skips before accepting the update. Then review `deploy/continuous.yaml`, especially protected packages, watchlists and the daily download budget. Start the feed and static worker together:

```sh
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml config --quiet
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml up --build -d db feed worker
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml logs --since=2m feed worker
```

The overlay mounts the same configuration into both services and retains the base Compose file's host port, database, persistent data and signing-key mount. It enables static analysis and leaves runtime execution disabled. Use the same pair of `-f` arguments for subsequent Compose operations. Do not reset the database, delete volumes or generate a replacement signing key during an update.

Set `GITHUB_TOKEN` in the server's `.env` when GitHub's anonymous API limit is insufficient for backfill. The [global public-advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories) needs no additional fine-grained permissions. Exhausted GitHub limits remain source errors, with the reset time and token guidance; they are not marked successful. Recreate the feed container after editing `.env`.

Verify `/healthz`, then inspect `/v1/status`. Require both report sources and all enabled `registry:*` sources to have a recent `last_success` and no `error`. Initial backfill may take multiple cycles or longer than one hour. Registry sources are published as incomplete until their first successful poll. The status endpoint reports the committed manifest's coverage rather than assuming analysis is enabled.

Protected npm/PyPI packages are also polled individually, together with explicit watchlist entries. Names and ecosystem aliases are normalized and deduplicated. This recovers versions already omitted from the rolling feed for those packages. Newly discovered exact versions, including prereleases, enter the static queue; missing versions or publication timestamps are errors. A failed queue write keeps the discovery checkpoint unchanged, and replay uses the same job deduplication keys.

Rolling feeds are selective and can omit releases. Poll frequency is not a promise that every new registry version has been inspected. Check `/admin/stats` for queue age, failures, skipped artifacts and deferred budgets. The default 1 GiB/day budget conservatively reserves up to 20 MiB per artifact, so it can permit only about 51 reservations per UTC day even when actual artifacts are smaller. Increase the budget or workers deliberately for the desired throughput. Generated findings still require review before publication.

Unsupported upstream package identities, such as historical npm names beginning with `--`, no longer abort a whole import. The raw report stays private, `ingest_skip` records the omission, and the source's `gaps` retains up to 20 distinct examples. These are excluded coverage, not imported findings. Malformed reports, transport failures and storage failures remain errors. Package-less withdrawals reuse an existing record's identity solely to retract it; [OSV's `[EMPTY]` export](https://google.github.io/osv.dev/data/#per-ecosystem-downloads) is included in bootstrap and incremental polling.

## Refresh the Zoli client automatically

On the Zoli client laptop, `deploy/client/zoli-feed-update.service` and `.timer` refresh the verified cache every five minutes. The supplied paths match the current `~/Documents/Zoli` and `~/Documents/intel-feed` checkouts; edit them if those paths differ. The configuration and cache remain under `data/zoli-client`, and the existing pinned URL/key and rollback state remain in force.

Install these user units from a normal client terminal:

```sh
mkdir -p ~/.config/systemd/user
install -m 644 deploy/client/zoli-feed-update.service deploy/client/zoli-feed-update.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now zoli-feed-update.timer
systemctl --user start zoli-feed-update.service
systemctl --user list-timers zoli-feed-update.timer
journalctl --user -u zoli-feed-update.service -n 30
```

The timer runs while the user manager is active and catches up after missed calendar runs. Keep the server awake and the tunnel running. A Quick Tunnel hostname changes after restart; update the pinned client's URL when that happens, or use a persistent named tunnel for a stable endpoint. Unit installation/activation is not performed by the restricted workspace session.

## Monitoring and recovery

Monitor `GET /v1/status` for each source's last success, error and recorded gaps. Alert when report ingestion has not succeeded for an hour, when a signed manifest is stale, or when the expected source has never completed its first import. `GET /admin/stats` exposes queue counts, ages, skipped artifacts and daily budget reservations. Report-only ecosystems and incomplete release discovery must remain visible in Zoli.

GitHub Actions triggers ingestion at minutes 7 and 37. Set repository variable `ZOLI_FEED_URL` to the HTTPS service URL and secret `ZOLI_OPERATOR_TOKEN` to the operator credential. Server scheduling continues independently. The workflow does not checkout or execute submitted package code.

Use a TLS reverse proxy with body and connection limits. The API deliberately ignores spoofable forwarded-IP headers. Configure API keys for clients needing individual rate limits; unauthenticated clients behind one reverse proxy share its visible peer limit. Downloads remain public and cacheable.

Back up PostgreSQL daily with `deploy/backup.sh`, plus the private evidence volume and published feed files to private object storage. Keep the signing key in a separate restricted backup. Restore into a new database and verify operator history, source checkpoints, the signed manifest and referenced files before switching traffic. Never reset publication sequences while serving existing clients.

The database keeps private report revisions. Public files reuse unchanged snapshots and preserve 30 days of deltas. Private artifacts may be malicious: access them through the review workflow and isolated analysis host. They must not be served through the public feed route.

Resource limits are configuration values rather than permanent throughput caps. Add static workers as needed; PostgreSQL claims use leases and `SKIP LOCKED`. Expired work retries up to five attempts. Completion tokens fence stale workers, and runtime completion creates its evidence job atomically. A daily-budget denial defers work to the next UTC day without consuming retry attempts.

The service logs failed scheduled operations and exposes health/status endpoints. Connect your monitoring system to those endpoints for notifications; this repository does not send messages to external services automatically.

The one-hour target measures upstream report ingestion after bootstrap. It does not cover the time before a source discovers malware, queue delays from selective scanning, or operator review time. Those limits should be explicit in user-facing protection status.
