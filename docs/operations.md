# Operations

Roll out in stages: report ingestion and signed delivery, then static workers, then the separate sandbox runner. Keep human review enabled for all Zoli-generated findings. Verify the initial source backfill before using the feed for installation policy.

Monitor `GET /v1/status` for each source's last success, error and recorded gaps. Alert when report ingestion has not succeeded for an hour, when a signed manifest is stale, or when the expected source has never completed its first import. `GET /admin/stats` exposes queue counts, ages, skipped artifacts and daily budget reservations. Report-only ecosystems and incomplete release discovery must remain visible in Zoli.

GitHub Actions triggers ingestion at minutes 7 and 37. Set repository variable `ZOLI_FEED_URL` to the HTTPS service URL and secret `ZOLI_OPERATOR_TOKEN` to the operator credential. Server scheduling continues independently. The workflow does not checkout or execute submitted package code.

Use a TLS reverse proxy with body and connection limits. The API deliberately ignores spoofable forwarded-IP headers. Configure API keys for clients needing individual rate limits; unauthenticated clients behind one reverse proxy share its visible peer limit. Downloads remain public and cacheable.

Back up PostgreSQL daily with `deploy/backup.sh`, plus the private evidence volume and published feed files to private object storage. Keep the signing key in a separate restricted backup. Restore into a new database and verify operator history, source checkpoints, the signed manifest and referenced files before switching traffic. Never reset publication sequences while serving existing clients.

The database keeps private report revisions. Public files reuse unchanged snapshots and preserve 30 days of deltas. Private artifacts may be malicious: access them through the review workflow and isolated analysis host. They must not be served through the public feed route.

Resource limits are configuration values rather than permanent throughput caps. Add static workers as needed; PostgreSQL claims use leases and `SKIP LOCKED`. Expired work retries up to five attempts. Completion tokens fence stale workers, and runtime completion creates its evidence job atomically. A daily-budget denial defers work to the next UTC day without consuming retry attempts.

The service logs failed scheduled operations and exposes health/status endpoints. Connect your monitoring system to those endpoints for notifications; this repository does not send messages to external services automatically.

The one-hour target measures upstream report ingestion after bootstrap. It does not cover the time before a source discovers malware, queue delays from selective scanning, or operator review time. Those limits should be explicit in user-facing protection status.
