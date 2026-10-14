CREATE TABLE IF NOT EXISTS reports (
 id text PRIMARY KEY, content_hash text NOT NULL, record jsonb NOT NULL,
 source text NOT NULL, source_id text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(source,source_id)
);
CREATE TABLE IF NOT EXISTS public_records (id text PRIMARY KEY, record jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS report_revisions (
 id text NOT NULL, revision integer NOT NULL, record jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(id,revision)
);
CREATE TABLE IF NOT EXISTS source_state (name text PRIMARY KEY, state jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
 id bigserial PRIMARY KEY, dedup_key text NOT NULL UNIQUE, kind text NOT NULL, payload jsonb NOT NULL,
 status text NOT NULL DEFAULT 'queued', attempts integer NOT NULL DEFAULT 0,
 available_at timestamptz NOT NULL DEFAULT now(), lease_until timestamptz,
 lease_token text, priority integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz, last_error text NOT NULL DEFAULT '', result jsonb
);
CREATE INDEX IF NOT EXISTS jobs_claim ON jobs(kind,status,available_at,priority DESC);
CREATE TABLE IF NOT EXISTS budgets (
 day date NOT NULL, kind text NOT NULL, used bigint NOT NULL DEFAULT 0, PRIMARY KEY(day,kind)
);
CREATE TABLE IF NOT EXISTS feed_snapshots (hash text PRIMARY KEY, records jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS publications (
 sequence bigserial PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now(),
 manifest bytea NOT NULL, records_hash text NOT NULL REFERENCES feed_snapshots(hash)
);
CREATE TABLE IF NOT EXISTS service_events (
 id bigserial PRIMARY KEY, kind text NOT NULL, detail text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
