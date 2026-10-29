# Run Intel Feed on your homelab

Checked against this local source on 29 October 2026. These are Linux host commands; no remote deployment was performed while preparing this guide. Docker Compose configurations were validated with placeholder credentials. The database acceptance suite must still run on your server.

Use the continuous configuration: malware report refresh every 15 minutes, npm/PyPI release discovery every minute, publication every minute, and a static worker. Runtime sandbox execution stays disabled.

## 1. Put the current source on the server

The server needs Docker Engine with the Compose plugin, Python 3 and curl. Copy the current `intel-feed` source directory to your server, then enter that directory. The Docker build compiles the Go binary, so host Go is unnecessary.

This laptop's source contains the 22 October continuous-ingestion repairs and has no Git metadata. Do not assume a remote clone contains the same changes. For a fresh server, copy source without `.env`, `secrets/`, `data/` or `bin/`. For example, from the laptop, substituting your SSH destination:

```sh
rsync -av --exclude=.env --exclude=secrets/ --exclude=data/ --exclude=bin/ \
  ~/Documents/intel-feed/ YOUR_USER@YOUR_HOMELAB:~/intel-feed/
ssh YOUR_USER@YOUR_HOMELAB
cd ~/intel-feed
```

If moving an existing feed to this host, restore its PostgreSQL database, feed/private-data volume and original signing key together. A source copy alone is not a migration; preserve publication sequence and client trust. Do not use the fresh-key step below for an existing feed.

## 2. Fresh installation only: credentials and signing key

Generate a private `.env` with three independent random values. This refuses to overwrite an existing file. If `.env` already exists, retain it and skip this command.

```sh
python3 - <<'PY'
import os
import secrets

password = secrets.token_hex(32)
contents = (
    f"POSTGRES_PASSWORD={password}\n"
    f"DATABASE_URL=postgres://zoli:{password}@db:5432/zoli?sslmode=disable\n"
    f"ZOLI_OPERATOR_TOKEN={secrets.token_hex(32)}\n"
    f"ZOLI_RUNNER_TOKEN={secrets.token_hex(32)}\n"
    "GITHUB_TOKEN=\n"
    "ZOLI_API_KEYS=\n"
)
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    output.write(contents)
print('Created .env with mode 0600; no secrets printed.')
PY
```

Add your GitHub token to `GITHUB_TOKEN` in `.env` if needed for backfill rate limits. Keep existing database credentials on later runs; changing this file does not change an initialized PostgreSQL password.

Build the images and create a directory accessible to container uid 10001:

```sh
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml build feed worker
sudo install -d -o 10001 -g 10001 -m 700 secrets
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml \
  run --rm --no-deps feed keygen --key /app/secrets/feed.key
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml \
  run --rm --no-deps feed publickey --key /app/secrets/feed.key
```

`keygen` creates a new key and refuses to replace an existing one. Save the printed **public key** for the Zoli client and back up the private signing key separately. Do not regenerate the signing key on restart or update.

## 3. Validate the database and start the services

Review `deploy/continuous.yaml`, particularly `protected_packages`, `watchlist` and `analysis.daily_bytes`. The default 1 GiB/day reserves up to 20 MiB per artifact, permitting about 51 download reservations per UTC day; it does not cover all npm/PyPI releases.

```sh
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml config --quiet
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml up -d db
```

Wait for the database to show healthy in `docker compose ps`. Create the dedicated acceptance database once (skip `createdb` if it already exists), then run its nine integration tests:

```sh
sudo docker compose exec -T db createdb -U zoli zoli_readiness_test
sudo docker compose -f compose.yaml -f deploy/validation.compose.yaml run --rm validation
```

Require all nine database tests to pass without skips. Then start the feed and static worker:

```sh
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml up --build -d db feed worker
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml ps
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml logs --tail=100 feed worker
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/v1/status | python3 -m json.tool
```

Run the curl commands on the homelab host. Initial OSV/GitHub backfill can take more than an hour. A healthy HTTP endpoint alone does not prove that the intelligence is ready: require recent `last_success` and no `error` for both report sources and every enabled `registry:*` source. Inspect coverage gaps and incomplete sources too. Generated findings require operator review before publication.

## 4. Give Zoli a stable HTTPS endpoint

Compose exposes the API only on the homelab's `127.0.0.1:8080`. Point an existing HTTPS reverse proxy or a persistent named tunnel at that address, on the same host. A proxy in another container has its own loopback and needs an explicit connection to the feed's Docker network instead.

Zoli currently accepts feed URLs only on **public HTTPS port 443 with publicly resolving IP addresses**, with a base path ending in `/feed`. A URL such as `http://192.168.x.x:8080/feed`, a private-only Tailscale address, or an HTTPS hostname resolving to a LAN address will be rejected. A named tunnel with a public hostname can serve a feed hosted inside your homelab. Download routes must be accessible without an interactive login page.

Use a stable hostname and verify these paths through it:

```sh
curl -fsS https://YOUR_FEED_HOST/healthz
curl -fsS https://YOUR_FEED_HOST/v1/status | python3 -m json.tool
curl -fsS https://YOUR_FEED_HOST/feed/latest.json > /tmp/zoli-latest.json
```

Pin the public key obtained directly from your server, rather than learning it from an untrusted download.

## 5. Point the laptop's Zoli client at it

The existing client timer uses `~/Documents/intel-feed/data/zoli-client` as `ZOLI_HOME`. Edit that directory's `config.json`, preserving any other settings. The minimal shape is:

```json
{
  "config_version": 1,
  "feed": {
    "url": "https://YOUR_FEED_HOST/feed",
    "public_key": "PASTE_THE_SERVER_BASE64_PUBLIC_KEY"
  }
}
```

For a fresh client, create the directory with `mkdir -p ~/Documents/intel-feed/data/zoli-client`, then save the JSON above as `config.json` inside it. For an existing client, retain `state.json` and `cache/`; do not delete rollback state to work around a server sequence or signing-key mismatch.

```sh
chmod 700 ~/Documents/intel-feed/data/zoli-client
chmod 600 ~/Documents/intel-feed/data/zoli-client/config.json
cd ~/Documents/Zoli
cargo build --workspace --locked
export ZOLI_HOME="$HOME/Documents/intel-feed/data/zoli-client"
./target/debug/zoli update
./target/debug/zoli status
./target/debug/zoli check --eco npm --name left-pad --ver 1.3.0
```

`update` and `status` verify/report feed state; they do not approve a package. Checks may remain blocked during incomplete, errored or stale source ingestion.

Optional: enable the supplied five-minute client refresh timer from the laptop's normal user shell:

```sh
cd ~/Documents/intel-feed
mkdir -p ~/.config/systemd/user
install -m 644 deploy/client/zoli-feed-update.service deploy/client/zoli-feed-update.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now zoli-feed-update.timer
systemctl --user start zoli-feed-update.service
journalctl --user -u zoli-feed-update.service -n 30
```

These unit files assume the checkout paths above. Adjust them if your laptop paths differ.

## Later restarts and updates

On the homelab, enter the **same directory / Compose project** used for the first deployment so Compose reuses its existing volumes. Keep `.env`, signing key and persistent volumes.

```sh
cd ~/intel-feed
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml up --build -d db feed worker
sudo docker compose -f compose.yaml -f deploy/continuous.compose.yaml logs --tail=100 feed worker
curl -fsS http://127.0.0.1:8080/v1/status | python3 -m json.tool
```

Use the same two `-f` arguments for normal operations. Avoid `down -v`, which deletes the database/feed volumes. See [operations](operations.md) for monitoring, private backups and review procedures.
