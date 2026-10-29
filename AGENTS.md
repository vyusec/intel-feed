# Local resource preference

The user requested low CPU usage on 30 October 2026.

- Run builds and tests sequentially, with `GOMAXPROCS=1` and Go build/test `-p=1`.
- On this Linux desktop, run compute-heavy commands through `systemd-run --user --scope --quiet -p CPUQuota=50% -p CPUWeight=10 nice -n 15 ...`. If unavailable, retain one job and low priority; do not claim a hard cap.
- Prefer focused regression checks. Avoid Docker, full race suites and parallel scans unless required by the change. Hosted CI requirements remain unchanged.
