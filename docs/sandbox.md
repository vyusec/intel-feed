# Separate runtime analysis host

The runner has a limited broker token and public-registry download access. It receives no database credentials, operator token or signing key. The analyzed container receives only synthetic credentials, copied package archives and prefetched dependencies. It has no host bind mounts or external network, runs as uid 10001, drops capabilities and uses bounded memory/process/tmpfs resources.

Install Podman and a verified gVisor `runsc` release on a separate disposable Linux host. Follow [gVisor's installation instructions](https://gvisor.dev/docs/user_guide/install/), including keeping its sidecar binaries with `runsc`. The supplied launcher expects `/usr/local/bin/runsc`.

Install `deploy/sandbox/runsc-zoli.sh` as `/usr/local/bin/runsc-zoli`, executable by the dedicated runner account, and register it as the `runsc` runtime using `deploy/sandbox/containers.conf`. Create `/var/log/zoli-runsc` with restricted permissions for that account. The wrapper writes per-container `.boot.log` syscall logs on the host; package code cannot rewrite them. File-path substitution and logging flags follow [gVisor's debugging interface](https://gvisor.dev/docs/user_guide/debugging/).

Build the analysis images from the repository root:

```sh
podman build -f deploy/sandbox/Dockerfile.npm -t zoli-sandbox-npm .
podman build -f deploy/sandbox/Dockerfile.pypi -t zoli-sandbox-pypi .
podman image inspect zoli-sandbox-npm --format '{{.Id}}'
podman image inspect zoli-sandbox-pypi --format '{{.Id}}'
```

Set `analysis.sandbox_images.npm` and `.pypi` in `deploy/runner.yaml` to those `sha256:<64 hex>` image IDs or registry references pinned by digest. The runner rejects tag-only images. Record base-image versions and rebuild regularly; the supplied Dockerfiles are build recipes, while runtime jobs require the resulting immutable digest.

On the control service, enable `analysis.runtime_enabled`, set a distinct random `ZOLI_RUNNER_TOKEN`, and keep `runtime_concurrency: 1` initially. On the separate host, supply only that runner token and start:

```sh
./bin/zoli-intel runner --config deploy/runner.yaml --url https://your-feed-host
```

The host downloader verifies artifact hashes and prefetches bounded npm dependencies and universal Python wheels without installing them. Resolution does not fully reproduce npm peers/aliases, Python conditional/extras requirements or platform wheels. Those gaps are recorded and may make execution inconclusive.

Dependency caches and package execution happen inside the sandbox. `network=none` prevents runtime payload retrieval and can suppress some malware behavior. Timeouts, installation failures and unavailable telemetry are inconclusive results. No fallback to an ordinary container runtime is permitted.

Before enabling live package execution, verify with a controlled synthetic archive that the host captures file/process/network observations, an external connection fails, memory/process/time limits work, and the container can neither reach broker credentials nor host logs. The ordinary CI job does not execute live malware. Container and gVisor execution cannot be verified in a workspace without access to the runtime.

Raw runtime logs remain private under the runner's `storage_dir/traces`. Limit that host's disk and log retention, monitor crashes and exhausted budgets, and rebuild the disposable host if isolation fails.
