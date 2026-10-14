#!/bin/sh
set -eu
# runsc writes syscall telemetry on the host, outside this uid 10001 container.
mkdir -p /work/home/.aws /work/home/.ssh
printf '%s\n' '[default]' 'aws_access_key_id = ZOLI_SYNTHETIC_KEY' 'aws_secret_access_key = ZOLI_SYNTHETIC_SECRET' > /work/home/.aws/credentials
printf '%s\n' 'ZOLI_SYNTHETIC_SSH_KEY' > /work/home/.ssh/id_rsa
export HOME=/work/home
export npm_config_cache=/work/npm-cache
export PIP_DISABLE_PIP_VERSION_CHECK=1
exec /usr/local/bin/execute.sh
