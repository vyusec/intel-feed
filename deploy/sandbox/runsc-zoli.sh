#!/bin/sh
set -eu
# Register this wrapper as Podman's `runsc` OCI runtime on the sandbox host.
# Logs are host-side and are never mounted into the analyzed container.
exec /usr/local/bin/runsc \
  --debug \
  '--debug-log=/var/log/zoli-runsc/%ID%.%COMMAND%.log' \
  --strace \
  --strace-syscalls=openat,execve,connect,clone \
  --strace-log-size=256 \
  "$@"
