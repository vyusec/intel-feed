#!/usr/bin/env bash
# Run the real database gate in a disposable, private Unix-socket cluster.
set -euo pipefail
cd "$(dirname "$0")/.."
for program in initdb pg_ctl createdb go; do
  command -v "$program" >/dev/null || { echo "Required local tool missing: $program" >&2; exit 1; }
done
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/zoli-postgres.XXXXXXXX")
cleanup() {
  pg_ctl -D "$test_dir/db" -m immediate -w stop >/dev/null 2>&1 || true
  rm -rf -- "$test_dir"
}
trap cleanup EXIT
mkdir "$test_dir/socket"
initdb -D "$test_dir/db" -A trust -U zoli --no-locale >"$test_dir/initdb.log"
pg_ctl -D "$test_dir/db" -l "$test_dir/postgres.log" -o "-h '' -k '$test_dir/socket'" -w start >/dev/null
createdb -h "$test_dir/socket" -U zoli zoli_test
export ZOLI_TEST_DATABASE_URL="postgresql://zoli@/zoli_test?host=$test_dir/socket&sslmode=disable"
make test-db
