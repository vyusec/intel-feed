#!/bin/sh
set -eu
: "${DATABASE_URL:?Set DATABASE_URL}"
backup_dir="${ZOLI_BACKUP_DIR:-./data/backups}"
mkdir -p "$backup_dir"
umask 077
backup_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
pg_dump --format=custom --file="$backup_dir/zoli-$backup_stamp.dump" "$DATABASE_URL"
