#!/bin/sh
# Restores a backup over the live database, e.g. after losing the server.
# Needs the same secrets/ directory (or at least the keyring) as when the
# dump was taken. On a new server: run setup.sh, copy secrets/keyring and
# .env back from your safe place, copy the dump into backups/, then run this.
# Usage: sudo ./restore.sh backups/tabbysync-<time>.dump
set -eu
cd "$(dirname "$0")"
f=${1:?usage: restore.sh backups/tabbysync-<time>.dump}
[ -f "$f" ] && [ -f "$f.sha256" ] || { echo "$f or $f.sha256 not found" >&2; exit 1; }
case "$(cd "$(dirname "$f")" && pwd)" in
"$(pwd)/backups") ;;
*) echo "the dump must be in $(pwd)/backups" >&2; exit 1 ;;
esac

docker compose stop syncd
docker compose up -d --wait db
docker compose run --rm --no-deps -T backup restore "/backups/$(basename "$f")"
docker compose run --rm --no-deps -T syncd verify
docker compose up -d --wait
echo "restored from $f"
