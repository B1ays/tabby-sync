#!/bin/sh
# Restores a backup over the live database, e.g. after losing the server.
# Needs the same secrets/ directory (or at least the keyring) as when the
# dump was taken. On a new server: run setup.sh, copy secrets/keyring and
# .env back from your safe place, copy the dump into backups/, then run this.
#
# Before overwriting anything it dumps the current database to
# backups/tabbysync-prerestore-<time>.dump, so restoring the wrong dump can be
# undone by restoring that file. If the current database cannot be dumped
# (e.g. it is damaged), --no-snapshot restores without that safety copy.
#
# Usage: sudo ./restore.sh [--no-snapshot] backups/tabbysync-<time>.dump
set -eu
cd "$(dirname "$0")"
snapshot=true
if [ "${1:-}" = "--no-snapshot" ]; then
	snapshot=false
	shift
fi
f=${1:?usage: restore.sh [--no-snapshot] backups/tabbysync-<time>.dump}
[ -f "$f" ] && [ -f "$f.sha256" ] || { echo "$f or $f.sha256 not found" >&2; exit 1; }
case "$(cd "$(dirname "$f")" && pwd)" in
"$(pwd)/backups") ;;
*) echo "the dump must be in $(pwd)/backups" >&2; exit 1 ;;
esac

# Same lock as backup.sh: no backup may run while the database is replaced.
exec 9>>backups/.lock
flock -n 9 || { echo "a backup or restore is already running; try again later" >&2; exit 1; }

docker compose stop syncd
docker compose up -d --wait db
if $snapshot; then
	ts=$(date -u +%Y%m%dT%H%M%SZ)
	if ! docker compose run --rm --no-deps -T backup snapshot "$ts"; then
		echo "could not dump the current database, nothing was restored;" >&2
		echo "rerun with --no-snapshot to restore without a safety copy" >&2
		docker compose up -d --wait
		exit 1
	fi
	echo "the database before this restore: backups/tabbysync-prerestore-$ts.dump"
fi
docker compose run --rm --no-deps -T backup restore "/backups/$(basename "$f")"
docker compose run --rm --no-deps -T syncd verify
docker compose up -d --wait
echo "restored from $f"
