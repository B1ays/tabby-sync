#!/bin/sh
# Daily backup, run by cron (see tabby-sync.cron):
#   1. dump the database and restore the dump into a scratch database;
#   2. decrypt every revision of the restored copy with the current keyring;
#   3. only then name it tabbysync-<time>.dump, write its .sha256, prune old
#      dumps and record the time in backups/LAST_SUCCESS.
# A dump that fails a check stays as *.unverified, which restore.sh refuses.
# Any failure exits non-zero and leaves LAST_SUCCESS untouched; monitor its age.
# Copy backups/ off the server (restic, rclone...) and keep secrets/keyring
# in a different place than the dumps.
set -eu
cd "$(dirname "$0")"
umask 077
keep_days=${TABBYSYNC_BACKUP_KEEP_DAYS:-14}
keep_min=${TABBYSYNC_BACKUP_KEEP_MIN:-7}

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }
cleanup() { docker compose run --rm --no-deps -T backup cleanup >/dev/null 2>&1 || true; }

# One backup or restore at a time: backups share the scratch database and a
# restore replaces the live one. Taken before the trap, so a run that loses
# the race never drops the other run's scratch database.
exec 9>>backups/.lock
flock -n 9 || { log "BACKUP SKIPPED: another backup or restore is running"; exit 1; }
trap cleanup EXIT

ts=$(date -u +%Y%m%dT%H%M%SZ)
log "backup started"
docker compose run --rm --no-deps -T backup dump "$ts" || { log "BACKUP FAILED: dump or restore"; exit 1; }
docker compose run --rm --no-deps -T syncd verify -database tabbysync_restore_check ||
	{ log "BACKUP FAILED: the restored copy does not decrypt"; exit 1; }

mv "backups/tabbysync-$ts.dump.unverified" "backups/tabbysync-$ts.dump"
mv "backups/tabbysync-roles-$ts.sql.unverified" "backups/tabbysync-roles-$ts.sql"
(cd backups && sha256sum "tabbysync-$ts.dump" > "tabbysync-$ts.dump.sha256")

# Prune by age, but never below the newest $keep_min verified dumps.
ls -1t backups/tabbysync-2*.dump | tail -n +"$((keep_min + 1))" | while read -r old; do
	if [ -n "$(find "$old" -mtime +"$keep_days")" ]; then
		stamp=${old#backups/tabbysync-}
		stamp=${stamp%.dump}
		rm -f "$old" "$old.sha256" "backups/tabbysync-roles-$stamp.sql"
	fi
done
find backups -maxdepth 1 \( -name 'tabbysync-*.unverified' -o -name 'tabbysync-prerestore-*' \) \
	-mtime +"$keep_days" -delete

date -u +%Y-%m-%dT%H:%M:%SZ > backups/LAST_SUCCESS
log "backup ok: backups/tabbysync-$ts.dump"
