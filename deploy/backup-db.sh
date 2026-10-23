#!/bin/sh
# Runs inside the "backup" container (postgres image) as the database
# superuser. Called by backup.sh and restore.sh on the host:
#   dump TS          write tabbysync-TS.dump.unverified and restore it into a
#                    scratch database; backup.sh renames it once verified
#   snapshot TS      write tabbysync-prerestore-TS.dump of the live database
#   cleanup          drop the scratch database
#   restore FILE     replace the live database with a verified dump
set -eu
umask 077
export PGHOST=db PGUSER=postgres PGPASSWORD="$(cat /run/secrets/db_superuser_password)"
check=tabbysync_restore_check

q() { psql -X -v ON_ERROR_STOP=1 -tA "$@"; }

case "${1:-}" in
dump)
	ts=${2:?usage: backup-db.sh dump TIMESTAMP}
	f=/backups/tabbysync-$ts.dump.unverified
	pg_dump -Fc -d tabbysync -f "$f"
	# Role definitions (with password hashes) are needed to rebuild a cluster.
	pg_dumpall --roles-only -f "/backups/tabbysync-roles-$ts.sql.unverified"
	echo "dump: $f ($(wc -c < "$f") bytes)"

	# Restore from the file just written, exactly as one would after a loss.
	dropdb --if-exists --force "$check"
	createdb "$check"
	pg_restore --exit-on-error --no-owner --no-acl -d "$check" "$f"

	live=$(q -d tabbysync -c "SELECT max(version_id) FROM tabbysync.goose_db_version WHERE is_applied")
	restored=$(q -d "$check" -c "SELECT max(version_id) FROM tabbysync.goose_db_version WHERE is_applied")
	[ "$live" = "$restored" ] || { echo "schema version $restored in the dump, $live live" >&2; exit 1; }
	echo "restored: schema version $restored, $(q -d "$check" -c "SELECT
		(SELECT count(*) FROM tabbysync.users) || ' users, ' ||
		(SELECT count(*) FROM tabbysync.configs WHERE deleted_at IS NULL) || ' configs, ' ||
		(SELECT count(*) FROM tabbysync.config_revisions) || ' revisions'")"

	# Let the server's role read the copy, so "syncd verify" can decrypt it.
	q -d "$check" -c "GRANT USAGE ON SCHEMA tabbysync TO tabbysync_app;
		GRANT SELECT ON ALL TABLES IN SCHEMA tabbysync TO tabbysync_app" >/dev/null
	;;
snapshot)
	# A plain copy of the live database, taken by restore.sh before it
	# overwrites it, so a restore from the wrong dump can be undone.
	ts=${2:?usage: backup-db.sh snapshot TIMESTAMP}
	name=tabbysync-prerestore-$ts.dump
	pg_dump -Fc -d tabbysync -f "/backups/$name.partial"
	mv "/backups/$name.partial" "/backups/$name"
	(cd /backups && sha256sum "$name" > "$name.sha256")
	echo "snapshot: /backups/$name ($(wc -c < "/backups/$name") bytes)"
	;;
cleanup)
	dropdb --if-exists --force "$check"
	;;
restore)
	# Replace the live database with a dump; owners and grants come from it.
	f=${2:?usage: backup-db.sh restore /backups/tabbysync-<time>.dump}
	(cd /backups && sha256sum -c -s "$(basename "$f").sha256")
	pg_restore --clean --if-exists --exit-on-error -d tabbysync "$f"
	echo "restored $f: schema version $(q -d tabbysync -c "SELECT max(version_id) FROM tabbysync.goose_db_version WHERE is_applied")"
	;;
*)
	echo "usage: backup-db.sh dump TS|snapshot TS|cleanup|restore FILE" >&2
	exit 2
	;;
esac
