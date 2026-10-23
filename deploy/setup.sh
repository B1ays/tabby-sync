#!/bin/sh
# One-time setup on the server: generates secrets, builds the image and
# installs the maintenance cron jobs. Safe to re-run: existing secrets and
# keys are kept.
# Usage: sudo ./setup.sh sync.example.com
set -eu
cd "$(dirname "$0")"
here=$(pwd)

domain=${1:?usage: setup.sh <domain>}
[ "$(id -u)" -eq 0 ] || { echo "run as root (secrets get container-specific owners)" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is not installed" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "the docker compose plugin is not installed" >&2; exit 1; }

umask 077
mkdir -p secrets/oidc backups

rand() { head -c 32 /dev/urandom | base64 | tr -d '/+=\n'; }
new() { [ -s "secrets/$1" ] || rand > "secrets/$1"; }

new db_superuser_password
new db_owner_password
new db_app_password

# The database is on an internal Docker network with no route out, so the
# connection is not TLS. Use sslmode=verify-full for a database elsewhere.
printf 'postgres://tabbysync_owner:%s@db:5432/tabbysync?sslmode=disable' \
	"$(cat secrets/db_owner_password)" > secrets/owner_database_url
printf 'postgres://tabbysync_app:%s@db:5432/tabbysync?sslmode=disable' \
	"$(cat secrets/db_app_password)" > secrets/app_database_url

# The key-encryption key is 32 random bytes; generating it here, before
# anything else, means .env exists before compose first reads the file.
touch .env
if [ ! -s secrets/keyring ]; then
	if grep -q '^TABBYSYNC_KEK_PRIMARY=' .env; then
		echo "secrets/keyring is missing but .env names a key: restore the keyring from backup" >&2
		exit 1
	fi
	kek="k$(date +%Y%m)"
	printf '%s %s\n' "$kek" "$(head -c 32 /dev/urandom | base64 | tr -d '\n')" > secrets/keyring
	printf 'TABBYSYNC_KEK_PRIMARY=%s\n' "$kek" >> .env
fi
grep -q '^TABBYSYNC_DOMAIN=' .env || printf 'TABBYSYNC_DOMAIN=%s\n' "$domain" >> .env

# Secrets are bind-mounted with host ownership: postgres runs as uid 70 in
# the alpine image, the server as distroless nonroot (65532). The server
# refuses a keyring readable by anyone else.
chown 70:70 secrets/db_*_password
chown 65532:65532 secrets/keyring secrets/*_database_url
chown -R 65532:65532 secrets/oidc
find secrets -maxdepth 1 -type f -exec chmod 0400 {} +
chmod 0500 secrets/oidc
chmod 0600 .env
chmod 0700 backups
chmod 0755 backup.sh restore.sh initdb/*.sh

docker compose build migrate

# Daily backup with restore check, and cleanup of expired data.
sed "s|@DIR@|$here|g" tabby-sync.cron > tabby-sync.cron.installed
if [ -d /etc/cron.d ]; then
	install -m 0644 tabby-sync.cron.installed /etc/cron.d/tabby-sync
	rm tabby-sync.cron.installed
	echo "Installed /etc/cron.d/tabby-sync (backup 03:15, purge 03:45)."
else
	echo "No /etc/cron.d here: add $here/tabby-sync.cron.installed to root's crontab yourself." >&2
fi

echo
echo "Secrets are in $here/secrets, backups go to $here/backups."
echo "Copy secrets/keyring somewhere safe, separately from the backups:"
echo "without it the data cannot be decrypted; stored next to them, encryption protects nothing."
echo "Next: docker compose up -d && docker compose run --rm syncd user add <name>"
