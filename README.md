# tabby-sync

**English** | [Русский](README.ru.md)

A self-hosted config sync server for the [Tabby](https://github.com/Eugeny/tabby) terminal.

The server implements the Tabby Web sync API (`/api/1`), so the desktop Tabby app connects to it as is. Configs are encrypted on the server, every device has its own token, changes are kept in a revision history, and concurrent edits from different devices are never lost.

## Features

- **Tabby compatibility.** The desktop app syncs through the standard *Settings → Config sync* page.
- **Encryption at rest.** Each revision is encrypted with AES-256-GCM under its own data key; data keys are wrapped with a master key (envelope encryption). Ciphertext is bound to its user, config and revision, so rows swapped in the database fail to decrypt.
- **History and rollback.** Every content change is a new immutable revision. Any revision can be viewed and restored from the web UI or the API.
- **No lost writes.** Writes to one config are serialized with a row lock. API v2 requires `If-Match` and answers `412` if the config has changed in the meantime.
- **Per-device tokens.** Each device gets its own token with scopes and an expiry; tokens can be revoked at any time. Only the SHA-256 of a token is stored.
- **Web UI.** Sign-in with any OpenID Connect provider; device and session management; history browsing and restore.
- **API v2** for your own clients: mandatory `If-Match`, `Idempotency-Key`, `Repr-Digest`/`Content-Digest` (RFC 9530).
- **Ready-made deployment.** Docker Compose with PostgreSQL and Caddy (automatic TLS); daily backups verified by a test restore; separate database roles; resource limits and a health check.

### Compared with Tabby Web

| | Tabby Web | tabby-sync |
|---|---|---|
| Config storage | plaintext | AES-256-GCM, envelope encryption, bound to owner and revision |
| Concurrent edits | last write wins | every write is a revision; `If-Match` → `412` |
| History | none | revisions with a retention policy and rollback |
| Sync token | one per user, stored in plaintext, accepted in the URL | one per device, stored hashed, with scopes, expiry and revocation; header only |
| Web sign-in | OAuth via social_django | OIDC Authorization Code + PKCE, `state`, `nonce` |
| Sessions and CSRF | Django | server-side sessions in a `__Host-` cookie; `Sec-Fetch-Site`/`Origin` check plus a form token |
| Database privileges | a single role | migrations run as the schema owner; the server can only read and write rows |

## Quick start

You need a Linux server with Docker Engine and the Compose v2 plugin, cron, and a domain whose DNS record points to the server. Ports 80 and 443 must be open: Caddy obtains a Let's Encrypt certificate.

```bash
git clone <repository-url> /opt/tabby-sync
```

```bash
cd /opt/tabby-sync/deploy && sudo ./setup.sh sync.example.com
```

```bash
cd /opt/tabby-sync/deploy && sudo docker compose up -d --wait
```

`setup.sh` generates the database passwords, the master key (`secrets/keyring`) and `.env`, builds the image and installs the cron jobs for backups and cleanup. Running it again overwrites nothing.

Create a user and a token for the first device:

```bash
cd /opt/tabby-sync/deploy && sudo docker compose run --rm syncd user add alice
```

```bash
cd /opt/tabby-sync/deploy && sudo docker compose run --rm syncd token create -user alice -name laptop
```

The token is shown only once. In Tabby, open *Settings → Config sync* and enter the address `https://sync.example.com` and the token.

> **Store `secrets/keyring` and `.env` somewhere safe right away, separately from the backups.** Without the master key the data cannot be decrypted, and a key kept next to the backups makes the encryption pointless.

## Deployment options

### Behind an existing nginx

If the server already runs nginx with TLS, the bundled Caddy is not needed. Before `docker compose up`, enable the override file:

```bash
cd /opt/tabby-sync/deploy && sudo cp nginx/compose.override.yaml compose.override.yaml
```

It disables Caddy, publishes the server on `127.0.0.1:8080` only, and trusts `X-Forwarded-For` only from the gateway of the Docker network that nginx connects through. Compose loads this file automatically, so the backup scripts and cron jobs use it too.

Then add the site from [`deploy/nginx/tabby-sync.conf`](deploy/nginx/tabby-sync.conf), replacing the domain and certificate paths. The settings that matter:

- `client_max_body_size 8m` — with nginx's default limit (1 MB), large configs get `413`;
- `proxy_set_header X-Forwarded-For $remote_addr` — the header is overwritten, so a client cannot inject its own address;
- `proxy_set_header Host $host` — the CSRF protection checks `Origin` against it;
- the app sets HSTS and CSP itself; do not add them again in nginx.

### Under a path on a shared domain

The service can live next to other applications, for example at `https://example.com/services/tabby-sync/`. Add to `deploy/.env`:

```
TABBYSYNC_BASE_PATH=/services/tabby-sync
```

and paste the snippet from [`deploy/nginx/tabby-sync-location.conf`](deploy/nginx/tabby-sync-location.conf) into the existing nginx `server { ... }` block. In this mode:

- the server strips the prefix itself and answers `404` to anything outside it; links, redirects and `Location` headers include the prefix;
- cookies are scoped to `<prefix>/` and use the `__Secure-` prefix (`__Host-` requires `Path=/`), so other applications on the same domain never receive them;
- HSTS is not sent: the domain's own nginx owns that policy;
- in Tabby, enter the server address with the prefix: `https://example.com/services/tabby-sync`.

With a path prefix, sibling subdomains of the same domain can plant cookies. If those subdomains run untrusted applications, give the service its own subdomain.

### Without a reverse proxy

The server can terminate TLS itself: set `TABBYSYNC_TLS_CERT_FILE`, `TABBYSYNC_TLS_KEY_FILE` and `TABBYSYNC_LISTEN`.

## Web sign-in (OIDC)

The web UI works with any OpenID Connect provider: Google, Microsoft Entra ID, GitLab, Keycloak, Authentik, Auth0 and others. GitHub does not support OIDC for user sign-in and cannot be used.

1. Register a web application with the provider, with the redirect URI `https://<domain>[<prefix>]/auth/<id>/callback`, for example `https://sync.example.com/auth/google/callback`.
2. Save the client secret to a file that the container sees as `/run/oidc/<id>`:
   ```bash
   cd /opt/tabby-sync/deploy && sudo sh -c 'umask 077; cat > secrets/oidc/google && chown 65532:65532 secrets/oidc/google'
   ```
3. Add the settings to `deploy/.env`:
   ```
   TABBYSYNC_OIDC_PROVIDERS=google
   TABBYSYNC_OIDC_GOOGLE_NAME=Google
   TABBYSYNC_OIDC_GOOGLE_ISSUER=https://accounts.google.com
   TABBYSYNC_OIDC_GOOGLE_CLIENT_ID=<client-id>.apps.googleusercontent.com
   TABBYSYNC_OIDC_GOOGLE_CLIENT_SECRET_FILE=/run/oidc/google
   ```
4. Restart the server:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose up -d --wait syncd
   ```

**Who can sign in.** A user is identified by the issuer plus the provider's subject ID, not by email. Email is used only on the first sign-in, and only if the provider has verified it (`email_verified`):

- if an administrator has assigned this address to a user (`syncd user add alice -email alice@example.com` or `syncd user set-email alice alice@example.com`), the sign-in is linked to that user;
- otherwise a new user is created only if the address is listed in `TABBYSYNC_ALLOWED_EMAILS` or its domain in `TABBYSYNC_ALLOWED_EMAIL_DOMAINS`;
- in all other cases the sign-in is refused.

Issuing a device token in the web UI requires a recent sign-in (15 minutes by default). The re-authentication request uses `max_age=0`, and the provider must confirm it with a fresh `auth_time`; an existing session at the provider does not count.

## Administration

Run the commands from the `deploy/` directory as `sudo docker compose run --rm syncd <command>`.

```
syncd user add <name> [-email addr]          create a user
syncd user set-email <name> <addr|->         set or clear ("-") the email that links the first web sign-in
syncd user list                              list users
syncd user disable|enable <name>             disable or enable; disabling immediately invalidates all tokens and sessions
syncd token create -user U -name N [-scopes S] [-ttl D]
                                             issue a device token (shown once)
syncd token import-legacy -user U -name N    import a Tabby Web token (read from stdin)
syncd token list -user U                     list a user's devices
syncd token revoke -user U (-id ID | -all)   revoke token(s)
syncd keys generate -id ID                   generate a keyring line
syncd keys rewrap                            rewrap data keys under the primary master key
syncd purge                                  delete expired data (run by cron)
syncd verify [-database NAME]                decrypt every revision and check integrity
syncd migrate up|down|status|version         manage the database schema
syncd health                                 readiness check (used by the health check)
```

Token scopes: `configs:read`, `configs:write`, `user:read`, `user:write`. By default a token gets `configs:read,configs:write,user:read` and a one-year lifetime; `-ttl 0` issues a token that never expires.

## API

### API v1 — Tabby Web compatible

| Request | Purpose |
|---|---|
| `GET /api/1/configs` | list configs with their content |
| `POST /api/1/configs` | create a config |
| `GET /api/1/configs/{id}` | get a config |
| `PATCH`, `PUT /api/1/configs/{id}` | change name, content, Tabby version |
| `DELETE /api/1/configs/{id}` | delete a config |
| `GET`, `PUT`, `PATCH /api/1/user` | profile and active config |

Authentication is `Authorization: Bearer <device token>`; passing the token in the URL (`?auth_token=`) is not supported. Responses carry an `ETag`, and writes honor `If-Match` when the client sends it. A write with unchanged content creates no revision and does not move `modified_at`, so other devices do not download the config again.

### API v2

For clients that can handle conflicts. Authentication is the same.

| Request | Purpose |
|---|---|
| `GET /api/2/configs` | list metadata: id, name, version, revision, size, timestamps |
| `POST /api/2/configs` | create a config (`{"name", "content"}`); requires `Idempotency-Key` |
| `GET /api/2/configs/{id}` | metadata with `content_digest` and `ETag` |
| `PATCH /api/2/configs/{id}` | change `name`, `last_used_with_version`; requires `If-Match` |
| `DELETE /api/2/configs/{id}` | delete; requires `If-Match` |
| `GET /api/2/configs/{id}/content` | content (`application/yaml`) with `Repr-Digest`; `If-None-Match` → `304` |
| `PUT /api/2/configs/{id}/content` | upload content; requires `If-Match` |
| `GET /api/2/configs/{id}/revisions` | revision history, newest first |
| `GET /api/2/configs/{id}/revisions/{rev}/content` | revision content with `Repr-Digest` |
| `POST /api/2/configs/{id}/revisions/{rev}/restore` | make a revision current; requires `If-Match` |

- **Concurrency.** An `ETag` such as `"v12"` changes on every change to the config. A change without `If-Match` is refused with `428`, one with a stale value with `412` and the current `ETag`. `If-Match: *` is not accepted.
- **Integrity.** `Repr-Digest: sha-256=:…:` is the SHA-256 of the content. A client may send `Content-Digest` or `Repr-Digest` (sha-256 or sha-512) with an upload; on a mismatch the server answers `400` and writes nothing.
- **Idempotency.** `Idempotency-Key: "…"` (1–255 visible ASCII characters) is accepted on every modifying request and required for `POST`. The response is stored for 24 hours in the same transaction as the change. A repeated request gets the stored response with `Idempotent-Replayed: true`; the same key with a different request gets `422`. Client errors (4xx) are stored, server errors (5xx) are not, so such a request can be retried. Keys are scoped per user.

Errors use `application/problem+json` (RFC 9457).

## Security

**What is synced.** Tabby sends its whole `config.yaml` except the sync settings themselves: connection profiles (hosts, ports, user names, key paths), terminal settings and — depending on Tabby's sync options — hotkeys, appearance and the secrets vault. Passwords saved in the OS keychain and the key files themselves are not sent.

**What the encryption protects.** Config content is encrypted, and the master key is stored apart from the database (`secrets/keyring`). A leaked database dump, backup or disk without the key does not reveal the content. Access to the running server (root) also gives access to the key. To keep secrets away even from the server, enable Tabby's vault or full config encryption: the server then only receives data encrypted with your passphrase.

**Metadata** — config names, change times, revision sizes, device information — is stored unencrypted.

**Other measures:**
- tokens and session IDs are stored only as SHA-256 hashes;
- rate limits per client address (per /64 for IPv6), per failed authentication attempts and per device;
- strict security headers (CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`) and `Cache-Control: no-store`;
- the server container (distroless) runs as non-root, with a read-only file system and no capabilities; the database is reachable only on an internal Docker network, and the server connects with a role that can only read and write rows;
- the server refuses to start if the keyring file is accessible to anyone but its owner.

## Operations

### Backups

Every day at 03:15 cron runs `deploy/backup.sh`. It:

1. dumps the database and roles to `deploy/backups/`;
2. restores the dump into a scratch database and checks the schema version;
3. decrypts every revision of the restored copy with the current key (`syncd verify`);
4. only when all checks pass, names the dump `tabbysync-<time>.dump`, writes a `.sha256` file and records the time in `backups/LAST_SUCCESS`. A dump that fails a check keeps the `.unverified` extension.

Dumps are kept for 14 days (`TABBYSYNC_BACKUP_KEEP_DAYS`), but the latest 7 verified dumps are always kept (`TABBYSYNC_BACKUP_KEEP_MIN`). These variables are read by `backup.sh`; you can set them in `/etc/cron.d/tabby-sync`. Output goes to syslog: `journalctl -t tabby-sync-backup`.

Backup and restore share a lock: if one is already running, the other exits immediately with a message.

Recommended:
- watch the age of `backups/LAST_SUCCESS` — if it is older than a day, backups are failing;
- copy `backups/` off the server (restic, rclone, borg);
- keep `secrets/keyring` and `.env` separate from the dumps.

### Restore

```bash
cd /opt/tabby-sync/deploy && sudo ./restore.sh backups/tabbysync-<time>.dump
```

The script stops the server, saves the current database to `backups/tabbysync-prerestore-<time>.dump`, replaces it with the dump, checks that it decrypts and starts the server. Only verified dumps with a `.sha256` file are accepted. To undo a restore, restore the safety copy with the same script. If the current database cannot be dumped (for example, because it is damaged), rerun with `--no-snapshot`.

**Moving to a new server:** run `setup.sh`, bring back `secrets/` (at least `keyring`) and `.env` from your safe copy, put the dump and its `.sha256` into `backups/` and run `restore.sh`.

### Master key rotation

1. Generate a new key and append the printed line to `secrets/keyring`:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose run --rm syncd keys generate -id k202701
   ```
2. Set `TABBYSYNC_KEK_PRIMARY=k202701` in `.env` and restart the server:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose up -d --wait syncd
   ```
3. Rewrap the data keys of existing revisions:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose run --rm syncd keys rewrap
   ```
4. Remove the old key's line from `secrets/keyring`.

### Maintenance and resources

Every day at 03:45 cron runs `syncd purge`. It permanently removes configs deleted more than 30 days ago (`TABBYSYNC_SOFT_DELETE_RETENTION`), as well as expired sessions, abandoned sign-in attempts and idempotency keys. You can check database integrity at any time:

```bash
cd /opt/tabby-sync/deploy && sudo docker compose run --rm --no-deps syncd verify
```

Container logs are capped at five 10 MB files per service. Memory limits: PostgreSQL 512 MB, the server 256 MB, Caddy 128 MB. The server has a health check (which also checks the database); Caddy starts only once it passes.

## Updating

Secrets, `.env`, `backups/` and `compose.override.yaml` are not part of the repository, so an update leaves them alone.

1. Take a backup and tag the current image for a possible rollback:
   ```bash
   cd /opt/tabby-sync/deploy && sudo ./backup.sh
   ```
   ```bash
   sudo docker tag tabby-sync:local tabby-sync:prev
   ```
2. Get the new version:
   ```bash
   cd /opt/tabby-sync && sudo git pull
   ```
   Without a git clone on the server, use an archive: `git archive --format=tar.gz -o tabby-sync.tar.gz HEAD` on your machine, then `tar -xzf tabby-sync.tar.gz -C /opt/tabby-sync` on the server.
3. Build the image, apply migrations and recreate the containers:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose up -d --build --wait
   ```
4. Check that the server runs the new image:
   ```bash
   [ "$(sudo docker inspect tabby-sync-syncd-1 --format '{{.Image}}')" = "$(sudo docker image inspect tabby-sync:local --format '{{.Id}}')" ] && echo "syncd runs the new image"
   ```

`docker compose restart` does not pick up a new image — it restarts the existing container. Use `docker compose up -d`. The image is built from the installation directory, so changes in other copies of the repository do not end up in it.

**Rollback.** Bring back the previous image without rebuilding:

```bash
cd /opt/tabby-sync/deploy && sudo docker tag tabby-sync:prev tabby-sync:local && sudo docker compose up -d --wait
```

If the new version has already applied schema migrations, also restore the backup from step 1 with `restore.sh`. Remove unused images with `sudo docker image prune -f`.

## Configuration

The server is configured with environment variables. For secrets you can give a file path by appending `_FILE` to the name (for example, `TABBYSYNC_DATABASE_URL_FILE`). In the Docker Compose deployment the variables go into `deploy/.env`.

| Variable | Default | Description |
|---|---|---|
| `TABBYSYNC_LISTEN` | `127.0.0.1:8080` (`:8080` in the image) | HTTP listen address |
| `TABBYSYNC_TLS_CERT_FILE`, `TABBYSYNC_TLS_KEY_FILE` | — | certificate and key when the server terminates TLS itself |
| `TABBYSYNC_DATABASE_URL` | — | PostgreSQL connection string |
| `TABBYSYNC_KEYRING_FILE` | — | master key file |
| `TABBYSYNC_KEK_PRIMARY` | — | ID of the primary master key |
| `TABBYSYNC_PUBLIC_URL` | — | external URL of the service, including the prefix; required for OIDC |
| `TABBYSYNC_BASE_PATH` | — | path prefix on a shared domain, for example `/services/tabby-sync` |
| `TABBYSYNC_TRUSTED_PROXIES` | — | proxy addresses or subnets allowed to send `X-Forwarded-For` |
| `TABBYSYNC_CORS_ALLOWED_ORIGINS` | `*` | allowed CORS origins for the API |
| `TABBYSYNC_OIDC_PROVIDERS` | — | comma-separated OIDC provider IDs |
| `TABBYSYNC_OIDC_<ID>_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_NAME`, `_SCOPES` | `_SCOPES`: `openid,email,profile` | settings of provider `<ID>` |
| `TABBYSYNC_ALLOWED_EMAILS`, `TABBYSYNC_ALLOWED_EMAIL_DOMAINS` | — | who may sign up on first sign-in |
| `TABBYSYNC_SESSION_IDLE` | `30m` | web session idle timeout |
| `TABBYSYNC_SESSION_MAX_AGE` | `12h` | maximum web session lifetime |
| `TABBYSYNC_REAUTH_MAX_AGE` | `15m` | maximum age of the sign-in required to issue a token |
| `TABBYSYNC_MAX_CONFIG_BYTES` | `2097152` (2 MiB) | maximum config size |
| `TABBYSYNC_MAX_CONFIGS_PER_USER` | `100` | maximum number of configs per user |
| `TABBYSYNC_REVISIONS_KEEP_MIN` | `20` | number of latest revisions always kept |
| `TABBYSYNC_REVISIONS_MAX_AGE` | `720h` | older revisions beyond the minimum are removed |
| `TABBYSYNC_REVISIONS_HARD_CAP` | `500` | maximum number of revisions per config |
| `TABBYSYNC_SOFT_DELETE_RETENTION` | `720h` | how long deleted configs are kept before permanent removal |
| `TABBYSYNC_RATE_IP_RPS`, `_BURST` | `20`, `60` | request rate limit per address |
| `TABBYSYNC_RATE_AUTH_FAIL_PER_MIN`, `_BURST` | `10`, `10` | failed authentication limit per address |
| `TABBYSYNC_RATE_DEVICE_RPS`, `_BURST` | `5`, `30` | request rate limit per device |
| `TABBYSYNC_LOG_LEVEL` | `info` | log level (`debug`, `info`, `warn`, `error`) |

## Development

Go 1.26 or newer is required. Integration tests need Docker (PostgreSQL is started via testcontainers) or `TABBYSYNC_TEST_DATABASE_URL` pointing to a server where the user may create databases.

```bash
go test ./...
```

Without a database the integration tests are skipped; `TABBYSYNC_REQUIRE_DB=1` turns the skip into a failure.

To try the web UI locally with a test OIDC provider (served at http://localhost:18080):

```bash
TABBYSYNC_PREVIEW=1 go test -run TestPreview -timeout 15m ./internal/httpapi
```

Project layout:

```
cmd/syncd/           server and CLI
internal/auth/       device tokens
internal/config/     settings
internal/configs/    configs and revisions
internal/crypto/     envelope encryption and keyring
internal/httpapi/    HTTP: API v1/v2, web UI, OIDC, middleware
internal/store/      PostgreSQL access and migrations
deploy/              Docker Compose, setup, backup and restore scripts
```

CI runs `golangci-lint` (including gosec), `govulncheck`, tests with `-race` and fuzzing of the validation code; for tags it builds an image with an SBOM, provenance and a cosign signature.

## License

[MIT](LICENSE)
