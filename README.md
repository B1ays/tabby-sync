# tabby-sync

Сервер синхронизации конфигов для настольного [Tabby](https://github.com/Eugeny/tabby). Совместим с API `/api/1` из Tabby Web, поэтому клиент работает без изменений: в настройках Tabby → Config sync укажите адрес сервера (`https://…`) и токен устройства.

Готовы этапы 1–7 плана: каркас, хранилище с ревизиями, шифрование, токены устройств, совместимый API v1, веб-интерфейс со входом через OIDC и строгий API v2 для своих клиентов. Аудита и метрик пока нет.

## Чем отличается от Tabby Web

| | Tabby Web | tabby-sync |
|---|---|---|
| Хранение | открытый текст | AES-256-GCM, отдельный ключ на каждую ревизию, ключи обёрнуты KEK (envelope) |
| Привязка шифртекста | — | AAD = пользователь, конфиг, ревизия: перенос строки в БД обнаруживается при расшифровке |
| Конкурентные записи | последняя затирает | блокировка строки, каждая запись — новая ревизия; `If-Match` даёт `412` |
| История | нет | ревизии хранятся по политике `REVISIONS_*`; строки неизменяемы (триггер) |
| Токен | один на пользователя, хранится открыто, есть `?auth_token=` | по токену на устройство, хранится только SHA-256, права, срок, отзыв; только заголовок |
| Права БД | — | миграции под владельцем схемы, сервер — только DML |
| Веб-вход | OAuth через social_django | OIDC Authorization Code + PKCE (S256), `state` и `nonce`, одноразовый поток, привязанный к cookie браузера |
| Сессии | Django | серверные: в cookie `__Host-` только случайный ID, в БД его SHA-256; 30 мин бездействия / 12 ч максимум; новый ID при каждом входе |
| CSRF | Django | `http.CrossOriginProtection` (Sec-Fetch-Site / Origin) + токен формы, выведенный из секрета сессии |

Неизменный `content` не создаёт ревизию и не сдвигает `modified_at`, чтобы другие устройства не перекачивали конфиг впустую.

## API v2

Для собственных клиентов, которые умеют обрабатывать конфликты. Аутентификация та же: `Authorization: Bearer <токен устройства>`.

| Запрос | Назначение |
|---|---|
| `GET /api/2/configs` | список: id, name, version, revision, size, `content_digest`, даты |
| `POST /api/2/configs` | создать (`{"name","content"}`); **`Idempotency-Key` обязателен** |
| `GET /api/2/configs/{id}` | метаданные, `ETag` |
| `PATCH /api/2/configs/{id}` | `{"name","last_used_with_version"}`; **`If-Match` обязателен** |
| `DELETE /api/2/configs/{id}` | **`If-Match` обязателен** |
| `GET /api/2/configs/{id}/content` | содержимое как `application/yaml`, `Repr-Digest`, `If-None-Match` → `304` |
| `PUT /api/2/configs/{id}/content` | загрузить содержимое; **`If-Match` обязателен**, `Content-Digest` проверяется |
| `GET /api/2/configs/{id}/revisions` | история, новые сверху |
| `GET /api/2/configs/{id}/revisions/{rev}/content` | содержимое ревизии, `Repr-Digest` |
| `POST /api/2/configs/{id}/revisions/{rev}/restore` | сделать ревизию текущей (новой ревизией); **`If-Match` обязателен** |

- **Конкурентность.** `ETag` вида `"v12"` меняется при любом изменении конфига. Без `If-Match` изменение отклоняется с `428`, с устаревшим — `412` и текущим `ETag` в ответе; `If-Match: *` не принимается.
- **Целостность.** `Repr-Digest: sha-256=:…:` (RFC 9530) — SHA-256 содержимого; тот же дайджест в поле `content_digest`. Клиент может прислать `Content-Digest` или `Repr-Digest` (sha-256 / sha-512) с загрузкой — при несовпадении `400`, ничего не записывается. `Content-Encoding` не поддерживается (`415`).
- **Идемпотентность.** `Idempotency-Key: "…"` (1–255 видимых ASCII) принимается всеми изменяющими запросами, для `POST` обязателен. Ответ сохраняется 24 ч вместе с изменением, в одной транзакции. Повтор возвращает тот же ответ с `Idempotent-Replayed: true` (в том числе после потерянного ответа на `PUT`, который иначе получил бы `412`); тот же ключ с другим запросом — `422`. Ответы с ошибкой клиента (4xx) тоже запоминаются, ошибки сервера (5xx) — нет, такой запрос можно повторить. Ключи у каждого пользователя свои.

## Развёртывание (VPS с Docker)

Нужны Linux, Docker с плагином compose и cron. `setup.sh` создаёт секреты и ключ, собирает образ и ставит задачи в `/etc/cron.d/tabby-sync`; повторный запуск ничего не перезаписывает.

```bash
cd deploy
sudo ./setup.sh sync.example.com
```

```bash
sudo docker compose up -d --wait
```

```bash
docker compose run --rm syncd user add alice
```

```bash
docker compose run --rm syncd token create -user alice -name laptop
```

Токен печатается один раз. Caddy получает сертификат Let's Encrypt; для этого DNS-запись домена должна указывать на сервер, порты 80/443 — открыты.

**Вход через веб (OIDC).** Подходит любой провайдер OpenID Connect (Google, Microsoft Entra ID, GitLab, Keycloak, Authentik, Auth0…). GitHub — не OIDC и не поддерживается. Зарегистрируйте у провайдера приложение с redirect URI `https://<домен>/auth/<id>/callback`, положите client secret в файл и добавьте в `deploy/.env`:

```
TABBYSYNC_OIDC_PROVIDERS=google
TABBYSYNC_OIDC_GOOGLE_NAME=Google
TABBYSYNC_OIDC_GOOGLE_ISSUER=https://accounts.google.com
TABBYSYNC_OIDC_GOOGLE_CLIENT_ID=...apps.googleusercontent.com
TABBYSYNC_OIDC_GOOGLE_CLIENT_SECRET_FILE=/run/oidc/google
TABBYSYNC_ALLOWED_EMAILS=me@gmail.com
```

```bash
sudo sh -c 'umask 077; cat > secrets/oidc/google && chown 65532:65532 secrets/oidc/google'
```

Пользователь определяется парой (issuer, subject), а не email. Email используется один раз, при первом входе, и только если провайдер подтвердил его (`email_verified`):
- если администратор завёл пользователя с этим email (`syncd user add alice -email alice@example.com`), вход привязывается к нему;
- иначе пользователь создаётся, только если email есть в `TABBYSYNC_ALLOWED_EMAILS` или его домен в `TABBYSYNC_ALLOWED_EMAIL_DOMAINS`;
- в остальных случаях вход отклоняется.

Выпуск токена в вебе требует свежего входа (`REAUTH_MAX_AGE`, 15 мин). Повторный вход запрашивается с `max_age=0`, и провайдер должен вернуть `auth_time` не раньше начала этого входа; иначе уже открытая сессия у провайдера (SSO) засчитывалась бы как повторный ввод пароля.

**Ключи.** `deploy/secrets/keyring` нужно хранить отдельно от бэкапов базы. Без него данные не расшифровать, а лежащий рядом с бэкапом он делает шифрование бесполезным. Сервер не запустится, если keyring доступен кому-то кроме владельца (права должны быть 0400 или 0600).

**Ротация KEK.**

1. Выпустить новый ключ и добавить строку в `secrets/keyring`:
   ```bash
   docker compose run --rm syncd keys generate -id k202701
   ```
2. Указать `TABBYSYNC_KEK_PRIMARY=k202701` в `.env` и перезапустить сервер:
   ```bash
   docker compose up -d syncd
   ```
3. Переобернуть ключи данных существующих ревизий:
   ```bash
   docker compose run --rm syncd keys rewrap
   ```
4. Удалить старую строку из keyring.

**Бэкапы.** Каждый день в 03:15 cron запускает `deploy/backup.sh`:
1. `pg_dump` базы и ролей в `deploy/backups/`;
2. восстановление дампа в отдельную временную базу и сверка версии схемы;
3. `syncd verify` расшифровывает каждую ревизию восстановленной копии текущим keyring;
4. только после этого файл получает имя `tabbysync-<время>.dump` и `.sha256`, а время пишется в `backups/LAST_SUCCESS`. Дамп, не прошедший проверку, остаётся `*.unverified`.

Хранятся дампы за `TABBYSYNC_BACKUP_KEEP_DAYS` (14) дней, но не меньше `TABBYSYNC_BACKUP_KEEP_MIN` (7) последних подтверждённых. Вывод — в syslog (`journalctl -t tabby-sync-backup`).

Что нужно сделать самому:
- **Следить за `backups/LAST_SUCCESS`.** Если файлу больше суток, бэкап не работает; оповещений сервис пока не шлёт.
- **Копировать `backups/` за пределы сервера** (restic, rclone, borg). Дампы с одного диска не спасут от его потери.
- **Хранить `secrets/keyring` и `.env` отдельно от дампов.** Без ключа дампы не расшифровать, а ключ рядом с ними делает шифрование бесполезным.

**Восстановление после аварии.** На новом сервере: `setup.sh`, затем вернуть `secrets/` (как минимум `keyring`) и `.env` из надёжного места, положить дамп с его `.sha256` в `backups/` и выполнить:

```bash
sudo ./restore.sh backups/tabbysync-<время>.dump
```

Скрипт останавливает сервер, заменяет базу дампом, проверяет расшифровку (`syncd verify`) и поднимает всё обратно. Неподтверждённые дампы он не принимает. Сценарий «удалили том базы — восстановились из дампа» проверен.

**Обслуживание.** В 03:45 cron запускает `syncd purge`: он окончательно стирает конфиги, удалённые раньше `SOFT_DELETE_RETENTION`, а также истёкшие сессии, брошенные попытки входа и ключи идемпотентности. Проверить целостность рабочей базы можно в любой момент:

```bash
sudo docker compose run --rm --no-deps syncd verify
```

**Ресурсы.** Логи контейнеров ограничены (10 МБ × 5 файлов на сервис). Лимиты памяти: Postgres 512 МБ, syncd 256 МБ (`GOMEMLIMIT` 200 МиБ), Caddy 128 МБ. У `syncd` есть healthcheck (`syncd health` проверяет `/readyz`, то есть и базу); Caddy стартует только после него.

## Команды

```
syncd serve
syncd migrate up|down|status|version
syncd user add <name> [-email addr]
syncd user list|disable|enable <name>
syncd token create -user U -name N [-scopes configs:read,configs:write,user:read] [-ttl 8760h]
syncd token import-legacy -user U -name N      # токен Tabby Web со stdin
syncd token list -user U
syncd token revoke -user U (-id DEVICE | -all)
syncd keys generate -id ID
syncd keys rewrap
syncd purge
syncd verify [-database NAME]                  # расшифровать все ревизии, проверить целостность
syncd health                                   # healthcheck контейнера
```

Права токена: `configs:read`, `configs:write`, `user:read`, `user:write`. Отключение пользователя (`user disable`) сразу аннулирует все его токены.

## Настройки (переменные окружения)

| Переменная | По умолчанию | |
|---|---|---|
| `TABBYSYNC_LISTEN` | `127.0.0.1:8080` (в образе `:8080`) | адрес |
| `TABBYSYNC_TLS_CERT_FILE` / `_KEY_FILE` | — | TLS без прокси |
| `TABBYSYNC_DATABASE_URL` / `_FILE` | — | строка подключения Postgres |
| `TABBYSYNC_KEYRING_FILE`, `TABBYSYNC_KEK_PRIMARY` | — | keyring и основной ключ |
| `TABBYSYNC_TRUSTED_PROXIES` | — | IP/CIDR прокси, которым верим в `X-Forwarded-For` |
| `TABBYSYNC_CORS_ALLOWED_ORIGINS` | `*` | API без cookie, поэтому `*` безопасен; можно сузить |
| `TABBYSYNC_MAX_CONFIG_BYTES` | 2 MiB | |
| `TABBYSYNC_MAX_CONFIGS_PER_USER` | 100 | |
| `TABBYSYNC_REVISIONS_KEEP_MIN` / `_MAX_AGE` / `_HARD_CAP` | 20 / 720h / 500 | история |
| `TABBYSYNC_SOFT_DELETE_RETENTION` | 720h | |
| `TABBYSYNC_RATE_IP_RPS` / `_BURST` | 20 / 60 | до аутентификации |
| `TABBYSYNC_RATE_AUTH_FAIL_PER_MIN` / `_BURST` | 10 / 10 | неудачные токены с IP |
| `TABBYSYNC_RATE_DEVICE_RPS` / `_BURST` | 5 / 30 | на устройство |
| `TABBYSYNC_LOG_LEVEL` | `info` | |
| `TABBYSYNC_PUBLIC_URL` | — | `https://домен`, обязателен с OIDC (в compose задаётся из `TABBYSYNC_DOMAIN`) |
| `TABBYSYNC_OIDC_PROVIDERS` | — | id провайдеров через запятую; для каждого `TABBYSYNC_OIDC_<ID>_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET` / `_FILE`, `_NAME`, `_SCOPES` |
| `TABBYSYNC_ALLOWED_EMAILS` / `_EMAIL_DOMAINS` | — | кому разрешена регистрация при первом входе |
| `TABBYSYNC_SESSION_IDLE` / `_MAX_AGE` | 30m / 12h | веб-сессии |
| `TABBYSYNC_REAUTH_MAX_AGE` | 15m | давность входа для выпуска токена |

## Разработка

```bash
go test ./...
```

Интеграционные тесты поднимают Postgres через testcontainers (нужен Docker) или берут `TABBYSYNC_TEST_DATABASE_URL`. Без БД они пропускаются; `TABBYSYNC_REQUIRE_DB=1` (стоит в CI) превращает пропуск в ошибку. Посмотреть веб-интерфейс локально с фейковым OIDC-провайдером: `TABBYSYNC_PREVIEW=1 go test -run TestPreview -timeout 15m ./internal/httpapi`, затем http://localhost:18080.

CI также запускает `golangci-lint` (с gosec), `govulncheck`, `-race`, фаззинг валидации, а для тегов собирает образ с SBOM, провенансом и подписью cosign.
