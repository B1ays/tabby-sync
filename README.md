# tabby-sync

Самостоятельно размещаемый сервер синхронизации конфигураций для терминала [Tabby](https://github.com/Eugeny/tabby).

Сервер совместим с API синхронизации Tabby Web (`/api/1`), поэтому настольный Tabby подключается к нему без доработок. Конфиги шифруются на сервере, у каждого устройства свой токен, изменения сохраняются в истории, а одновременные правки с разных устройств не теряются.

## Возможности

- **Совместимость с Tabby.** Настольный клиент синхронизируется через стандартный раздел *Settings → Config sync*.
- **Шифрование хранимых данных.** Каждая ревизия шифруется AES-256-GCM собственным ключом данных; ключи данных обёрнуты мастер-ключом (envelope encryption). Шифртекст привязан к пользователю, конфигу и ревизии, поэтому подмена строк в базе обнаруживается при расшифровке.
- **История и откат.** Каждое изменение содержимого — новая неизменяемая ревизия. Любую ревизию можно посмотреть и восстановить через веб или API.
- **Ничего не теряется при одновременной записи.** Записи в один конфиг упорядочиваются блокировкой строки. API v2 требует `If-Match` и отвечает `412`, если конфиг уже изменили.
- **Токены устройств.** У каждого устройства свой токен с правами и сроком действия; токен можно отозвать в любой момент. В базе хранится только SHA-256 токена.
- **Веб-интерфейс.** Вход через любой OpenID Connect-провайдер; управление устройствами и сессиями; просмотр и восстановление истории.
- **API v2** для собственных клиентов: обязательный `If-Match`, `Idempotency-Key`, `Repr-Digest`/`Content-Digest` (RFC 9530).
- **Готовое развёртывание.** Docker Compose с PostgreSQL и Caddy (автоматический TLS); ежедневные бэкапы с проверкой восстановления; отдельные роли базы данных; лимиты ресурсов и healthcheck.

### Отличия от Tabby Web

| | Tabby Web | tabby-sync |
|---|---|---|
| Хранение конфигов | открытым текстом | AES-256-GCM, envelope encryption, привязка к владельцу и ревизии |
| Одновременные правки | последняя запись затирает остальные | каждая запись — ревизия; `If-Match` → `412` |
| История | нет | ревизии с политикой хранения и откатом |
| Токен синхронизации | один на пользователя, хранится открыто, допускается в URL | по токену на устройство, хранится хеш, права, срок, отзыв; только в заголовке |
| Веб-вход | OAuth через social_django | OIDC Authorization Code + PKCE, `state`, `nonce` |
| Сессии и CSRF | Django | серверные сессии в cookie `__Host-`; проверка `Sec-Fetch-Site`/`Origin` и токен формы |
| Права в базе | одна роль | миграции под владельцем схемы, сервер — только чтение и запись строк |

## Быстрый старт

Нужны Linux-сервер с Docker Engine и плагином Compose v2, cron, а также домен, DNS-запись которого указывает на сервер. Порты 80 и 443 должны быть открыты: Caddy получит сертификат Let's Encrypt.

```bash
git clone <url-репозитория> /opt/tabby-sync
```

```bash
cd /opt/tabby-sync/deploy && sudo ./setup.sh sync.example.com
```

```bash
cd /opt/tabby-sync/deploy && sudo docker compose up -d --wait
```

`setup.sh` создаёт пароли базы, мастер-ключ (`secrets/keyring`) и `.env`, собирает образ и устанавливает задачи cron для бэкапов и очистки. Повторный запуск ничего не перезаписывает.

Создайте пользователя и токен для первого устройства:

```bash
cd /opt/tabby-sync/deploy && sudo docker compose run --rm syncd user add alice
```

```bash
cd /opt/tabby-sync/deploy && sudo docker compose run --rm syncd token create -user alice -name laptop
```

Токен показывается один раз. В Tabby откройте *Settings → Config sync*, укажите адрес `https://sync.example.com` и токен.

> **Сразу сохраните `secrets/keyring` и `.env` в надёжном месте отдельно от бэкапов.** Без мастер-ключа данные невозможно расшифровать, а ключ, лежащий рядом с бэкапами, делает шифрование бесполезным.

## Варианты развёртывания

### За существующим nginx

Если на сервере уже работает nginx с TLS, встроенный Caddy не нужен. Перед `docker compose up` подключите override-файл:

```bash
cd /opt/tabby-sync/deploy && sudo cp nginx/compose.override.yaml compose.override.yaml
```

Он отключает Caddy, публикует сервер только на `127.0.0.1:8080` и доверяет `X-Forwarded-For` только шлюзу Docker-сети, через которую приходит nginx. Compose загружает этот файл автоматически, поэтому его учитывают и скрипты бэкапа, и cron.

Затем добавьте сайт из [`deploy/nginx/tabby-sync.conf`](deploy/nginx/tabby-sync.conf), заменив домен и пути к сертификату. Важные настройки в нём:

- `client_max_body_size 8m` — с ограничением nginx по умолчанию (1 МБ) большие конфиги получат `413`;
- `proxy_set_header X-Forwarded-For $remote_addr` — заголовок перезаписывается, клиент не может подставить свой адрес;
- `proxy_set_header Host $host` — по нему CSRF-защита сверяет `Origin`;
- HSTS и CSP выставляет само приложение, дублировать их в nginx не нужно.

### Под путём на общем домене

Сервис можно разместить рядом с другими приложениями, например на `https://example.com/services/tabby-sync/`. Добавьте в `deploy/.env`:

```
TABBYSYNC_BASE_PATH=/services/tabby-sync
```

и вставьте в существующий блок `server { ... }` nginx фрагмент из [`deploy/nginx/tabby-sync-location.conf`](deploy/nginx/tabby-sync-location.conf). В этом режиме:

- сервер сам снимает префикс и отвечает `404` на всё вне его; ссылки, редиректы и заголовки `Location` содержат префикс;
- cookie ограничены путём `<префикс>/` и используют приставку `__Secure-` (приставка `__Host-` требует `Path=/`), поэтому другие приложения на том же домене их не получают;
- HSTS не отправляется: политикой домена управляет его nginx;
- в Tabby адрес сервера указывается с префиксом: `https://example.com/services/tabby-sync`.

В режиме с префиксом cookie можно подставить с соседних поддоменов того же домена. Если поддомены обслуживают недоверенные приложения, разместите сервис на собственном поддомене.

### Без обратного прокси

Сервер может сам принимать TLS: задайте `TABBYSYNC_TLS_CERT_FILE`, `TABBYSYNC_TLS_KEY_FILE` и `TABBYSYNC_LISTEN`.

## Вход через веб (OIDC)

Веб-интерфейс работает с любым провайдером OpenID Connect: Google, Microsoft Entra ID, GitLab, Keycloak, Authentik, Auth0 и другими. GitHub не поддерживает OIDC для входа пользователей и не подходит.

1. Зарегистрируйте у провайдера веб-приложение с redirect URI `https://<домен>[<префикс>]/auth/<id>/callback`, например `https://sync.example.com/auth/google/callback`.
2. Сохраните client secret в файл, который будет виден в контейнере как `/run/oidc/<id>`:
   ```bash
   cd /opt/tabby-sync/deploy && sudo sh -c 'umask 077; cat > secrets/oidc/google && chown 65532:65532 secrets/oidc/google'
   ```
3. Добавьте настройки в `deploy/.env`:
   ```
   TABBYSYNC_OIDC_PROVIDERS=google
   TABBYSYNC_OIDC_GOOGLE_NAME=Google
   TABBYSYNC_OIDC_GOOGLE_ISSUER=https://accounts.google.com
   TABBYSYNC_OIDC_GOOGLE_CLIENT_ID=<client-id>.apps.googleusercontent.com
   TABBYSYNC_OIDC_GOOGLE_CLIENT_SECRET_FILE=/run/oidc/google
   ```
4. Перезапустите сервер:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose up -d --wait syncd
   ```

**Кто может войти.** Пользователь определяется парой «издатель + идентификатор у провайдера», а не адресом почты. Почта используется только при первом входе и только если провайдер подтвердил её (`email_verified`):

- если администратор заранее указал этот адрес пользователю (`syncd user add alice -email alice@example.com` или `syncd user set-email alice alice@example.com`), вход привязывается к этому пользователю;
- иначе новый пользователь создаётся, только если адрес указан в `TABBYSYNC_ALLOWED_EMAILS` или его домен — в `TABBYSYNC_ALLOWED_EMAIL_DOMAINS`;
- в остальных случаях вход отклоняется.

Чтобы выпустить токен устройства через веб, нужен недавний вход (по умолчанию не старше 15 минут). Повторный вход запрашивается с `max_age=0`, и провайдер должен подтвердить его свежим `auth_time`; уже открытая сессия у провайдера не засчитывается.

## Управление

Команды выполняются в каталоге `deploy/` в виде `sudo docker compose run --rm syncd <команда>`.

```
syncd user add <name> [-email addr]          создать пользователя
syncd user set-email <name> <addr|->         задать или очистить ("-") email для привязки первого входа через веб
syncd user list                              список пользователей
syncd user disable|enable <name>             отключить или включить; отключение сразу аннулирует все токены и сессии
syncd token create -user U -name N [-scopes S] [-ttl D]
                                             выпустить токен устройства (показывается один раз)
syncd token import-legacy -user U -name N    импортировать токен Tabby Web (читается из stdin)
syncd token list -user U                     список устройств пользователя
syncd token revoke -user U (-id ID | -all)   отозвать токен(ы)
syncd keys generate -id ID                   сгенерировать строку для keyring
syncd keys rewrap                            переобернуть ключи данных под основной мастер-ключ
syncd purge                                  удалить устаревшие данные (запускается cron)
syncd verify [-database NAME]                расшифровать все ревизии и проверить целостность
syncd migrate up|down|status|version         управление схемой базы
syncd health                                 проверка готовности (используется healthcheck)
```

Права токена: `configs:read`, `configs:write`, `user:read`, `user:write`. По умолчанию токен получает права `configs:read,configs:write,user:read` и срок 1 год; `-ttl 0` выпускает бессрочный токен.

## API

### API v1 — совместимость с Tabby Web

| Запрос | Назначение |
|---|---|
| `GET /api/1/configs` | список конфигов с содержимым |
| `POST /api/1/configs` | создать конфиг |
| `GET /api/1/configs/{id}` | получить конфиг |
| `PATCH`, `PUT /api/1/configs/{id}` | изменить имя, содержимое, версию Tabby |
| `DELETE /api/1/configs/{id}` | удалить конфиг |
| `GET`, `PUT`, `PATCH /api/1/user` | профиль и активный конфиг |

Аутентификация — `Authorization: Bearer <токен устройства>`; передача токена в URL (`?auth_token=`) не поддерживается. Ответы содержат `ETag`, запись учитывает `If-Match`, если клиент его передаёт. Запись с неизменённым содержимым не создаёт ревизию и не меняет `modified_at`, поэтому другие устройства не скачивают конфиг повторно.

### API v2

API для клиентов, которые умеют обрабатывать конфликты. Аутентификация та же.

| Запрос | Назначение |
|---|---|
| `GET /api/2/configs` | список метаданных: id, name, version, revision, size, даты |
| `POST /api/2/configs` | создать конфиг (`{"name", "content"}`); требует `Idempotency-Key` |
| `GET /api/2/configs/{id}` | метаданные с `content_digest` и `ETag` |
| `PATCH /api/2/configs/{id}` | изменить `name`, `last_used_with_version`; требует `If-Match` |
| `DELETE /api/2/configs/{id}` | удалить; требует `If-Match` |
| `GET /api/2/configs/{id}/content` | содержимое (`application/yaml`) с `Repr-Digest`; `If-None-Match` → `304` |
| `PUT /api/2/configs/{id}/content` | загрузить содержимое; требует `If-Match` |
| `GET /api/2/configs/{id}/revisions` | история ревизий, новые сверху |
| `GET /api/2/configs/{id}/revisions/{rev}/content` | содержимое ревизии с `Repr-Digest` |
| `POST /api/2/configs/{id}/revisions/{rev}/restore` | сделать ревизию текущей; требует `If-Match` |

- **Конкурентность.** `ETag` вида `"v12"` меняется при любом изменении конфига. Изменение без `If-Match` отклоняется с `428`, с устаревшим значением — с `412` и текущим `ETag`. `If-Match: *` не принимается.
- **Целостность.** `Repr-Digest: sha-256=:…:` — SHA-256 содержимого. Клиент может передать `Content-Digest` или `Repr-Digest` (sha-256 или sha-512) при загрузке; при несовпадении сервер отвечает `400` и ничего не записывает.
- **Идемпотентность.** `Idempotency-Key: "…"` (1–255 видимых символов ASCII) принимается всеми изменяющими запросами и обязателен для `POST`. Ответ сохраняется на 24 часа в той же транзакции, что и изменение. Повтор запроса возвращает сохранённый ответ с заголовком `Idempotent-Replayed: true`; тот же ключ с другим запросом — `422`. Ответы с ошибкой клиента (4xx) сохраняются, ошибки сервера (5xx) — нет, такой запрос можно повторить. Ключи у каждого пользователя свои.

Ошибки возвращаются в формате `application/problem+json` (RFC 9457).

## Безопасность

**Что синхронизируется.** Tabby отправляет свой `config.yaml` целиком, кроме раздела настроек самой синхронизации: профили подключений (хосты, порты, имена пользователей, пути к ключам), настройки терминала, а также — по выбору в настройках Tabby — горячие клавиши, внешний вид и хранилище секретов (vault). Пароли, сохранённые в системном хранилище ОС, и сами файлы ключей не передаются.

**Что защищает шифрование.** Содержимое конфигов зашифровано, а мастер-ключ хранится отдельно от базы (`secrets/keyring`). Утечка дампа базы, бэкапа или диска без ключа не раскрывает содержимое. Доступ к работающему серверу (root) даёт доступ и к ключу. Чтобы секреты не были доступны даже серверу, включите в Tabby хранилище секретов (vault) или шифрование всей конфигурации: тогда на сервер попадают только данные, зашифрованные вашей мастер-фразой.

**Метаданные** — имена конфигов, время изменений, размеры ревизий, сведения об устройствах — хранятся открыто.

**Прочие меры:**
- токены и идентификаторы сессий хранятся только в виде SHA-256;
- ограничение частоты запросов по адресу клиента (IPv6 — по сети /64), по неудачным попыткам аутентификации и по устройству;
- строгие заголовки безопасности (CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`), `Cache-Control: no-store`;
- контейнер сервера (distroless) работает без root, с файловой системой только для чтения и без capabilities; база доступна только во внутренней сети Docker; сервер подключается к ней ролью, которой разрешены только чтение и запись строк;
- сервер не запускается, если файл keyring доступен кому-либо, кроме владельца.

## Эксплуатация

### Бэкапы

Каждый день в 03:15 cron запускает `deploy/backup.sh`. Он:

1. снимает дамп базы и ролей в `deploy/backups/`;
2. восстанавливает дамп во временную базу и сверяет версию схемы;
3. расшифровывает каждую ревизию восстановленной копии текущим ключом (`syncd verify`);
4. только после успешных проверок даёт дампу имя `tabbysync-<время>.dump`, создаёт файл `.sha256` и записывает время в `backups/LAST_SUCCESS`. Дамп, не прошедший проверку, остаётся с расширением `.unverified`.

Дампы хранятся 14 дней (`TABBYSYNC_BACKUP_KEEP_DAYS`), но всегда остаются хотя бы 7 последних подтверждённых (`TABBYSYNC_BACKUP_KEEP_MIN`). Эти переменные читает `backup.sh`; задать их можно в `/etc/cron.d/tabby-sync`. Журнал — в syslog: `journalctl -t tabby-sync-backup`.

Бэкап и восстановление используют общую блокировку: если одна операция уже выполняется, вторая сразу завершается с сообщением.

Рекомендуется:
- следить за возрастом `backups/LAST_SUCCESS` — если файлу больше суток, бэкап не работает;
- копировать `backups/` за пределы сервера (restic, rclone, borg);
- хранить `secrets/keyring` и `.env` отдельно от дампов.

### Восстановление

```bash
cd /opt/tabby-sync/deploy && sudo ./restore.sh backups/tabbysync-<время>.dump
```

Скрипт останавливает сервер, сохраняет текущую базу в `backups/tabbysync-prerestore-<время>.dump`, заменяет её дампом, проверяет расшифровку и запускает сервер. Принимаются только подтверждённые дампы с файлом `.sha256`. Чтобы отменить восстановление, восстановите страховочную копию тем же скриптом. Если текущую базу снять не удаётся (например, она повреждена), повторите с флагом `--no-snapshot`.

**Перенос на новый сервер:** выполните `setup.sh`, верните `secrets/` (как минимум `keyring`) и `.env` из резервной копии, положите дамп вместе с `.sha256` в `backups/` и запустите `restore.sh`.

### Ротация мастер-ключа

1. Сгенерируйте новый ключ и добавьте выведенную строку в `secrets/keyring`:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose run --rm syncd keys generate -id k202701
   ```
2. Укажите `TABBYSYNC_KEK_PRIMARY=k202701` в `.env` и перезапустите сервер:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose up -d --wait syncd
   ```
3. Переоберните ключи данных существующих ревизий:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose run --rm syncd keys rewrap
   ```
4. Удалите строку старого ключа из `secrets/keyring`.

### Обслуживание и ресурсы

Каждый день в 03:45 cron запускает `syncd purge`. Он окончательно удаляет конфиги, удалённые более 30 дней назад (`TABBYSYNC_SOFT_DELETE_RETENTION`), а также истёкшие сессии, незавершённые попытки входа и ключи идемпотентности. Проверить целостность базы можно в любой момент:

```bash
cd /opt/tabby-sync/deploy && sudo docker compose run --rm --no-deps syncd verify
```

Логи контейнеров ограничены пятью файлами по 10 МБ на сервис. Лимиты памяти: PostgreSQL — 512 МБ, сервер — 256 МБ, Caddy — 128 МБ. У сервера есть healthcheck (проверяет и доступность базы); Caddy запускается только после него.

## Обновление

Секреты, `.env`, `backups/` и `compose.override.yaml` не входят в репозиторий, поэтому обновление их не затрагивает.

1. Сделайте бэкап и пометьте текущий образ для возможного отката:
   ```bash
   cd /opt/tabby-sync/deploy && sudo ./backup.sh
   ```
   ```bash
   sudo docker tag tabby-sync:local tabby-sync:prev
   ```
2. Получите новую версию:
   ```bash
   cd /opt/tabby-sync && sudo git pull
   ```
   Без git-клона на сервере используйте архив: `git archive --format=tar.gz -o tabby-sync.tar.gz HEAD` на своей машине, затем `tar -xzf tabby-sync.tar.gz -C /opt/tabby-sync` на сервере.
3. Соберите образ, примените миграции и пересоздайте контейнеры:
   ```bash
   cd /opt/tabby-sync/deploy && sudo docker compose up -d --build --wait
   ```
4. Убедитесь, что сервер работает на новом образе:
   ```bash
   [ "$(sudo docker inspect tabby-sync-syncd-1 --format '{{.Image}}')" = "$(sudo docker image inspect tabby-sync:local --format '{{.Id}}')" ] && echo "syncd работает на свежем образе"
   ```

`docker compose restart` не подхватывает новый образ — он перезапускает существующий контейнер. Используйте `docker compose up -d`. Образ собирается из каталога установки, поэтому изменения в других копиях репозитория в него не попадут.

**Откат.** Верните предыдущий образ без пересборки:

```bash
cd /opt/tabby-sync/deploy && sudo docker tag tabby-sync:prev tabby-sync:local && sudo docker compose up -d --wait
```

Если новая версия уже применила миграции схемы, восстановите также бэкап из шага 1 с помощью `restore.sh`. Неиспользуемые образы удаляются командой `sudo docker image prune -f`.

## Настройки

Сервер настраивается переменными окружения. Для секретов можно указать путь к файлу, добавив к имени `_FILE` (например, `TABBYSYNC_DATABASE_URL_FILE`). В развёртывании через Docker Compose переменные задаются в `deploy/.env`.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `TABBYSYNC_LISTEN` | `127.0.0.1:8080` (в образе `:8080`) | адрес HTTP-сервера |
| `TABBYSYNC_TLS_CERT_FILE`, `TABBYSYNC_TLS_KEY_FILE` | — | сертификат и ключ, если сервер сам принимает TLS |
| `TABBYSYNC_DATABASE_URL` | — | строка подключения к PostgreSQL |
| `TABBYSYNC_KEYRING_FILE` | — | файл с мастер-ключами |
| `TABBYSYNC_KEK_PRIMARY` | — | идентификатор основного мастер-ключа |
| `TABBYSYNC_PUBLIC_URL` | — | внешний адрес сервиса с префиксом; обязателен для OIDC |
| `TABBYSYNC_BASE_PATH` | — | префикс пути на общем домене, например `/services/tabby-sync` |
| `TABBYSYNC_TRUSTED_PROXIES` | — | адреса или подсети прокси, которым разрешено передавать `X-Forwarded-For` |
| `TABBYSYNC_CORS_ALLOWED_ORIGINS` | `*` | разрешённые источники CORS для API |
| `TABBYSYNC_OIDC_PROVIDERS` | — | идентификаторы OIDC-провайдеров через запятую |
| `TABBYSYNC_OIDC_<ID>_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_NAME`, `_SCOPES` | `_SCOPES`: `openid,email,profile` | настройки провайдера `<ID>` |
| `TABBYSYNC_ALLOWED_EMAILS`, `TABBYSYNC_ALLOWED_EMAIL_DOMAINS` | — | кому разрешена регистрация при первом входе |
| `TABBYSYNC_SESSION_IDLE` | `30m` | срок бездействия веб-сессии |
| `TABBYSYNC_SESSION_MAX_AGE` | `12h` | максимальный срок веб-сессии |
| `TABBYSYNC_REAUTH_MAX_AGE` | `15m` | максимальная давность входа для выпуска токена |
| `TABBYSYNC_MAX_CONFIG_BYTES` | `2097152` (2 МиБ) | максимальный размер конфига |
| `TABBYSYNC_MAX_CONFIGS_PER_USER` | `100` | максимальное число конфигов у пользователя |
| `TABBYSYNC_REVISIONS_KEEP_MIN` | `20` | сколько последних ревизий хранится всегда |
| `TABBYSYNC_REVISIONS_MAX_AGE` | `720h` | более старые ревизии сверх минимума удаляются |
| `TABBYSYNC_REVISIONS_HARD_CAP` | `500` | максимальное число ревизий одного конфига |
| `TABBYSYNC_SOFT_DELETE_RETENTION` | `720h` | через сколько удалённые конфиги стираются окончательно |
| `TABBYSYNC_RATE_IP_RPS`, `_BURST` | `20`, `60` | лимит запросов с одного адреса |
| `TABBYSYNC_RATE_AUTH_FAIL_PER_MIN`, `_BURST` | `10`, `10` | лимит неудачных попыток аутентификации с одного адреса |
| `TABBYSYNC_RATE_DEVICE_RPS`, `_BURST` | `5`, `30` | лимит запросов одного устройства |
| `TABBYSYNC_LOG_LEVEL` | `info` | уровень журнала (`debug`, `info`, `warn`, `error`) |

## Разработка

Требуется Go 1.26 или новее. Для интеграционных тестов нужен Docker (PostgreSQL запускается через testcontainers) или переменная `TABBYSYNC_TEST_DATABASE_URL` с адресом базы, где разрешено создавать базы данных.

```bash
go test ./...
```

Без доступной базы интеграционные тесты пропускаются; `TABBYSYNC_REQUIRE_DB=1` превращает пропуск в ошибку.

Посмотреть веб-интерфейс локально с тестовым OIDC-провайдером (откроется на http://localhost:18080):

```bash
TABBYSYNC_PREVIEW=1 go test -run TestPreview -timeout 15m ./internal/httpapi
```

Структура проекта:

```
cmd/syncd/           сервер и CLI
internal/auth/       токены устройств
internal/config/     загрузка настроек
internal/configs/    логика конфигов и ревизий
internal/crypto/     envelope encryption и keyring
internal/httpapi/    HTTP: API v1/v2, веб-интерфейс, OIDC, middleware
internal/store/      доступ к PostgreSQL и миграции
deploy/              Docker Compose, скрипты установки, бэкапа и восстановления
```

CI запускает `golangci-lint` (включая gosec), `govulncheck`, тесты с `-race` и фаззинг валидации; для тегов собирается образ с SBOM, provenance и подписью cosign.

## Лицензия

[MIT](LICENSE)
