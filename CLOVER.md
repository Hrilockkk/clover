# Clover — система сканирования игроков

Документация по подсистеме **Clover Scan**: как она устроена, как работает и
как развернуть её на сайте. Всё необходимое лежит в этой папке.

```
clover/
├── CLOVER.md                  ← этот файл
├── clover.exe                 ← сканер (Windows x64, ~6.9 МБ), отдаётся игроку
├── backend/
│   ├── scans.js               ← ядро: ссылки, криптография, хранение сканов
│   ├── scans.routes.js        ← HTTP-эндпоинты /api/scans/* (готовый модуль)
│   └── scans.sql              ← схема таблиц (PostgreSQL + SQLite)
└── frontend/
    ├── scans.html             ← админская страница /scans (ссылки + результаты)
    ├── scan-player.html       ← страница игрока /scan?id=…
    ├── js/session.js          ← хелпер сессии для scans.html
    └── images/iconhtml.png    ← favicon страниц
```

---

## 1. Что это такое

Clover — подсистема проверки игрока на его компьютере:

1. Админ на странице `/scans` создаёт **одноразовую ссылку** (TTL 10 минут).
2. Игрок открывает `/scan?id=<id>` и скачивает персональный `clover.exe`,
   внутрь которого сервер **встроил конфиг именно этой ссылки**.
3. Игрок запускает файл от имени администратора, при необходимости вводит
   выданный пароль. Сканер проверяет систему и **сам отправляет результат**
   на сервер (POST с шифрованным payload), после чего самоуничтожается.
4. Если авто-отправка не удалась — рядом с exe создаётся файл `scan_*.enc`,
   который игрок перетаскивает в dropzone на той же странице `/scan`.
5. Админ видит результат на `/scans` → клик по скану открывает полноэкранную
   страницу `/scans/<id>` (вкладки: обзор, совпадения, удалённое, папки, сеть,
   amcache, shellbags — полный листинг BagMRU со слотами и датами, appdata, USB,
   prefetch, shimcache, bam, процессы, драйверы, «Очистка» — ini клинера на диске
   и в USN + пересоздание $UsnJrnl после загрузки, «Сервисы» — статус критичных
   служб) с поиском и сортировкой в каждой таблице; поиск по SteamID/HWID/нику.

---

## 2. Компоненты и как они связаны

| Компонент | Файл | Роль |
|---|---|---|
| Сканер | `clover.exe` | Windows-бинарь (PE x64). Читает конфиг из собственного «хвоста», сканирует ПК, шифрует и отправляет результат, самоудаляется |
| Ядро | `backend/scans.js` | CRUD ссылок (файлы `data/scans/links/*.json`, TTL 10 мин), AES-256-GCM шифрование конфига/payload, сборка exe «под ссылку», хранение сканов через DB-слой |
| Роуты | `backend/scans.routes.js` | Все эндпоинты `/api/scans/*` с доступом, rate-limit и логированием |
| БД | `backend/scans.sql` | Таблица `panel_scans` / `scans` (JSON payload + индексные поля); сигнатуры — в настройках БД (ключ `signatures`) |
| Админ-UI | `frontend/scans.html` + `frontend/scan.html` | Создание/удаление ссылок, готовые CMD/PowerShell one-liner'ы, список сканов; полноэкранная страница скана `/scans/<id>` со всеми вкладками (включая «Очистка» и «Сервисы»), поиском и сортировкой |
| Сигнатуры-UI | `frontend/signatures.html` | Правила контента, списки целевых имён, amcache-имена, чёрный список драйверов; просмотр всем, запись — уровень 5 |
| Player-UI | `frontend/scan-player.html` | Инструкция, кнопка скачивания, dropzone для ручной загрузки `.enc` |

---

## 3. Жизненный цикл скана (подробно)

### 3.1. Создание ссылки (админ)

`POST /api/scans/links { "note": "проверка vasya" }` → `scans.createLink()`:

```jsonc
// data/scans/links/<id>.json — срок жизни 10 минут
{
  "id": "32 hex-символа",
  "createdAt": "2026-08-05T12:00:00.000Z",
  "expiresAt": 1754404860000,          // now + 10 мин
  "note": "проверка vasya",
  "playerPassword": "K7X9PQ2M",        // 8 символов A-Z/2-9 без неоднозначных
  "adminUser": "ftu",
  "adminDisplayName": "Ftu"
}
```

В ответ админу приходят готовые артефакты:

```jsonc
{
  "link": { … },
  "downloadUrl":    "https://site/api/scans/download/<id>?p=<пароль>",
  "downloadUrlB64": "https://site/api/scans/download-b64/<id>?p=<пароль>",
  "exeName": "cl_a1b2c3d4.exe",         // случайное имя (анти-репутация)
  "cmdCommand": "curl -sL \"…download…\" -o \"%TEMP%\\cl_….exe\" && \"%TEMP%\\cl_….exe\" && del /f …",
  "psCommand":  "powershell -c \"$r=iwr …; проверка PE-заголовка; запуск; del\""
}
```

- **cmdCommand** — простой вариант: скачать бинарь в `%TEMP%`, запустить, удалить.
- **psCommand** — вариант через `download-b64`: скачивает JSON `{base64, name, size}`,
  проверяет PE-заголовок (`MZ`) и архитектуру x64, потом запускает. Нужен, когда
  CDN/фильтр перед сайтом подменяет сырой бинарный ответ HTML-челленджем.

### 3.2. Встраивание конфига в clover.exe

При скачивании сервер **не отдаёт исходный файл**, а собирает новый
(`scans.buildEmbeddedScanner`):

```
┌──────────────────────────┐
│  исходный clover.exe     │  (читается с диска: CLOVER_EXE_PATH или ./clover.exe)
├──────────────────────────┤
│  CONFIG_MARKER           │  16 байт ASCII: xK9pL2mQ5vX8wR4t
├──────────────────────────┤
│  длина шифротекста       │  4 байта UInt32 LE
├──────────────────────────┤
│  AES-256-GCM(конфиг)     │  IV(12) ‖ ciphertext ‖ authTag(16)
└──────────────────────────┘
```

Зашифрованный конфиг:

```jsonc
{
  "scanId": "<id ссылки>",
  "uploadUrl": "https://site/api/scans/upload/<id>",
  "playerPassword": "K7X9PQ2M",
  "adminUser": "ftu",
  "adminDisplayName": "Ftu",
  // Актуальные сигнатуры со страницы «Сигнатуры» — вшиваются при скачивании
  // и заменяют встроенные дефолты сканера:
  "rules":           [ { "min": 9437184, "max": 15728640, "pattern": "Gentee Launcher" } ],
  "targetDirNames":  [ "XONE", "Memesense" ],
  "targetFileNames": [ "token.ms", "nl.log" ],
  "amcacheExeNames": [ "exloader.exe" ],
  "driverBlacklist": [ "iqvw64e.sys", "capcom.sys" ]
}
```

- Ключ AES-256-GCM **зашит в `backend/scans.js`** (`CONFIG_KEY`, обфусцирован
  разбиением base64-строки) и такой же ключ зашит в бинарь сканера.
  ⚠️ Менять ключ можно только синхронно с пересборкой clover.exe.
- `uploadUrl` строится из origin'а запроса (`x-forwarded-proto/host`) —
  поэтому сайт должен отдавать правильный внешний хост (см. раздел 6).

### 3.2а. Сигнатуры (страница «Сигнатуры»)

Правила поиска больше не зашиты в бинарь: сервер при каждом скачивании
вшивает в exe актуальный конфиг из БД (`scans.getSignatures()` → ключ
`signatures` в настройках; если не сохранён — `DEFAULT_SIGNATURES` в
`backend/scans.js`, зеркало дефолтов сканера). Управление:

- **rules** — контентные правила: `pattern` (байтовая строка) или `sha256`
  (точный хэш), диапазон размеров `min`/`max` в байтах, флаги `utf16`
  (искать и UTF-16LE/BE формы) и `checkPath` (матч по пути, без чтения).
- **targetDirNames** — имена папок, сразу попадающие в отчёт.
- **targetFileNames** — точные имена файлов на любом диске.
- **amcacheExeNames** — программы для поиска в Amcache.hve.
- **driverBlacklist** — BYOVD/злоупотребляемые драйверы (флаг `blacklist`).

Списки имён также влияют на подсветку совпадений (`matched`) в новых
коллекторах: prefetch, shimcache, bam, процессы. `GET /api/scans/signatures`
возвращает `{signatures, defaults}`; `PUT` валидирует и сохраняет
(лог `signatures_update`). Сканер применяет embedded-конфиг поверх дефолтов
(`config.ApplyEmbedded`), отсутствующие поля (null) не трогают дефолт.

Сканер при запуске находит маркер в конце собственного файла, читает длину,
расшифровывает конфиг тем же ключом и работает автономно.

### 3.3. Сканирование и отправка

Сканер собирает (по структуре, которую рендерит `scans.html`):

```jsonc
{
  "scanId": "<id>", "timestamp": 1754404800000,
  "hardware": { "hwid": "…", "hostname": "…", "username": "…", "usb": [ … ] },
  "steam": { "accounts": [ { "steamId": "7656…", "accountName": "…",
                             "mostRecent": true, "timestamp": 1750000000 } ] },
  "results":      [ { "Name", "Matched", "Path", "Modified", "Deleted" } ],  // найденные совпадения (читы/сигнатуры)
  "deletedFiles": [ { "Name", "Path", "Deleted" } ],
  "deletedDirs":  [ { "Name", "Path", "Deleted" } ],
  "dirs":         [ { "Name", "Path", "Modified" } ],
  "namedFiles":   [ { "Name", "Path", "Modified" } ],
  "cs2Conns":     [ { "RemoteAddress", "RemotePort", "State", "LocalAddress", "LocalPort" } ],
  "cs2Rwx":       [ … ],               // RWX-участки памяти в процессе CS2
  "amcache":      [ { "Name", "Path", "LastRun" } ],
  "shellbags":    [ { "Name", "Path", "LastAccess" } ],
  "appData":      [ { "FileName", "DirPath", "DirModified", "FileModified" } ],
  "usb":          [ … ],
  "prefetch":     [ { "name", "path", "size", "created", "modified", "matched" } ],   // Prefetch-запуски (mtime ≈ last run)
  "shimcache":    [ { "path", "modified", "executed", "matched" } ],                 // AppCompatCache Win10/11
  "bam":          [ { "source": "bam|dam", "userSid", "path", "lastRun", "matched" } ],
  "processes":    [ { "pid", "name", "path", "matched" } ],                          // снапшот процессов
  "drivers":      [ { "name", "imagePath", "kind": "kernel|fs", "keyModified", "flag": "blacklist|recent" } ]
}
```

- Тело запроса: `{"encrypted": base64}` — тот же AES-256-GCM (IV‖ct‖tag).
  Plain JSON тоже принимается (legacy/standalone).
- После успешной загрузки **ссылка удаляется** — повторно использовать нельзя.
- Если POST не удался — сканер пишет `scan_*.enc` рядом с собой; его
  перетаскивают в dropzone на `/scan` → `POST /api/scans/upload-manual/:id`.

### 3.4. Хранение результата

`scans.saveRecord()` → DB-слой кладёт запись в `panel_scans`/`scans`:
полный JSON в `payload` + выделенные поля для поиска (`hwid`, `hostname`,
`username`, CSV `steam_ids`/`steam_names`, `admin_user`). При первом старте
выполняется миграция старых файлов из `data/scans/records/*.json` в БД.

---

## 4. API эндпоинты

| Метод | Путь | Доступ | Назначение |
|---|---|---|---|
| GET | `/api/scans/links` | scan-доступ¹ | Список живых ссылок |
| POST | `/api/scans/links` | scan-доступ¹ | Создать ссылку `{note}` → `link`, `cmdCommand`, `psCommand`, URL'ы |
| DELETE | `/api/scans/links/:id` | scan-доступ¹ | Удалить ссылку |
| GET | `/api/scans/list` | scan-доступ¹ | Все сканы (DESC по времени) |
| GET | `/api/scans/search?q=` | scan-доступ¹ | Поиск по SteamID / HWID / hostname / нику / админу |
| GET | `/api/scans/view/:id` | scan-доступ¹ | Полный JSON одного скана |
| GET | `/api/scans/signatures` | scan-доступ¹ | Актуальные сигнатуры + встроенные дефолты |
| PUT | `/api/scans/signatures` | level = 5 | Сохранить сигнатуры `{signatures: {rules, targetDirNames, targetFileNames, amcacheExeNames, driverBlacklist}}` |
| GET | `/api/scans/download/:id?p=<pwd>` | публичный² | clover.exe со встроенным конфигом (octet-stream) |
| GET | `/api/scans/download-b64/:id?p=<pwd>` | публичный² | То же в JSON `{base64, name, size}` — обход CDN |
| POST | `/api/scans/upload/:id` | публичный³ | Приём результата от сканера |
| POST | `/api/scans/upload-manual/:id` | публичный³ | Ручная загрузка `.enc` со страницы игрока |
| GET | `/api/scans/page/:id` | публичный | JSON-описание ссылки для `/scan?id=` |

¹ **scan-доступ**: любой авторизованный пользователь панели — если учётная
запись есть в `/admin`, доступ уже есть.

² Пароль в query `?p=`; rate-limit **10 запросов/мин с IP**.
³ Авторизация по самому id ссылки (32 hex); rate-limit **10 запросов/мин с IP**.

---

## 5. Безопасность (что уже встроено)

- **Одноразовые ссылки**: TTL 10 минут, авто-удаление при чтении/листинге,
  удаление после загруженного скана.
- **Пароль игрока**: 8 символов, требуется и при скачивании (`?p=`), и при
  запуске сканера (зашит в конфиг).
- **AES-256-GCM**: конфиг внутри exe и upload-пayload зашифрованы одним ключом;
  подделать payload без ключа нельзя (authTag).
- **Rate-limit**: 10/мин на download и upload с одного IP.
- **Случайное имя файла** (`cl_<8 hex>.exe`) — против репутационных сигнатур AV.
- **PE-проверка в psCommand** — игрок не выполнит подменённый/HTML-файл.
- **Доступ по сессии**: сканы доступны любому авторизованному пользователю панели.
- **Тихий auto-mode**: игрок не видит результатов скана, URL сервера и
  упоминания самоудаления; нейтральная ошибка при детекте отладчика/VM.
- **Retry аплоада**: до 4 попыток с backoff (0/2/5/10 с), успех = HTTP 2xx.
- **Self-destruct с retry**: bat повторяет удаление до 15 раз (антивирус может
  держать файл); удаляется и сам bat.
- Все действия админов логируются (`scan_link_create`, `scan_link_delete`,
  `signatures_update`).

---

## 6. Как залить Clover на сайт (пошагово)

### Шаг 1. Файлы

```
your-site/
├── clover.exe                    ← из этой папки (корень или задайте CLOVER_EXE_PATH)
├── src/
│   └── scans.js                ← backend/scans.js
│   └── scans.routes.js         ← backend/scans.routes.js
├── public/
│   ├── scans.html              ← frontend/scans.html      (защищённая страница)
│   ├── scan-player.html        ← frontend/scan-player.html (публичная страница)
│   ├── js/session.js           ← нужен scans.html
│   └── images/iconhtml.png     ← favicon
└── data/scans/links/           ← создастся само (ссылки)
```

### Шаг 2. База данных

Выполните `backend/scans.sql` (таблица сканов).
DB-слой сайта должен реализовать методы, которые дергает `scans.js`:

```js
saveScanRecord(rec)            // upsert по rec.scanId; индекс-поля — см. extractScanFields в doc
getScanRecord(id)              // -> объект | null
listScanRecords()              // -> [объекты], timestamp DESC
searchScanRecords(q)           // LIKE по hwid/hostname/username/steam_ids/steam_names/admin_*
```

Поле `payload` — это `JSON.stringify(rec)` целиком; индексные колонки
заполняются из `rec.hardware` и `rec.steam.accounts` (см. `scans.sql`).

### Шаг 3. Подключение роутов

```js
const scans = require('./src/scans');              // поправьте require('./database') внутри на ваш DB-слой
const handleScans = require('./src/scans.routes')({
    scans,
    getSessionFromReq,   // async (req) => session|null  (Bearer или cookie, как у вас)
    sendJson, sendError, // ваши хелперы ответов
    getClientIp,         // req -> '1.2.3.4' (учитывайте x-forwarded-for)
    safeLog              // опционально: аудит действий
});

// plain http сервер:
const parsedUrl = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
if (parsedUrl.pathname.startsWith('/api/scans/')) {
    if (await handleScans(req, res, parsedUrl)) return;
}
```

> В `scans.js` вверху стоит `require('./database')` — укажите там ваш модуль,
> экспортирующий функции из шага 2. Также при старте вызовите `await scans.init()`
> (создаст каталоги и мигрирует старые файловые записи в БД).

### Шаг 4. Страницы

| URL | Файл | Доступ |
|---|---|---|
| `/scans` | `public/scans.html` | только с валидной сессией (серверно редиректить на логин, как другие защищённые страницы) |
| `/scan?id=<id>` | `public/scan-player.html` | публичная |

`scans.html` использует `localStorage.user.sessionToken` (через `js/session.js`)
и `GET /api/me` для бейджа пользователя — оставьте как есть, если у вас та же
модель сессии; иначе поправьте функцию `authHeaders()` внутри файла.

### Шаг 5. Бинарь и окружение

- Положите `clover.exe` рядом с сервером **или** задайте `CLOVER_EXE_PATH=/abs/path/clover.exe`.
- Origin, из которого строится `uploadUrl`, берётся из `x-forwarded-proto` +
  `x-forwarded-host` (или `host`). За прокси (Traefik/Nginx/Cloudflare)
  убедитесь, что эти заголовки пробрасываются — иначе сканер будет стучаться
  на внутренний адрес.
- Тело POST до 8 МБ (`MAX_REQUEST_BODY_BYTES` в `scans.routes.js`) — payload
  с prefetch/shimcache/bam/процессами/драйверами заметно больше старого;
  следите за лимитом прокси (`client_max_body_size` ≥ 8m).

### Шаг 6. Проверка

1. Войдите любым пользователем панели → `/scans`.
2. Создайте ссылку → получите `cmdCommand`/`psCommand` и ссылку `/scan?id=…`.
3. Откройте `/scan?id=…` в другом браузере → скачайте exe → запустите от
   администратора → введите пароль из ответа API.
4. Дождитесь загрузки → скан появится в списке «Сканы»; ссылка исчезнет.

---

## 7. Подводные камни

- **CDN/фильтры перед сайтом**: если бинарь при скачивании превращается в
  HTML-страницу — используйте `download-b64` + `psCommand` (поэтому он и есть).
- **Антивирусы**: clover.exe — инструмент сканирования системы, AV может
  ругаться. Случайное имя файла и встроенный конфиг частично помогают,
  но будьте готовы объяснять игрокам про исключения.
- **HTTPS**: `uploadUrl` наследует протокол запроса; если админ зашёл по
  `https`, сканер отправит по `https` — не ломайте сертификат на домене.
- **Ключ шифрования**: `CONFIG_KEY` в `scans.js` должен совпадать с ключом в
  бинаре. Чужой/пересобранный clover.exe с другим ключом работать не будет.
- **Не храните ссылки дольше 10 минут**: если игрок не успевает — создайте новую.
- **8 МБ лимит тела**: обрезанный проксей upload придёт как `DECRYPT_ERROR`.

---

*Извлечено из проекта VibeCoding (src/scans.js, src/http/handler.js,
public/scans.html, public/scan-player.html). Логика перенесена без изменений.*
