# Clover — система проверки игроков

Один сервис: сайт + API + база данных (SQLite, файл `data/clover.db`).
Отдельный сервер БД поднимать не нужно.

## Запуск

```bash
npm install
npm start
```

Открыть: **http://localhost:3000**

## Доступ к базе данных (DBeaver / DataGrip / pgAdmin)

**В docker-compose PostgreSQL уже включён** и торчит наружу на порту 5432.
Строка подключения — вставляешь в свой DB-клиент и шаманишь:

```
postgres://clover:<POSTGRES_PASSWORD>@<IP-сервера>:5432/clover
```

Пароль задаётся `POSTGRES_PASSWORD` в `.env` (по умолчанию `clover` — смени!).

Таблицы: `scans` (сканы: payload + поля для поиска), `users`, `sessions`, `settings`.

Безопасный вариант вместо открытого порта: в `docker-compose.yml` замени
`"5432:5432"` на `"127.0.0.1:5432:5432"` и ходи через SSH-туннель:

```bash
ssh -L 5432:localhost:5432 user@сервер
# и в DB-клиенте: postgres://clover:<pass>@localhost:5432/clover
```

Приложение само выбирает драйвер: есть `DATABASE_URL` → PostgreSQL,
нет → SQLite в `data/clover.db`.

## Деплой на свой сервер

### Вариант 1: Docker (рекомендуется) — одна команда

```bash
# 1. Склонировать (репо приватный — подставь токен github.com/settings/tokens)
git clone https://<ТОКЕН>@github.com/Hrilockkk/clover.git
cd clover

# 2. Пароли (админ панели + postgres)
echo "ADMIN_PASSWORD=$(openssl rand -hex 8)" > .env
echo "POSTGRES_PASSWORD=$(openssl rand -hex 12)" >> .env

# 3. Поднять (приложение + PostgreSQL)
docker compose up -d --build
```

Готово: сервис на порту **3000**, PostgreSQL на **5432** (строка подключения —
в разделе «Доступ к базе данных»). Данные — в named volumes, переживают
пересборку. Логи: `docker compose logs -f`.
Обновление: `git pull && docker compose up -d --build`.

### Вариант 2: Без Docker (bare metal, Ubuntu/Debian)

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt install -y nodejs git
git clone https://<ТОКЕН>@github.com/Hrilockkk/clover.git /opt/clover
cd /opt/clover && npm ci --omit=dev
cp .env.example .env && nano .env   # сменить ADMIN_PASSWORD
npm start                           # или systemd ниже
```

Автозапуск через systemd (`/etc/systemd/system/clover.service`):

```ini
[Unit]
Description=Clover Scan
After=network.target

[Service]
WorkingDirectory=/opt/clover
ExecStart=/usr/bin/node server.js
Restart=always
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now clover
```

### За Nginx (домен + HTTPS)

```nginx
server {
    listen 80;
    server_name scan.example.com;
    client_max_body_size 10m;         # upload скана до 8 МБ, с запасом

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

`X-Forwarded-*` обязательны: из них строится `uploadUrl`, на который сканер
шлёт результат. HTTPS повесь через `certbot --nginx` — если панель открыта по
https, сканер тоже будет слать по https.

| Страница | URL | Доступ |
|---|---|---|
| Лендинг | `/` | публичная |
| Вход | `/auth` | публичная |
| Сканы (ссылки + результаты) | `/scans` | после входа |
| Сигнатуры (правила поиска сканера) | `/signatures` | просмотр всем, запись — уровень 5 |
| Админ-панель (пользователи, доступы, пароли) | `/admin` | уровень 5 |
| Страница игрока | `/scan?id=…` | публичная |

Если в `.env` заданы **ADMIN_USERNAME + ADMIN_PASSWORD** — этот админ
создаётся автоматически, а при повторных запусках пароль **синхронизируется**
(удобно для сброса: поменял в `.env` → перезапустил → вошёл). Без переменных
на пустой базе создаётся **admin / admin** (уровень 5).

```bash
# Windows (PowerShell)
$env:ADMIN_USERNAME="myadmin"; $env:ADMIN_PASSWORD="strongpass"; npm start

# Linux
ADMIN_USERNAME=myadmin ADMIN_PASSWORD=strongpass npm start
```

Порт: `PORT=8080 npm start` (по умолчанию 3000).

## Пользователи

Веб-интерфейс — страница **`/admin`** (только уровень 5): создание
пользователей, уровни доступа, точечный доступ к сканам, сброс паролей
(с завершением всех сессий), кик и удаление. Нельзя удалить/понизить самого
себя и последнего пользователя уровня 5.

CLI-вариант (удобно для первоначальной настройки):

```bash
npm run adduser -- <логин> <пароль> [уровень 1..5]
# пример: npm run adduser -- moderator pass123 2
```

Доступ к `/scans`: любой авторизованный пользователь панели — если учётная
запись есть в `/admin`, доступ уже есть.

## Как это работает

1. Админ на `/scans` создаёт одноразовую ссылку (TTL 10 минут).
2. Игрок открывает `/scan?id=…` и скачивает персональный `clover.exe` —
   сервер встраивает в него зашифрованный конфиг именно этой ссылки
   (включая актуальные сигнатуры со страницы «Сигнатуры»).
3. Игрок запускает файл от имени администратора, вводит выданный пароль.
   Сканер проверяет систему и сам отправляет результат (AES-256-GCM),
   после чего самоуничтожается.
4. Если авто-отправка не удалась — рядом создаётся `scan_*.enc`, его
   перетаскивают в dropzone на странице `/scan`.
5. Админ видит результат на `/scans`: обзор с авто-вердиктом, совпадения,
   удалённое, папки, сеть, amcache, shellbags, appdata, USB, prefetch,
   shimcache, bam, **запуски** (UserAssist, RecentApps, AppSwitched, MuiCache,
   AppCompat Store, RunMRU, ComDlg32, PCA — 8 независимых источников),
   таймлайн (единая хронология всех артефактов), USN (журнал $UsnJrnl как в
   JournalTrace — все события файлов с поиском), процессы, окна (ESP-оверлеи),
   драйверы (blacklist + неподписанные), очистку (ini клинеров,
   fsutil/wevtutil, wipe USN), сервисы. Запуск из-под VM/песочницы не прерывает
   скан, а попадает в отчёт флажками. Поиск — по SteamID / HWID / нику.

## Новые возможности панели

- **Авто-вердикт** — эвристический скоринг (сигнатуры, клинеры, BYOVD,
  неподписанные драйверы, wipe USN, VM-флаги…): бейдж «чисто / подозрительно /
  находки» прямо в списке сканов.
- **AI-анализ** — кнопка на странице скана; дайджест уходит во внешний LLM
  (OpenAI-совместимый), вердикт с обоснованием сохраняется.
- **Уведомления** — Telegram-бот и/или Discord webhook при загрузке скана.
- **Страница «Настройки»** (`/settings`, уровень 5) — AI (API URL, ключ,
  модель), Telegram/Discord, публичный адрес панели. Значения хранятся в БД
  и имеют приоритет над `.env`; секреты показываются маской.
- **Статус проверки и заметки** — решение проверяющего (на рассмотрении / бан /
  оправдан) + комментарий на странице скана.
- **Сравнение сканов** — что появилось/исчезло между двумя проверками игрока.
- **Пакетные ссылки** — до 50 ссылок одной кнопкой.
- **Водяные знаки** — в каждый скачанный exe вшивается метка, кто и когда его
  скачал (видно при анализе утёкшего бинаря).
- **Trust Badge** — публичная карточка `/badge/<steamId>`: «проверен, чист» +
  дата последней проверки. Игрок может делиться ссылкой как репутацией.
- **Светлая тема** — переключатель в углу любой страницы (запоминается).
- **Локальные ассеты** — шрифты/иконки/Tailwind лежат в `frontend/vendor/`,
  сайт работает без CDN. Пересборка Tailwind после правок классов:
  `npm run build:css`.
- **Быстрый режим сканера** — `clover.exe -fast`: только реестровые/снапшотные
  коллекторы (секунды вместо полного обхода дисков).

## Сигнатуры сканера (страница «Сигнатуры»)

Всё, что ищет сканер, настраивается с сайта — без пересборки бинаря:
контентные правила (паттерн/SHA256 + диапазон размеров + UTF-16/по пути),
целевые директории и файлы, имена exe для Amcache, чёрный список драйверов
(BYOVD). Сохранённое вшивается в `clover.exe` при каждом скачивании ссылки.
Просмотр — всем пользователям панели, изменение — уровню 5.

Подробная техническая документация — в [CLOVER.md](CLOVER.md).

## Структура

```
├── server.js             ← единый сервис (http-сервер: страницы + API)
├── package.json
├── clover.exe            ← сканер, отдаётся игроку (обязателен в корне)
├── backend/
│   ├── database.js       ← SQLite-слой (база: data/clover.db)
│   ├── scans.js          ← ядро: ссылки, криптография, хранение
│   ├── scans.routes.js   ← HTTP-эндпоинты /api/scans/*
│   └── scans.sql         ← справочная схема таблиц
├── frontend/
│   ├── index.html        ← лендинг /
│   ├── auth.html         ← вход /auth
│   ├── scans.html        ← сканы /scans (ссылки, поиск, график)
│   ├── scan.html         ← детальный скан /scans/<id> (18 вкладок, вердикт, AI)
│   ├── signatures.html   ← сигнатуры /signatures (запись — уровень 5)
│   ├── admin.html        ← админ-панель /admin (уровень 5)
│   ├── scan-player.html  ← страница игрока /scan
│   ├── badge.html        ← Trust Badge /badge/<steamId> (публичная)
│   ├── event.html        ← статус события /event/<id> (публичная)
│   ├── css/clover.css    ← дизайн-система (общая для всех страниц, тёмная+светлая)
│   ├── js/session.js     ← сессия
│   ├── js/ui.js          ← общий UI-кит: toast/esc/auth/тема/a11y
│   ├── vendor/           ← локальные ассеты (Tailwind, Phosphor, шрифты)
│   └── images/iconhtml.png
├── scripts/adduser.js    ← добавление пользователей
├── scripts/fetch-vendor.js    ← скачивание vendor-ассетов
├── scripts/tailwind.config.js ← сборка статического Tailwind (npm run build:css)
└── ish/                  ← исходники сканера (Go)
```

## Переменные окружения

Скопируй `.env.example` в `.env` и поменяй под себя — файл подхватывается
автоматически при старте (переменные реального окружения имеют приоритет).
`.env` не коммитится.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `PORT` | `3000` | порт сервиса |
| `ADMIN_USERNAME` | `admin` | логин бутстрап-админа (применяется при каждом запуске) |
| `ADMIN_PASSWORD` | `admin` | пароль бутстрап-админа (применяется при каждом запуске, сбрасывает его сессии) |
| `CLOVER_EXE_PATH` | `./clover.exe` | путь к бинарю сканера |
| `CLOVER_DB_PATH` | `./data/clover.db` | путь к SQLite-базе (без `DATABASE_URL`) |
| `TG_BOT_TOKEN` + `TG_CHAT_ID` | — | уведомления о новых сканах в Telegram |
| `DISCORD_WEBHOOK_URL` | — | уведомления в Discord |
| `PUBLIC_BASE_URL` | — | публичный адрес панели (ссылка в уведомлениях) |
| `AI_API_URL` + `AI_API_KEY` + `AI_MODEL` | — | AI-анализ сканов через внешний LLM |

## За прокси (Nginx / Cloudflare)

`uploadUrl` для сканера строится из `x-forwarded-proto` + `x-forwarded-host` —
пробрасывайте эти заголовки, иначе сканер будет стучаться на внутренний адрес.
Лимит тела прокси — не меньше 8 МБ (upload скана).
