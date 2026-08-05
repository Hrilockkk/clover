# Clover — система проверки игроков

Один сервис: сайт + API + база данных (SQLite, файл `data/clover.db`).
Отдельный сервер БД поднимать не нужно.

## Запуск

```bash
npm install
npm start
```

Открыть: **http://localhost:3000**

## Деплой на свой сервер

### Вариант 1: Docker (рекомендуется) — одна команда

```bash
# 1. Склонировать (репо приватный — подставь токен github.com/settings/tokens)
git clone https://<ТОКЕН>@github.com/Hrilockkk/clover.git
cd clover

# 2. Пароль первого админа (опционально, по умолчанию admin/admin)
echo "ADMIN_PASSWORD=$(openssl rand -hex 8)" > .env

# 3. Поднять
docker compose up -d --build
```

Готово: сервис на порту **3000**, база — в named volume `clover-data`
(переживает пересборку и обновления). Логи: `docker compose logs -f`.
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
    client_max_body_size 2m;          # upload скана до 1 МБ, с запасом

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
| Админка (ссылки + сканы) | `/scans` | после входа |
| Страница игрока | `/scan?id=…` | публичная |

При первом запуске создаётся админ **admin / admin** (уровень 5).
Смените через переменные окружения перед первым запуском:

```bash
# Windows (PowerShell)
$env:ADMIN_USERNAME="myadmin"; $env:ADMIN_PASSWORD="strongpass"; npm start

# Linux
ADMIN_USERNAME=myadmin ADMIN_PASSWORD=strongpass npm start
```

Порт: `PORT=8080 npm start` (по умолчанию 3000).

## Пользователи

```bash
npm run adduser -- <логин> <пароль> [уровень 1..5] [--scan]
# пример: npm run adduser -- moderator pass123 2 --scan
```

Доступ к `/scans`: уровень ≥ `scans_min_level` (по умолчанию 4, меняется в админке
уровнем 5) **или** флаг `--scan` у пользователя.

## Как это работает

1. Админ на `/scans` создаёт одноразовую ссылку (TTL 10 минут).
2. Игрок открывает `/scan?id=…` и скачивает персональный `clover.exe` —
   сервер встраивает в него зашифрованный конфиг именно этой ссылки.
3. Игрок запускает файл от имени администратора, вводит выданный пароль.
   Сканер проверяет систему и сам отправляет результат (AES-256-GCM),
   после чего самоуничтожается.
4. Если авто-отправка не удалась — рядом создаётся `scan_*.enc`, его
   перетаскивают в dropzone на странице `/scan`.
5. Админ видит результат на `/scans`: обзор, совпадения, удалённое, папки,
   сеть, amcache, shellbags, appdata, USB. Поиск — по SteamID / HWID / нику.

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
│   ├── scans.html        ← админка /scans
│   ├── scan-player.html  ← страница игрока /scan
│   ├── js/session.js
│   └── images/iconhtml.png
├── scripts/adduser.js    ← добавление пользователей
└── ish/                  ← исходники сканера (Go)
```

## Переменные окружения

Скопируй `.env.example` в `.env` и поменяй под себя — файл подхватывается
автоматически при старте (переменные реального окружения имеют приоритет).
`.env` не коммитится.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `PORT` | `3000` | порт сервиса |
| `ADMIN_USERNAME` | `admin` | логин первого админа (только при первом запуске) |
| `ADMIN_PASSWORD` | `admin` | пароль первого админа (только при первом запуске) |
| `CLOVER_EXE_PATH` | `./clover.exe` | путь к бинарю сканера |

## За прокси (Nginx / Cloudflare)

`uploadUrl` для сканера строится из `x-forwarded-proto` + `x-forwarded-host` —
пробрасывайте эти заголовки, иначе сканер будет стучаться на внутренний адрес.
Лимит тела прокси — не меньше 1 МБ (upload скана).
