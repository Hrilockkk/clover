-- ═══════════════════════════════════════════════════════════════════════════
-- Clover Scans — схема БД
-- Извлечено из VibeCoding: src/databasePostgres.js (panel_scans) и
-- src/databaseSqlite.js (scans). Выберите нужный диалект.
-- ═══════════════════════════════════════════════════════════════════════════

-- ─── PostgreSQL ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS panel_scans (
    id TEXT PRIMARY KEY,              -- scanId (32 hex)
    link_id TEXT,                     -- id ссылки, по которой пришёл скан
    admin_user TEXT,                  -- username админа, создавшего ссылку
    admin_display_name TEXT,          -- отображаемое имя админа
    timestamp BIGINT NOT NULL,        -- unix ms
    hwid TEXT,                        -- из rec.hardware.hwid (для поиска)
    hostname TEXT,                    -- из rec.hardware.hostname
    username TEXT,                    -- из rec.hardware.username (учётка Windows)
    steam_ids TEXT,                   -- CSV из rec.steam.accounts[].steamId
    steam_names TEXT,                 -- CSV из rec.steam.accounts[].accountName
    payload TEXT NOT NULL             -- полный JSON скана
);

CREATE INDEX IF NOT EXISTS idx_panel_scans_timestamp  ON panel_scans(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_panel_scans_admin      ON panel_scans(admin_user);
CREATE INDEX IF NOT EXISTS idx_panel_scans_hwid       ON panel_scans(hwid);
CREATE INDEX IF NOT EXISTS idx_panel_scans_hostname   ON panel_scans(hostname);
CREATE INDEX IF NOT EXISTS idx_panel_scans_username   ON panel_scans(username);
CREATE INDEX IF NOT EXISTS idx_panel_scans_steam_ids  ON panel_scans(steam_ids);
CREATE INDEX IF NOT EXISTS idx_panel_scans_steam_names ON panel_scans(steam_names);

-- Per-user флаг «Разрешить сканы» (можно дать доступ без повышения уровня):
ALTER TABLE panel_users ADD COLUMN IF NOT EXISTS can_scan INTEGER NOT NULL DEFAULT 0;

-- Глобальная настройка уровня хранится в key-value таблице настроек
-- (panel_app_settings): ключ 'scans_min_level', значение 1..5 (по умолчанию 4).
-- Читается/пишется через db.getSetting('scans_min_level') / db.setSetting(...).


-- ─── SQLite ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    link_id TEXT,
    admin_user TEXT,
    admin_display_name TEXT,
    timestamp INTEGER NOT NULL,
    hwid TEXT,
    hostname TEXT,
    username TEXT,
    steam_ids TEXT,
    steam_names TEXT,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_timestamp   ON scans(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scans_admin       ON scans(admin_user);
CREATE INDEX IF NOT EXISTS idx_scans_hwid        ON scans(hwid);
CREATE INDEX IF NOT EXISTS idx_scans_hostname    ON scans(hostname);
CREATE INDEX IF NOT EXISTS idx_scans_username    ON scans(username);
CREATE INDEX IF NOT EXISTS idx_scans_steam_ids   ON scans(steam_ids);
CREATE INDEX IF NOT EXISTS idx_scans_steam_names ON scans(steam_names);

ALTER TABLE users ADD COLUMN can_scan INTEGER NOT NULL DEFAULT 0;

-- ─── Ссылки сканов ──────────────────────────────────────────────────────────
-- Ссылки НЕ в БД: это файлы data/scans/links/<id>.json (TTL 10 минут).
-- Структура файла:
-- {
--   "id": "32hex",
--   "createdAt": "ISO-строка",
--   "expiresAt": 1700000000000,
--   "note": "заметка ≤200 симв.",
--   "playerPassword": "8 символов A-Z2-9",
--   "adminUser": "username админа",
--   "adminDisplayName": "имя админа"
-- }
-- После успешной загрузки скана файл ссылки удаляется (одноразовость).
