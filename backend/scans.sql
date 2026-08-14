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

-- Доступ к сканам: любой авторизованный пользователь панели (без флагов и
-- порогов уровня — если учётная запись есть в админах, доступ уже есть).


-- ─── SQLite ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    link_id TEXT,
    admin_user TEXT,
    admin_display_name TEXT,
    timestamp BIGINT NOT NULL,
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
