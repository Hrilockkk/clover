'use strict';

/**
 * database.js — DB-слой Clover. Два драйвера:
 *
 *   • PostgreSQL — если задан DATABASE_URL (postgres://user:pass@host:5432/dbname).
 *     Строку подключения можно вставить в DBeaver/DataGrip/pgAdmin и смотреть/править
 *     данные напрямую.
 *   • SQLite (по умолчанию) — файл data/clover.db, ноль зависимостей для локалки.
 *
 * Контракт для scans.js и scans.routes.js:
 *   saveScanRecord / getScanRecord / listScanRecords / searchScanRecords
 *   getSetting / setSetting / getUserById
 * Плюс auth: getUserByUsername, createUser, checkCredentials,
 *            createSession, getSessionByToken, deleteSession, seedAdmin, initSchema.
 * Плюс админка (/admin): listUsers, updateUser, setUserPassword, deleteUser,
 *            countUsers, countScanRecords, deleteUserSessions.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const USE_PG = Boolean(process.env.DATABASE_URL);

// ─── Унифицированная обёртка запросов (плейсхолдеры '?', для pg → $1..$n) ───

let sql;

if (USE_PG) {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    const toPg = (text) => { let i = 0; return text.replace(/\?/g, () => '$' + (++i)); };
    sql = {
        all: async (t, p = []) => (await pool.query(toPg(t), p)).rows,
        get: async (t, p = []) => ((await pool.query(toPg(t), p)).rows[0]) ?? null,
        run: async (t, p = []) => { await pool.query(toPg(t), p); },
        exec: async (t) => { await pool.query(t); }
    };
} else {
    const Database = require('better-sqlite3');
    const DATA_DIR = path.join(__dirname, '..', 'data');
    fs.mkdirSync(DATA_DIR, { recursive: true });
    // CLOVER_DB_PATH — необязательный путь к файлу БД (по умолчанию data/clover.db)
    const db = new Database(process.env.CLOVER_DB_PATH || path.join(DATA_DIR, 'clover.db'));
    db.pragma('journal_mode = WAL');
    sql = {
        all: async (t, p = []) => db.prepare(t).all(...p),
        get: async (t, p = []) => db.prepare(t).get(...p) ?? null,
        run: async (t, p = []) => { db.prepare(t).run(...p); },
        exec: async (t) => { db.exec(t); }
    };
}

// ─── Схема ──────────────────────────────────────────────────────────────────

const DDL_SQLITE = `
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    link_id TEXT,
    admin_user TEXT,
    admin_display_name TEXT,
    "timestamp" INTEGER NOT NULL,
    hwid TEXT,
    hostname TEXT,
    username TEXT,
    steam_ids TEXT,
    steam_names TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp   ON scans("timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_scans_admin       ON scans(admin_user);
CREATE INDEX IF NOT EXISTS idx_scans_hwid        ON scans(hwid);
CREATE INDEX IF NOT EXISTS idx_scans_hostname    ON scans(hostname);
CREATE INDEX IF NOT EXISTS idx_scans_username    ON scans(username);
CREATE INDEX IF NOT EXISTS idx_scans_steam_ids   ON scans(steam_ids);
CREATE INDEX IF NOT EXISTS idx_scans_steam_names ON scans(steam_names);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 1,
    can_scan INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS settings (
    "key" TEXT PRIMARY KEY,
    "value" TEXT NOT NULL
);
`;

const DDL_PG = DDL_SQLITE; // диалект совпадает (TEXT/INTEGER, "quoted" идентификаторы)

async function initSchema() {
    await sql.exec(USE_PG ? DDL_PG : DDL_SQLITE);
}

// ─── Scans ──────────────────────────────────────────────────────────────────

function extractScanFields(rec) {
    const hw = rec.hardware || {};
    const accounts = (rec.steam && Array.isArray(rec.steam.accounts)) ? rec.steam.accounts : [];
    return [
        String(rec.scanId),
        rec.linkId || null,
        rec.adminUser || '',
        rec.adminDisplayName || '',
        Number(rec.timestamp) || Date.now(),
        hw.hwid || '',
        hw.hostname || '',
        hw.username || '',
        accounts.map(a => a.steamId).filter(Boolean).join(','),
        accounts.map(a => a.accountName).filter(Boolean).join(','),
        JSON.stringify(rec)
    ];
}

const UPSERT_SCAN = `
    INSERT INTO scans (id, link_id, admin_user, admin_display_name, "timestamp",
                       hwid, hostname, username, steam_ids, steam_names, payload)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
        link_id=excluded.link_id, admin_user=excluded.admin_user,
        admin_display_name=excluded.admin_display_name, "timestamp"=excluded."timestamp",
        hwid=excluded.hwid, hostname=excluded.hostname, username=excluded.username,
        steam_ids=excluded.steam_ids, steam_names=excluded.steam_names,
        payload=excluded.payload
`;

async function saveScanRecord(rec) {
    if (!rec || !rec.scanId) throw new Error('scan record without scanId');
    await sql.run(UPSERT_SCAN, extractScanFields(rec));
}

async function getScanRecord(id) {
    const row = await sql.get('SELECT payload FROM scans WHERE id = ?', [String(id)]);
    if (!row) return null;
    try { return JSON.parse(row.payload); } catch (_) { return null; }
}

async function listScanRecords() {
    const rows = await sql.all('SELECT payload FROM scans ORDER BY "timestamp" DESC');
    return rows.map(r => { try { return JSON.parse(r.payload); } catch (_) { return null; } }).filter(Boolean);
}

async function searchScanRecords(q) {
    q = String(q || '').trim();
    if (!q) return listScanRecords();
    const like = '%' + q.replace(/[%_]/g, c => '\\' + c) + '%';
    const rows = await sql.all(`
        SELECT payload FROM scans
        WHERE hwid LIKE ? ESCAPE '\\'
           OR hostname LIKE ? ESCAPE '\\'
           OR username LIKE ? ESCAPE '\\'
           OR steam_ids LIKE ? ESCAPE '\\'
           OR steam_names LIKE ? ESCAPE '\\'
           OR admin_user LIKE ? ESCAPE '\\'
           OR admin_display_name LIKE ? ESCAPE '\\'
        ORDER BY "timestamp" DESC
    `, [like, like, like, like, like, like, like]);
    return rows.map(r => { try { return JSON.parse(r.payload); } catch (_) { return null; } }).filter(Boolean);
}

// ─── Settings ───────────────────────────────────────────────────────────────

async function getSetting(key, defaultValue) {
    const row = await sql.get('SELECT "value" FROM settings WHERE "key" = ?', [String(key)]);
    if (!row) return defaultValue;
    try { return JSON.parse(row.value); } catch (_) { return row.value; }
}

async function setSetting(key, value) {
    await sql.run(
        'INSERT INTO settings ("key", "value") VALUES (?, ?) ON CONFLICT("key") DO UPDATE SET "value"=excluded."value"',
        [String(key), JSON.stringify(value)]
    );
}

// ─── Users ──────────────────────────────────────────────────────────────────

function hashPassword(password, salt) {
    salt = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
    return salt + ':' + hash;
}

function verifyPassword(password, stored) {
    const [salt, hash] = String(stored || '').split(':');
    if (!salt || !hash) return false;
    const candidate = crypto.scryptSync(String(password), salt, 64);
    const expected = Buffer.from(hash, 'hex');
    return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

function publicUser(row) {
    if (!row) return null;
    return {
        id: row.id,
        username: row.username,
        displayName: row.display_name || row.username,
        level: Number(row.level)
    };
}

async function getUserById(id) {
    return publicUser(await sql.get('SELECT * FROM users WHERE id = ?', [String(id)]));
}

async function getUserByUsername(username) {
    return sql.get('SELECT * FROM users WHERE username = ?', [String(username)]);
}

async function createUser({ username, password, displayName, level }) {
    const id = crypto.randomBytes(8).toString('hex');
    await sql.run(
        `INSERT INTO users (id, username, display_name, password_hash, level, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [id, String(username), String(displayName || username || ''), hashPassword(password),
         Number(level) || 1, Date.now()]
    );
    return getUserById(id);
}

async function listUsers() {
    const rows = await sql.all(`
        SELECT u.*,
               (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > ?) AS active_sessions
        FROM users u ORDER BY u.created_at ASC
    `, [Date.now()]);
    return rows.map(r => ({
        ...publicUser(r),
        createdAt: Number(r.created_at) || 0,
        activeSessions: Number(r.active_sessions) || 0
    }));
}

async function updateUser(id, patch) {
    const sets = [];
    const params = [];
    if (patch.displayName !== undefined) { sets.push('display_name = ?'); params.push(String(patch.displayName)); }
    if (patch.level !== undefined) { sets.push('level = ?'); params.push(Number(patch.level) || 1); }
    if (!sets.length) return getUserById(id);
    params.push(String(id));
    await sql.run('UPDATE users SET ' + sets.join(', ') + ' WHERE id = ?', params);
    return getUserById(id);
}

async function setUserPassword(id, password) {
    await sql.run('UPDATE users SET password_hash = ? WHERE id = ?', [hashPassword(password), String(id)]);
}

async function deleteUser(id) {
    await sql.run('DELETE FROM sessions WHERE user_id = ?', [String(id)]);
    await sql.run('DELETE FROM users WHERE id = ?', [String(id)]);
}

async function countUsers(level) {
    const row = level !== undefined
        ? await sql.get('SELECT COUNT(*) AS c FROM users WHERE level = ?', [Number(level)])
        : await sql.get('SELECT COUNT(*) AS c FROM users');
    return Number(row.c);
}

async function countScanRecords() {
    const row = await sql.get('SELECT COUNT(*) AS c FROM scans');
    return Number(row.c);
}

async function checkCredentials(username, password) {
    const row = await sql.get('SELECT * FROM users WHERE username = ?', [String(username)]);
    if (!row || !verifyPassword(password, row.password_hash)) return null;
    return publicUser(row);
}

// ─── Sessions ───────────────────────────────────────────────────────────────

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 дней

async function createSession(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    await sql.run(
        'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
        [token, String(userId), Date.now(), Date.now() + SESSION_TTL_MS]
    );
    return token;
}

async function getSessionByToken(token) {
    if (!token) return null;
    const row = await sql.get('SELECT * FROM sessions WHERE token = ?', [String(token)]);
    if (!row) return null;
    if (Date.now() > Number(row.expires_at)) {
        await sql.run('DELETE FROM sessions WHERE token = ?', [String(token)]);
        return null;
    }
    const user = await getUserById(row.user_id);
    if (!user) return null;
    return { userId: user.id, username: user.username, displayName: user.displayName, level: user.level };
}

async function deleteSession(token) {
    await sql.run('DELETE FROM sessions WHERE token = ?', [String(token)]);
}

async function deleteUserSessions(userId) {
    await sql.run('DELETE FROM sessions WHERE user_id = ?', [String(userId)]);
}

// ─── Seed ───────────────────────────────────────────────────────────────────

async function seedAdmin() {
    const row = await sql.get('SELECT COUNT(*) AS c FROM users');
    if (Number(row.c) > 0) return null;
    return {
        username: process.env.ADMIN_USERNAME || 'admin',
        password: process.env.ADMIN_PASSWORD || 'admin'
    };
}

module.exports = {
    initSchema,
    saveScanRecord, getScanRecord, listScanRecords, searchScanRecords, countScanRecords,
    getSetting, setSetting,
    getUserById, getUserByUsername, createUser, checkCredentials, hashPassword,
    listUsers, updateUser, setUserPassword, deleteUser, countUsers,
    createSession, getSessionByToken, deleteSession, deleteUserSessions,
    seedAdmin
};
