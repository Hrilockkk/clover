'use strict';

/**
 * database.js — DB-слой Clover на SQLite (better-sqlite3).
 *
 * Файл базы: data/clover.db (создаётся автоматически, отдельный процесс БД
 * не нужен). Реализует контракт, который ожидают scans.js и scans.routes.js:
 *
 *   saveScanRecord(rec) / getScanRecord(id) / listScanRecords() / searchScanRecords(q)
 *   getSetting(key, def) / setSetting(key, value)
 *   getUserById(id)
 *
 * Плюс auth-функции для server.js: getUserByUsername, createUser,
 * createSession, getSessionByToken, deleteSession.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const DATA_DIR = path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'clover.db'));
db.pragma('journal_mode = WAL');

db.exec(`
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
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`);

// ─── Scans ──────────────────────────────────────────────────────────────────

const upsertScan = db.prepare(`
    INSERT INTO scans (id, link_id, admin_user, admin_display_name, timestamp,
                       hwid, hostname, username, steam_ids, steam_names, payload)
    VALUES (@id, @link_id, @admin_user, @admin_display_name, @timestamp,
            @hwid, @hostname, @username, @steam_ids, @steam_names, @payload)
    ON CONFLICT(id) DO UPDATE SET
        link_id=excluded.link_id, admin_user=excluded.admin_user,
        admin_display_name=excluded.admin_display_name, timestamp=excluded.timestamp,
        hwid=excluded.hwid, hostname=excluded.hostname, username=excluded.username,
        steam_ids=excluded.steam_ids, steam_names=excluded.steam_names,
        payload=excluded.payload
`);

function extractScanFields(rec) {
    const hw = rec.hardware || {};
    const accounts = (rec.steam && Array.isArray(rec.steam.accounts)) ? rec.steam.accounts : [];
    return {
        id: String(rec.scanId),
        link_id: rec.linkId || null,
        admin_user: rec.adminUser || '',
        admin_display_name: rec.adminDisplayName || '',
        timestamp: Number(rec.timestamp) || Date.now(),
        hwid: hw.hwid || '',
        hostname: hw.hostname || '',
        username: hw.username || '',
        steam_ids: accounts.map(a => a.steamId).filter(Boolean).join(','),
        steam_names: accounts.map(a => a.accountName).filter(Boolean).join(','),
        payload: JSON.stringify(rec)
    };
}

async function saveScanRecord(rec) {
    if (!rec || !rec.scanId) throw new Error('scan record without scanId');
    upsertScan.run(extractScanFields(rec));
}

async function getScanRecord(id) {
    const row = db.prepare('SELECT payload FROM scans WHERE id = ?').get(String(id));
    if (!row) return null;
    try { return JSON.parse(row.payload); } catch (_) { return null; }
}

async function listScanRecords() {
    const rows = db.prepare('SELECT payload FROM scans ORDER BY timestamp DESC').all();
    return rows.map(r => { try { return JSON.parse(r.payload); } catch (_) { return null; } }).filter(Boolean);
}

async function searchScanRecords(q) {
    q = String(q || '').trim();
    if (!q) return listScanRecords();
    const like = '%' + q.replace(/[%_]/g, c => '\\' + c) + '%';
    const rows = db.prepare(`
        SELECT payload FROM scans
        WHERE hwid LIKE ? ESCAPE '\\'
           OR hostname LIKE ? ESCAPE '\\'
           OR username LIKE ? ESCAPE '\\'
           OR steam_ids LIKE ? ESCAPE '\\'
           OR steam_names LIKE ? ESCAPE '\\'
           OR admin_user LIKE ? ESCAPE '\\'
           OR admin_display_name LIKE ? ESCAPE '\\'
        ORDER BY timestamp DESC
    `).all(like, like, like, like, like, like, like);
    return rows.map(r => { try { return JSON.parse(r.payload); } catch (_) { return null; } }).filter(Boolean);
}

// ─── Settings ───────────────────────────────────────────────────────────────

async function getSetting(key, defaultValue) {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(String(key));
    if (!row) return defaultValue;
    try { return JSON.parse(row.value); } catch (_) { return row.value; }
}

async function setSetting(key, value) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
      .run(String(key), JSON.stringify(value));
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
        level: row.level,
        canScan: Boolean(row.can_scan)
    };
}

async function getUserById(id) {
    return publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(String(id)));
}

async function getUserByUsername(username) {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(String(username));
}

async function createUser({ username, password, displayName, level, canScan }) {
    const row = {
        id: crypto.randomBytes(8).toString('hex'),
        username: String(username),
        display_name: String(displayName || username || ''),
        password_hash: hashPassword(password),
        level: Number(level) || 1,
        can_scan: canScan ? 1 : 0,
        created_at: Date.now()
    };
    db.prepare(`INSERT INTO users (id, username, display_name, password_hash, level, can_scan, created_at)
                VALUES (@id, @username, @display_name, @password_hash, @level, @can_scan, @created_at)`).run(row);
    return getUserById(row.id);
}

function checkCredentials(username, password) {
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username));
    if (!row || !verifyPassword(password, row.password_hash)) return null;
    return publicUser(row);
}

// ─── Sessions ───────────────────────────────────────────────────────────────

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 дней

async function createSession(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .run(token, String(userId), Date.now(), Date.now() + SESSION_TTL_MS);
    return token;
}

async function getSessionByToken(token) {
    if (!token) return null;
    const row = db.prepare('SELECT * FROM sessions WHERE token = ?').get(String(token));
    if (!row) return null;
    if (Date.now() > row.expires_at) {
        db.prepare('DELETE FROM sessions WHERE token = ?').run(String(token));
        return null;
    }
    const user = await getUserById(row.user_id);
    if (!user) return null;
    return { userId: user.id, username: user.username, displayName: user.displayName, level: user.level };
}

async function deleteSession(token) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(String(token));
}

// ─── Seed ───────────────────────────────────────────────────────────────────

function seedAdmin() {
    const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
    if (count > 0) return null;
    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'admin';
    return { username, password };
}

module.exports = {
    saveScanRecord, getScanRecord, listScanRecords, searchScanRecords,
    getSetting, setSetting,
    getUserById, getUserByUsername, createUser, checkCredentials, hashPassword,
    createSession, getSessionByToken, deleteSession,
    seedAdmin
};
