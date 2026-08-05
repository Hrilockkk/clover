/**
 * scans.js — хранилище ссылок и результатов сканов Clover.
 *
 * Ссылки хранятся в файловой системе (data/scans/links).
 * Записи сканов хранятся в реляционной БД (таблица scans / panel_scans) в виде
 * JSON-блоба плюс индексируемые поля для поиска.
 *
 * clover.exe скачивается с встроенным конфигом (маркер + длина + JSON), который
 * сканер читает при запуске: scanId, uploadUrl, playerPassword, adminUser.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const db = require('./database');

const DATA_DIR = path.join(__dirname, '..', 'data', 'scans');
const LINKS_DIR = path.join(DATA_DIR, 'links');
const RECORDS_DIR = path.join(DATA_DIR, 'records');

const CONFIG_MARKER = Buffer.from('xK9pL2mQ5vX8wR4t');

// AES-256-GCM key shared with the Clover scanner. The key is obfuscated by
// splitting the base64 string before reassembling, so it does not appear as a
// single literal in the source.
const CONFIG_KEY = Buffer.from([
    'tiEJNrFlRv0', '/Ood4hcOif', 'IU2AJ13BVw', 'vtC3wgqDg1Mc='
].join(''), 'base64');

const LINK_TTL_MS = 10 * 60 * 1000; // 10 минут

function ensureDirs() {
    try { fs.mkdirSync(LINKS_DIR, { recursive: true }); } catch (_) {}
    try { fs.mkdirSync(RECORDS_DIR, { recursive: true }); } catch (_) {}
}

function genId() {
    return crypto.randomBytes(16).toString('hex');
}

function genPassword() {
    // 8-значный пароль: заглавные буквы + цифры (без неоднозначных символов)
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let pw = '';
    const buf = crypto.randomBytes(8);
    for (let i = 0; i < 8; i++) {
        pw += chars[buf[i] % chars.length];
    }
    return pw;
}

function linkPath(id) { return path.join(LINKS_DIR, id + '.json'); }
function recordPath(id) { return path.join(RECORDS_DIR, id + '.json'); }

function readJsonSafe(filePath) {
    try {
        const raw = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(raw);
    } catch (_) {
        return null;
    }
}

function writeJsonSafe(filePath, obj) {
    fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), 'utf8');
}

function deleteLinkFile(id) {
    try { fs.unlinkSync(linkPath(id)); } catch (_) {}
}

function isLinkExpired(link) {
    if (!link || !link.expiresAt) return false;
    return Date.now() > link.expiresAt;
}

// ─── Links ─────────────────────────────────────────────────────────────────

function createLink({ note, adminUser, adminDisplayName }) {
    ensureDirs();
    const now = Date.now();
    const password = genPassword();
    const link = {
        id: genId(),
        createdAt: new Date(now).toISOString(),
        expiresAt: now + LINK_TTL_MS,
        note: String(note || '').slice(0, 200),
        playerPassword: password,
        adminUser: String(adminUser || '').slice(0, 64),
        adminDisplayName: String(adminDisplayName || '').slice(0, 64)
    };
    writeJsonSafe(linkPath(link.id), link);
    return link;
}

function getLink(id) {
    if (!id || !/^[a-f0-9]+$/.test(id)) return null;
    const link = readJsonSafe(linkPath(id));
    if (!link) return null;
    // Авто-удаление истёкших ссылок
    if (isLinkExpired(link)) {
        deleteLinkFile(id);
        return null;
    }
    return link;
}

function listLinks() {
    ensureDirs();
    let entries = [];
    try { entries = fs.readdirSync(LINKS_DIR); } catch (_) {}
    const links = [];
    for (const name of entries) {
        if (!name.endsWith('.json')) continue;
        const l = readJsonSafe(path.join(LINKS_DIR, name));
        if (!l) continue;
        // Чистим истёкшие при листинге
        if (isLinkExpired(l)) {
            try { fs.unlinkSync(path.join(LINKS_DIR, name)); } catch (_) {}
            continue;
        }
        links.push(l);
    }
    links.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    return links;
}

function deleteLink(id) {
    if (!id || !/^[a-f0-9]+$/.test(id)) return false;
    deleteLinkFile(id);
    return true;
}

// ─── Records ───────────────────────────────────────────────────────────────

async function init() {
    ensureDirs();
    await migrateRecordsFromFiles();
}

async function migrateRecordsFromFiles() {
    try {
        const existing = await db.listScanRecords();
        if (existing.length > 0) return;
        let entries = [];
        try { entries = fs.readdirSync(RECORDS_DIR); } catch (_) {}
        let migrated = 0;
        for (const name of entries) {
            if (!name.endsWith('.json')) continue;
            const rec = readJsonSafe(path.join(RECORDS_DIR, name));
            if (rec) {
                await db.saveScanRecord(rec);
                migrated++;
            }
        }
        if (migrated) console.log(`[scans] migrated ${migrated} records from files to DB`);
    } catch (e) {
        console.warn('[scans] migrate records from files failed:', e.message);
    }
}

async function saveRecord(rec) {
    ensureDirs();
    if (!rec.scanId) rec.scanId = genId();
    if (!rec.timestamp) rec.timestamp = Date.now();
    await db.saveScanRecord(rec);
    // Удаляем ссылку после использования (скан загружен)
    if (rec.linkId) {
        deleteLinkFile(rec.linkId);
    }
    return rec;
}

async function getRecord(id) {
    if (!id || !/^[a-f0-9]+$/.test(id)) return null;
    return db.getScanRecord(id);
}

async function listRecords() {
    return db.listScanRecords();
}

async function searchRecords(q) {
    return db.searchScanRecords(q);
}

// ─── clover.exe embedding ──────────────────────────────────────────────────

function encryptConfig(plain) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', CONFIG_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, encrypted, tag]);
}

function decryptPayload(encryptedBase64) {
    const data = Buffer.from(encryptedBase64, 'base64');
    if (data.length < 28) throw new Error('encrypted payload too short'); // 12 iv + 16 tag + 0 ciphertext
    const iv = data.slice(0, 12);
    const tag = data.slice(data.length - 16);
    const ciphertext = data.slice(12, data.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', CONFIG_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function buildEmbeddedScanner(linkId, origin) {
    const link = getLink(linkId);
    if (!link) return null;

    const exePath = process.env.CLOVER_EXE_PATH || path.join(__dirname, '..', 'clover.exe');
    let baseData;
    try {
        baseData = fs.readFileSync(exePath);
    } catch (e) {
        throw new Error('clover.exe not found on server (CLOVER_EXE_PATH=' + exePath + '): ' + e.message);
    }

    const cfg = {
        scanId: link.id,
        uploadUrl: origin + '/api/scans/upload/' + link.id,
        playerPassword: link.playerPassword || '',
        adminUser: link.adminUser || '',
        adminDisplayName: link.adminDisplayName || ''
    };
    const cfgJson = Buffer.from(JSON.stringify(cfg), 'utf8');
    const enc = encryptConfig(cfgJson);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32LE(enc.length, 0);

    return Buffer.concat([baseData, CONFIG_MARKER, lenBuf, enc]);
}

// ─── Access level ──────────────────────────────────────────────────────────

const DEFAULT_SCANS_MIN_LEVEL = 4; // по умолчанию — уровень «ГА» (4)

async function getScansMinLevel(db) {
    try {
        const v = await db.getSetting('scans_min_level', DEFAULT_SCANS_MIN_LEVEL);
        const n = Number(v);
        return Number.isFinite(n) && n >= 1 && n <= 5 ? n : DEFAULT_SCANS_MIN_LEVEL;
    } catch (_) {
        return DEFAULT_SCANS_MIN_LEVEL;
    }
}

async function setScansMinLevel(db, level) {
    const n = Number(level);
    if (!Number.isFinite(n) || n < 1 || n > 5) {
        throw new Error('Level must be 1..5');
    }
    await db.setSetting('scans_min_level', n);
    return n;
}

module.exports = {
    init,
    ensureDirs,
    genId,
    createLink,
    getLink,
    listLinks,
    deleteLink,
    saveRecord,
    getRecord,
    listRecords,
    searchRecords,
    buildEmbeddedScanner,
    encryptConfig,
    decryptPayload,
    getScansMinLevel,
    setScansMinLevel,
    DEFAULT_SCANS_MIN_LEVEL,
    LINK_TTL_MS
};
