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

const LINK_TTL_MS = 10 * 60 * 1000; // 10 минут на СКАЧИВАНИЕ
// После скачивания exe ссылке продлевается жизнь: полный скан с правами
// администратора (raw MFT + USN по всем дискам) может идти заметно дольше
// 10 минут, и результаты не должны отбрасываться с 404.
const LINK_UPLOAD_GRACE_MS = 2 * 60 * 60 * 1000;

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

// extendLinkExpiry продлевает жизнь ссылки после скачивания exe — на время,
// достаточное для полного скана и загрузки результата.
function extendLinkExpiry(id, ttlMs) {
    const link = getLink(id);
    if (!link) return null;
    link.expiresAt = Date.now() + (ttlMs || LINK_UPLOAD_GRACE_MS);
    writeJsonSafe(linkPath(id), link);
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
        const existing = await db.listScanSummaries();
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
    return db.listScanSummaries();
}

async function searchRecords(q) {
    return db.searchScanSummaries(q);
}

async function getStats() {
    const scans = await db.listScanSummaries(2000);
    const now = Date.now();
    return {
        total: scans.length,
        flagged: scans.filter(s => (s.hitCount || 0) > 0).length,
        clean: scans.filter(s => !(s.hitCount || 0)).length,
        last24h: scans.filter(s => now - Number(s.timestamp || 0) <= 24 * 60 * 60 * 1000).length,
        latest: scans[0] || null
    };
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

// ─── Сигнатуры (управляются со страницы «Сигнатуры») ───────────────────────

// DEFAULT_SIGNATURES — зеркало встроенных дефолтов сканера (ish/internal/config).
// Если в БД нет сохранённых сигнатур, сканер получает именно эти.
const DEFAULT_SIGNATURES = {
    rules: [
        { min: 9437184, max: 15728640, pattern: 'Gentee Launcher' },
        { min: 9437184, max: 16777216, pattern: 'X PROGRAMM LTD1' },
        { min: 16777216, max: 25165824, pattern: '7+InZ[^0' },
        { min: 10485760, max: 25165824, pattern: 't$PfD)t$PL' },
        { min: 4194304, max: 10485760, pattern: 'KDMapper' },
        { min: 307200, max: 3145728, pattern: 'DragonBurn' },
        { min: 2097152, max: 8388608, pattern: 'D:/Projects/touchskins' },
        { min: 45088768, max: 62914560, pattern: 'vac_module_ok' },
        { min: 629145600, max: 734003200, pattern: 'SharkHack' },
        { min: 26214400, max: 32505856, sha256: 'a842a8dd5bfa9ea792dbdce210d53ec29e85c9c30115c4046d9b26c73dcdac66' },
        { min: 10485760, max: 16777216, pattern: '&Lp6U&XM}3ZQ*^[Hp)' },
        { min: 2097152, max: 8388608, pattern: 'j_M6:F' },
        { min: 102400, max: 409600, pattern: 'swiftsoft', utf16: true },
        { min: 20971520, max: 25165824, pattern: 'exloader' },
        { min: 13631488, max: 24117248, pattern: 'ZI>vZ@y#O%~' },
        { min: 204800, max: 409600, pattern: 'com.mvploader', utf16: true },
        { min: 3145728, max: 7340032, pattern: 'Wzo8f9:GPd_C[' },
        { min: 1048576, max: 4194304, pattern: 'lua54.dll not loaded!' }
    ],
    targetDirNames: ['XONE', 'Memesense', 'com.swiftsoft', 'Interium', 'com.mvploader', 'GPA', 'DragonBurn', 'DragonBurn-tmp', 'en1gma-tech', 'osiriscs2', 'fatality', 'nix'],
    targetFileNames: ['token.ms', 'schinese.bin', 'russian.bin', 'esp-icons.ttf', 'message-bus.bin', 'nl.log', 'nl_cs2.log'],
    amcacheExeNames: ['exloader.exe', 'mvploader.exe', 'catalyst.exe', 'exloader_installer.exe'],
    driverBlacklist: [
        'iqvw64e.sys', 'iqvw64.sys', 'dbutil_2_3.sys', 'capcom.sys',
        'rtcore64.sys', 'rtcore32.sys', 'winring0.sys', 'winring0x64.sys',
        'gdrv.sys', 'inpoutx64.sys', 'inpout32.sys', 'ntiolib.sys', 'ntiolib_x64.sys',
        'msio64.sys', 'msio32.sys', 'physmem.sys', 'kprocesshacker.sys',
        'mhyprot2.sys', 'mhyprot.sys', 'kdstinker.sys', 'amifldrv64.sys',
        'asio64.sys', 'gmer64.sys', 'hw.sys', 'kguard.sys', 'knpcdev.sys',
        'my.sys', 'pcdrv64.sys', 'pfc64.sys', 'rambpf64.sys', 'smepcap.sys',
        'speedfan.sys', 'tbs.sys', 'vmdrv.sys', 'wsprvt.sys', 'xhunter1.sys',
        'zam64.sys', 'zamguard64.sys'
    ]
};

const SIGNATURES_SETTING_KEY = 'signatures';
const MAX_RULES = 256;
const MAX_NAMES = 512;
const MAX_PATTERN_LEN = 256;
const MAX_NAME_LEN = 128;
const MAX_RULE_SIZE = 2 * 1024 * 1024 * 1024; // 2 ГБ

function isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

function cleanNameList(v, field) {
    if (!Array.isArray(v)) throw new Error(field + ': должен быть массивом строк');
    if (v.length > MAX_NAMES) throw new Error(field + ': максимум ' + MAX_NAMES + ' записей');
    return v.map(s => {
        if (typeof s !== 'string') throw new Error(field + ': записи должны быть строками');
        const t = s.trim();
        if (!t) throw new Error(field + ': пустая запись');
        if (t.length > MAX_NAME_LEN) throw new Error(field + ': запись длиннее ' + MAX_NAME_LEN + ' символов');
        return t;
    });
}

// validateSignatures нормализует и проверяет конфиг сигнатур с сайта.
// Бросает Error с понятным сообщением при невалидных данных.
function validateSignatures(sig) {
    if (!isPlainObject(sig)) throw new Error('ожидается объект');
    const out = {};
    if (sig.rules !== undefined) {
        if (!Array.isArray(sig.rules)) throw new Error('rules: должен быть массивом');
        if (sig.rules.length > MAX_RULES) throw new Error('rules: максимум ' + MAX_RULES + ' правил');
        out.rules = sig.rules.map((r, i) => {
            if (!isPlainObject(r)) throw new Error('rules[' + i + ']: должен быть объектом');
            const min = Number(r.min) || 0;
            const max = Number(r.max) || 0;
            if (min < 0 || max < 0 || min > max || max > MAX_RULE_SIZE) {
                throw new Error('rules[' + i + ']: некорректный диапазон размера');
            }
            const pattern = typeof r.pattern === 'string' ? r.pattern : '';
            const sha256 = typeof r.sha256 === 'string' ? r.sha256.trim().toLowerCase() : '';
            if (!pattern && !sha256) throw new Error('rules[' + i + ']: нужен pattern или sha256');
            if (pattern.length > MAX_PATTERN_LEN) throw new Error('rules[' + i + ']: pattern длиннее ' + MAX_PATTERN_LEN);
            if (sha256 && !/^[0-9a-f]{64}$/.test(sha256)) throw new Error('rules[' + i + ']: sha256 должен быть 64 hex-символа');
            const rule = { min, max };
            if (pattern) rule.pattern = pattern;
            if (sha256) rule.sha256 = sha256;
            if (r.utf16) rule.utf16 = true;
            if (r.checkPath) rule.checkPath = true;
            return rule;
        });
    }
    if (sig.targetDirNames !== undefined) out.targetDirNames = cleanNameList(sig.targetDirNames, 'targetDirNames');
    if (sig.targetFileNames !== undefined) out.targetFileNames = cleanNameList(sig.targetFileNames, 'targetFileNames');
    if (sig.amcacheExeNames !== undefined) out.amcacheExeNames = cleanNameList(sig.amcacheExeNames, 'amcacheExeNames');
    if (sig.driverBlacklist !== undefined) out.driverBlacklist = cleanNameList(sig.driverBlacklist, 'driverBlacklist');
    return out;
}

// getSignatures возвращает актуальный конфиг сигнатур: из БД, иначе дефолты.
async function getSignatures() {
    try {
        const raw = await db.getSetting(SIGNATURES_SETTING_KEY, null);
        if (!raw) return DEFAULT_SIGNATURES;
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        return validateSignatures(parsed);
    } catch (_) {
        return DEFAULT_SIGNATURES;
    }
}

// setSignatures валидирует и сохраняет конфиг в настройки БД.
async function setSignatures(sig) {
    const clean = validateSignatures(sig);
    await db.setSetting(SIGNATURES_SETTING_KEY, JSON.stringify(clean));
    return clean;
}

async function buildEmbeddedScanner(linkId, origin) {
    const link = getLink(linkId);
    if (!link) return null;

    const exePath = process.env.CLOVER_EXE_PATH || path.join(__dirname, '..', 'clover.exe');
    let baseData;
    try {
        baseData = fs.readFileSync(exePath);
    } catch (e) {
        throw new Error('clover.exe not found on server (CLOVER_EXE_PATH=' + exePath + '): ' + e.message);
    }

    // Актуальные сигнатуры вшиваются в exe на момент скачивания —
    // сканер применит их вместо встроенных дефолтов.
    const sig = await getSignatures();

    const cfg = {
        scanId: link.id,
        uploadUrl: origin + '/api/scans/upload/' + link.id,
        playerPassword: link.playerPassword || '',
        adminUser: link.adminUser || '',
        adminDisplayName: link.adminDisplayName || '',
        rules: sig.rules,
        targetDirNames: sig.targetDirNames,
        targetFileNames: sig.targetFileNames,
        amcacheExeNames: sig.amcacheExeNames,
        driverBlacklist: sig.driverBlacklist
    };
    const cfgJson = Buffer.from(JSON.stringify(cfg), 'utf8');
    const enc = encryptConfig(cfgJson);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32LE(enc.length, 0);

    return Buffer.concat([baseData, CONFIG_MARKER, lenBuf, enc]);
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
    getStats,
    buildEmbeddedScanner,
    getSignatures,
    setSignatures,
    DEFAULT_SIGNATURES,
    encryptConfig,
    decryptPayload,
    extendLinkExpiry,
    LINK_TTL_MS,
    LINK_UPLOAD_GRACE_MS
};
