'use strict';

/**
 * server.js — единый сервис Clover: сайт + API + БД (SQLite, файл data/clover.db).
 *
 *   npm install
 *   npm start          → http://localhost:3000
 *
 * Страницы:  / (лендинг) · /auth (вход) · /scans (админка) · /scan (игрок)
 * API:       /api/login · /api/logout · /api/me · /api/scans/*
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// Подхват .env из корня проекта (без внешних зависимостей).
// Переменные из реального окружения имеют приоритет.
try {
    const envFile = path.join(__dirname, '.env');
    for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
        const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
        if (!m) continue;
        const val = m[2].replace(/^["']|["']$/g, '');
        if (process.env[m[1]] === undefined) process.env[m[1]] = val;
    }
} catch (_) { /* .env необязателен */ }

const db = require('./backend/database');
const scans = require('./backend/scans');
const createScansHandler = require('./backend/scans.routes');

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, 'frontend');

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.json': 'application/json; charset=utf-8'
};

// ─── Хелперы ответов ────────────────────────────────────────────────────────

function sendJson(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(body);
}

function sendError(res, code, errCode, msg) {
    sendJson(res, code, { error: errCode, message: msg });
}

function sendHtml(res, code, html) {
    res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
}

function redirect(res, location) {
    res.writeHead(302, { Location: location });
    res.end();
}

function getClientIp(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return String(fwd).split(',')[0].trim();
    return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function readJsonBody(req, limitBytes = 64 * 1024) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk;
            if (body.length > limitBytes) { reject(new Error('PAYLOAD_TOO_LARGE')); try { req.destroy(); } catch (_) {} }
        });
        req.on('end', () => {
            try { resolve(body ? JSON.parse(body) : {}); } catch (_) { reject(new Error('INVALID_JSON')); }
        });
        req.on('error', reject);
    });
}

function getCookies(req) {
    const out = {};
    const raw = req.headers.cookie;
    if (!raw) return out;
    for (const part of raw.split(';')) {
        const i = part.indexOf('=');
        if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    }
    return out;
}

// ─── Сессии ─────────────────────────────────────────────────────────────────

async function getSessionFromReq(req) {
    const auth = req.headers.authorization || '';
    const bearer = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    const token = bearer || getCookies(req).clover_session || '';
    if (!token) return null;
    return db.getSessionByToken(token);
}

async function requireSession(req, res, minLevel) {
    const session = await getSessionFromReq(req);
    if (!session) { sendError(res, 401, 'UNAUTHORIZED', 'Требуется авторизация'); return null; }
    if (minLevel && session.level < minLevel) { sendError(res, 403, 'FORBIDDEN', 'Недостаточный уровень доступа'); return null; }
    return session;
}

function safeLog(session, action, targetSteamId, targetName, details) {
    console.log(`[audit] ${action} by=${session ? session.username : '-'} target=${targetName || targetSteamId || '-'} ${details || ''}`);
}

// ─── Scans API ──────────────────────────────────────────────────────────────

const handleScans = createScansHandler({
    scans, db,
    getSessionFromReq, requireSession,
    sendJson, sendError, getClientIp, safeLog
});

// ─── Auth API ───────────────────────────────────────────────────────────────

async function handleAuth(req, res, parsedUrl) {
    if (parsedUrl.pathname === '/api/login' && req.method === 'POST') {
        let body;
        try { body = await readJsonBody(req); } catch (_) { return sendError(res, 400, 'INVALID_JSON', 'Некорректный JSON'), true; }
        const user = await db.checkCredentials(body.username, body.password);
        if (!user) return sendError(res, 401, 'BAD_CREDENTIALS', 'Неверный логин или пароль'), true;
        const token = await db.createSession(user.id);
        res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': 'clover_session=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (30 * 24 * 3600)
        });
        res.end(JSON.stringify({ token, user: { ...user, sessionToken: token } }));
        return true;
    }
    if (parsedUrl.pathname === '/api/logout' && req.method === 'POST') {
        const auth = req.headers.authorization || '';
        const token = (auth.startsWith('Bearer ') ? auth.slice(7).trim() : '') || getCookies(req).clover_session || '';
        if (token) await db.deleteSession(token);
        res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': 'clover_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
        });
        res.end(JSON.stringify({ ok: true }));
        return true;
    }
    if (parsedUrl.pathname === '/api/me' && req.method === 'GET') {
        const session = await getSessionFromReq(req);
        if (!session) return sendError(res, 401, 'UNAUTHORIZED', 'Требуется авторизация'), true;
        const user = await db.getUserById(session.userId);
        if (!user) return sendError(res, 401, 'UNAUTHORIZED', 'Пользователь не найден'), true;
        sendJson(res, 200, user);
        return true;
    }
    return false;
}

// ─── Статика и страницы ─────────────────────────────────────────────────────

function serveFile(res, absPath) {
    fs.readFile(absPath, (err, data) => {
        if (err) return sendError(res, 404, 'NOT_FOUND', 'Файл не найден');
        res.writeHead(200, { 'Content-Type': MIME[path.extname(absPath).toLowerCase()] || 'application/octet-stream' });
        res.end(data);
    });
}

async function servePage(req, res, parsedUrl) {
    const p = parsedUrl.pathname;

    if (p === '/' || p === '/index.html') return serveFile(res, path.join(PUBLIC_DIR, 'index.html'));
    if (p === '/auth') return serveFile(res, path.join(PUBLIC_DIR, 'auth.html'));
    if (p === '/scan') return serveFile(res, path.join(PUBLIC_DIR, 'scan-player.html'));

    // Админка: защищена серверно — без сессии редирект на вход
    if (p === '/scans') {
        const session = await getSessionFromReq(req);
        if (!session) return redirect(res, '/auth?next=/scans');
        return serveFile(res, path.join(PUBLIC_DIR, 'scans.html'));
    }

    // Публичные статические файлы (js, images)
    if (p.startsWith('/js/') || p.startsWith('/images/')) {
        const rel = decodeURIComponent(p).replace(/^[/\\]+/, '');
        const abs = path.join(PUBLIC_DIR, rel);
        if (!abs.startsWith(PUBLIC_DIR)) return sendError(res, 403, 'FORBIDDEN', 'Недопустимый путь');
        return serveFile(res, abs);
    }

    sendError(res, 404, 'NOT_FOUND', 'Страница не найдена');
}

// ─── Запуск ─────────────────────────────────────────────────────────────────

async function main() {
    await db.initSchema();
    // Первый пользователь — супер-админ (уровень 5)
    const seed = await db.seedAdmin();
    if (seed) {
        await db.createUser({
            username: seed.username,
            password: seed.password,
            displayName: seed.username,
            level: 5,
            canScan: true
        });
        console.log('[clover] создан первый пользователь (уровень 5):');
        console.log('[clover]   логин:  ' + seed.username);
        console.log('[clover]   пароль: ' + seed.password + (process.env.ADMIN_PASSWORD ? '' : '  ← СМЕНИТЕ: задайте ADMIN_USERNAME/ADMIN_PASSWORD'));
    }

    await scans.init();

    const server = http.createServer(async (req, res) => {
        try {
            const parsedUrl = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
            if (parsedUrl.pathname.startsWith('/api/scans/')) {
                if (await handleScans(req, res, parsedUrl)) return;
            }
            if (parsedUrl.pathname.startsWith('/api/')) {
                if (await handleAuth(req, res, parsedUrl)) return;
                return sendError(res, 404, 'NOT_FOUND', 'Endpoint не найден');
            }
            if (req.method === 'GET' || req.method === 'HEAD') {
                return await servePage(req, res, parsedUrl);
            }
            sendError(res, 405, 'METHOD_NOT_ALLOWED', 'Метод не поддерживается');
        } catch (e) {
            console.error('[clover] request error:', e);
            try { sendError(res, 500, 'INTERNAL', 'Внутренняя ошибка сервера'); } catch (_) {}
        }
    });

    server.listen(PORT, () => {
        console.log('[clover] сервис запущен: http://localhost:' + PORT);
        console.log('[clover]   /       — лендинг');
        console.log('[clover]   /auth   — вход');
        console.log('[clover]   /scans  — админка (нужен вход)');
        console.log('[clover]   /scan   — страница игрока');
        console.log('[clover] БД: data/clover.db (SQLite)');
    });
}

main().catch(e => { console.error('[clover] fatal:', e); process.exit(1); });
