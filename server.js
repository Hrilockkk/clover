'use strict';

/**
 * server.js — единый сервис Clover: сайт + API + БД (SQLite, файл data/clover.db).
 *
 *   npm install
 *   npm start          → http://localhost:3000
 *
 * Страницы:  / (лендинг) · /auth (вход) · /scans (сканы) · /signatures (сигнатуры) · /admin (ур.5) · /scan (игрок)
 * API:       /api/login · /api/logout · /api/me · /api/scans/* · /api/users/* · /api/stats
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

// ─── Admin API (управление пользователями — только уровень 5) ───────────────

const USERNAME_RE = /^[a-zA-Z0-9_.-]{2,32}$/;
const MIN_PASSWORD_LEN = 4;

async function handleAdmin(req, res, parsedUrl) {
    const p = parsedUrl.pathname;

    // Сводка для дашборда админки
    if (p === '/api/stats' && req.method === 'GET') {
        const session = await requireSession(req, res, 5);
        if (!session) return true;
        sendJson(res, 200, {
            users: await db.countUsers(),
            scans: await db.countScanRecords(),
            links: scans.listLinks().length
        });
        return true;
    }

    if (p === '/api/users' && req.method === 'GET') {
        const session = await requireSession(req, res, 5);
        if (!session) return true;
        sendJson(res, 200, { users: await db.listUsers() });
        return true;
    }

    if (p === '/api/users' && req.method === 'POST') {
        const session = await requireSession(req, res, 5);
        if (!session) return true;
        let body;
        try { body = await readJsonBody(req); } catch (_) { return sendError(res, 400, 'INVALID_JSON', 'Некорректный JSON'), true; }
        const username = String(body.username || '').trim();
        const password = String(body.password || '');
        const level = Number(body.level) || 1;
        if (!USERNAME_RE.test(username)) return sendError(res, 400, 'BAD_USERNAME', 'Логин: 2–32 символа, латиница, цифры, . _ -'), true;
        if (password.length < MIN_PASSWORD_LEN) return sendError(res, 400, 'BAD_PASSWORD', 'Пароль минимум ' + MIN_PASSWORD_LEN + ' символа'), true;
        if (level < 1 || level > 5) return sendError(res, 400, 'BAD_LEVEL', 'Уровень должен быть 1..5'), true;
        if (await db.getUserByUsername(username)) return sendError(res, 409, 'USER_EXISTS', 'Такой логин уже занят'), true;
        const user = await db.createUser({
            username, password,
            displayName: String(body.displayName || username).trim().slice(0, 64) || username,
            level
        });
        safeLog(session, 'admin_user_create', null, username, 'level=' + level);
        sendJson(res, 200, { user });
        return true;
    }

    // /api/users/:id  ·  /api/users/:id/password  ·  /api/users/:id/kick
    const mUser = p.match(/^\/api\/users\/([a-f0-9]{8,16})(\/password|\/kick)?$/);
    if (mUser && ['PUT', 'POST', 'DELETE'].includes(req.method)) {
        const session = await requireSession(req, res, 5);
        if (!session) return true;
        const id = mUser[1];
        const action = mUser[2] || '';
        const target = await db.getUserById(id);
        if (!target) return sendError(res, 404, 'NOT_FOUND', 'Пользователь не найден'), true;

        // Обновление: имя / уровень
        if (req.method === 'PUT' && !action) {
            let body;
            try { body = await readJsonBody(req); } catch (_) { return sendError(res, 400, 'INVALID_JSON', 'Некорректный JSON'), true; }
            if (id === session.userId && body.level !== undefined && Number(body.level) < 5) {
                return sendError(res, 400, 'SELF_DEMOTE', 'Нельзя понизить собственный уровень'), true;
            }
            if (target.level >= 5 && body.level !== undefined && Number(body.level) < 5 && await db.countUsers(5) <= 1) {
                return sendError(res, 400, 'LAST_SUPER', 'Это последний пользователь уровня 5'), true;
            }
            const patch = {};
            if (body.displayName !== undefined) patch.displayName = String(body.displayName).trim().slice(0, 64);
            if (body.level !== undefined) {
                const lvl = Number(body.level);
                if (lvl < 1 || lvl > 5) return sendError(res, 400, 'BAD_LEVEL', 'Уровень должен быть 1..5'), true;
                patch.level = lvl;
            }
            const user = await db.updateUser(id, patch);
            safeLog(session, 'admin_user_update', null, target.username, JSON.stringify(patch));
            sendJson(res, 200, { user });
            return true;
        }

        // Сброс пароля (+ выброс из всех сессий)
        if (req.method === 'POST' && action === '/password') {
            let body;
            try { body = await readJsonBody(req); } catch (_) { return sendError(res, 400, 'INVALID_JSON', 'Некорректный JSON'), true; }
            const password = String(body.password || '');
            if (password.length < MIN_PASSWORD_LEN) return sendError(res, 400, 'BAD_PASSWORD', 'Пароль минимум ' + MIN_PASSWORD_LEN + ' символа'), true;
            await db.setUserPassword(id, password);
            await db.deleteUserSessions(id);
            safeLog(session, 'admin_user_password', null, target.username, '');
            sendJson(res, 200, { ok: true });
            return true;
        }

        // Завершить все сессии пользователя
        if (req.method === 'POST' && action === '/kick') {
            if (id === session.userId) return sendError(res, 400, 'SELF_KICK', 'Нельзя завершить собственные сессии'), true;
            await db.deleteUserSessions(id);
            safeLog(session, 'admin_user_kick', null, target.username, '');
            sendJson(res, 200, { ok: true });
            return true;
        }

        // Удаление
        if (req.method === 'DELETE' && !action) {
            if (id === session.userId) return sendError(res, 400, 'SELF_DELETE', 'Нельзя удалить самого себя'), true;
            if (target.level >= 5 && await db.countUsers(5) <= 1) {
                return sendError(res, 400, 'LAST_SUPER', 'Это последний пользователь уровня 5'), true;
            }
            await db.deleteUser(id);
            safeLog(session, 'admin_user_delete', null, target.username, '');
            sendJson(res, 200, { ok: true });
            return true;
        }
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

    // Полноэкранная страница одного скана (вместо модалки)
    if (/^\/scans\/[a-f0-9]{16,64}$/.test(p)) {
        const session = await getSessionFromReq(req);
        if (!session) return redirect(res, '/auth?next=' + encodeURIComponent(p));
        return serveFile(res, path.join(PUBLIC_DIR, 'scan.html'));
    }

    // Сигнатуры сканера: просмотр всем пользователям панели, запись — ур. 5 (в API)
    if (p === '/signatures') {
        const session = await getSessionFromReq(req);
        if (!session) return redirect(res, '/auth?next=/signatures');
        return serveFile(res, path.join(PUBLIC_DIR, 'signatures.html'));
    }

    // Админ-панель (пользователи): только уровень 5
    if (p === '/admin') {
        const session = await getSessionFromReq(req);
        if (!session) return redirect(res, '/auth?next=/admin');
        if ((session.level || 0) < 5) return redirect(res, '/scans');
        return serveFile(res, path.join(PUBLIC_DIR, 'admin.html'));
    }

    // Публичные статические файлы (js, css, images)
    if (p.startsWith('/js/') || p.startsWith('/css/') || p.startsWith('/images/')) {
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

    // Админ из окружения: если заданы ADMIN_USERNAME + ADMIN_PASSWORD, такой
    // пользователь ГАРАНТИРОВАННО существует с этим паролем и уровнем 5 —
    // работает и на существующей базе: пароль синхронизируется при каждом
    // старте, сессии этого пользователя сбрасываются.
    const envUser = (process.env.ADMIN_USERNAME || '').trim();
    const envPass = process.env.ADMIN_PASSWORD || '';
    if (envUser && envPass) {
        const existing = await db.getUserByUsername(envUser);
        if (existing) {
            await db.setUserPassword(existing.id, envPass);
            await db.deleteUserSessions(existing.id);
            if (Number(existing.level) !== 5) await db.updateUser(existing.id, { level: 5 });
            console.log('[clover] админ из .env: пароль синхронизирован для ' + envUser);
        } else {
            await db.createUser({ username: envUser, password: envPass, displayName: envUser, level: 5 });
            console.log('[clover] создан админ из .env (уровень 5): ' + envUser);
        }
    } else {
        // Без переменных окружения — старое поведение: admin/admin только на пустой базе.
        const seed = await db.seedAdmin();
        if (seed) {
            await db.createUser({
                username: seed.username,
                password: seed.password,
                displayName: seed.username,
                level: 5
            });
            console.log('[clover] создан первый пользователь (уровень 5):');
            console.log('[clover]   логин:  ' + seed.username);
            console.log('[clover]   пароль: ' + seed.password + (process.env.ADMIN_PASSWORD ? '' : '  ← СМЕНИТЕ: задайте ADMIN_USERNAME/ADMIN_PASSWORD в .env'));
        }
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
                if (await handleAdmin(req, res, parsedUrl)) return;
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
        console.log('[clover]   /scans  — сканы (нужен вход)');
        console.log('[clover]   /admin  — админ-панель (уровень 5)');
        console.log('[clover]   /scan   — страница игрока');
        console.log('[clover] БД: data/clover.db (SQLite)');
    });
}

main().catch(e => { console.error('[clover] fatal:', e); process.exit(1); });
