'use strict';

/**
 * scans.routes.js — HTTP-эндпоинты Clover Scans API.
 *
 * Извлечено 1:1 из VibeCoding `src/http/handler.js` (блок «Clover Scans API»),
 * обёрнуто в фабрику с внедрением зависимостей, чтобы модуль можно было
 * подключить к любому Node-серверу (plain http или Express).
 *
 * Использование (plain http):
 *
 *   const scans = require('./scans');
 *   const createScansHandler = require('./scans.routes');
 *   const handleScans = createScansHandler({
 *       scans,                                   // модуль backend/scans.js
 *       db,                                      // ваш DB-слой (см. scans.sql)
 *       getSessionFromReq,                       // async (req) => session | null
 *       requireSession,                          // async (req, res, minLevel) => session | null
 *       sendJson: (res, code, obj) => { ... },   // JSON-ответ
 *       sendError: (res, code, errCode, msg) => { ... },
 *       getClientIp: (req) => string,
 *       safeLog: (session, action, targetSteamId, targetName, details) => {}, // опционально
 *   });
 *
 *   const server = http.createServer(async (req, res) => {
 *       const parsedUrl = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
 *       if (parsedUrl.pathname.startsWith('/api/scans/')) {
 *           const handled = await handleScans(req, res, parsedUrl);
 *           if (handled) return;
 *       }
 *       // ... остальные маршруты
 *   });
 *
 * Для Express: app.use('/api/scans', (req, res) => handleScans(req, res, new URL(req.originalUrl, 'http://x')));
 *
 * Ожидания от session-объекта: { userId, username, displayName, level }.
 * Ожидания от db: getUserById(id) -> { canScan }, getSetting/setSetting (через scans.js),
 *                 saveScanRecord/getScanRecord/listScanRecords/searchScanRecords.
 */

const crypto = require('crypto');

const USER_LEVEL_ADMIN = 4;
const USER_LEVEL_SUPER = 5;
const MAX_REQUEST_BODY_BYTES = 1024 * 1024; // 1 MB

function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        let bodySize = 0;
        let tooLarge = false;
        req.on('data', (chunk) => {
            if (tooLarge) return;
            bodySize += chunk.length;
            if (bodySize > MAX_REQUEST_BODY_BYTES) {
                tooLarge = true;
                reject(new Error('PAYLOAD_TOO_LARGE'));
                try { req.destroy(); } catch (_) {}
                return;
            }
            body += chunk;
        });
        req.on('end', () => {
            if (tooLarge) return;
            try { resolve(body ? JSON.parse(body) : {}); }
            catch (e) { reject(new Error('INVALID_JSON')); }
        });
        req.on('error', reject);
    });
}

// Origin запроса (учитывает reverse-proxy заголовки)
function getOrigin(req) {
    const proto = req.headers['x-forwarded-proto'] || (req.socket && req.socket.encrypted ? 'https' : 'http');
    const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
    return proto + '://' + host;
}

module.exports = function createScansHandler(deps) {
    const {
        scans,
        db,
        getSessionFromReq,
        requireSession,
        sendJson,
        sendError,
        getClientIp,
        safeLog = () => {}
    } = deps;

    // Доступ: пользователь должен иметь canScan=true (per-user toggle «Разрешить сканы»)
    //         ИЛИ level >= scans_min_level (глобальная настройка, по умолчанию 4).
    async function requireScanAccess(req, res) {
        const session = await getSessionFromReq(req);
        if (!session) {
            sendError(res, 401, 'UNAUTHORIZED', 'Требуется авторизация');
            return null;
        }
        const user = await db.getUserById(session.userId);
        const minLevel = await scans.getScansMinLevel(db);
        const allowed = Boolean(user && user.canScan) || session.level >= minLevel;
        if (!allowed) {
            sendError(res, 403, 'FORBIDDEN', 'Нет доступа к сканам (нужно разрешение «Разрешить сканы»)');
            return null;
        }
        return session;
    }

    // In-memory rate limiter для публичных эндпоинтов (download / upload).
    // Лимиты — на IP в минуту, защита от перебора ссылок (Metelis и подобных краулеров).
    const scanIpLimits = new Map();
    const SCAN_LIMIT_WINDOW_MS = 60 * 1000;
    const SCAN_DOWNLOAD_LIMIT = 10;
    const SCAN_UPLOAD_LIMIT = 10;

    function checkScanRateLimit(ip, limit) {
        const now = Date.now();
        let entry = scanIpLimits.get(ip);
        if (!entry || now > entry.reset) {
            entry = { count: 0, reset: now + SCAN_LIMIT_WINDOW_MS };
        }
        entry.count++;
        scanIpLimits.set(ip, entry);
        return entry.count <= limit;
    }

    /**
     * Возвращает true, если запрос был обработан (маршрут /api/scans/* найден),
     * false — если путь не относится к сканам и надо передать дальше.
     */
    return async function handleScansRequest(req, res, parsedUrl) {
        if (parsedUrl.pathname === '/api/scans/links' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            sendJson(res, 200, { links: scans.listLinks(), minLevel: await scans.getScansMinLevel(db) });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/links' && req.method === 'POST') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const body = await readJsonBody(req);
            const link = scans.createLink({
                note: body.note,
                adminUser: session.username,
                adminDisplayName: session.displayName
            });
            safeLog(session, 'scan_link_create', null, String(body.note || ''), 'linkId=' + link.id);
            const origin = getOrigin(req);
            const downloadUrl = origin + '/api/scans/download/' + link.id + '?p=' + encodeURIComponent(link.playerPassword || '');
            const downloadUrlB64 = origin + '/api/scans/download-b64/' + link.id + '?p=' + encodeURIComponent(link.playerPassword || '');
            // Случайное имя файла, чтобы бинарь не совпадал с репутационными
            // сигнатурами по известному имени.
            const rndName = 'cl_' + crypto.randomBytes(4).toString('hex') + '.exe';
            // CMD one-liner: скачать clover.exe в TEMP, запустить, удалить.
            // В clover.exe встроен конфиг (uploadUrl, scanId, пароль, админ),
            // поэтому работает полностью автономно и самоуничтожается после скана.
            const cmdCommand = 'curl -sL "' + downloadUrl + '" -o "%TEMP%\\' + rndName + '" && "%TEMP%\\' + rndName + '" && del /f "%TEMP%\\' + rndName + '"';
            // PowerShell one-liner: качает JSON с base64-бинарём, декодирует, проверяет PE-заголовок
            // (x64), запускает. Обходит CDN, которые подменяют сырой бинарный ответ HTML-челленджем.
            const psCommand = 'powershell -c "$r=iwr -uri \'' + downloadUrlB64 + '\'; $j=$r.Content|ConvertFrom-Json; $b=[Convert]::FromBase64String($j.base64); $fn=$j.name; $p=$env:TEMP+\'\\\'+$fn; [IO.File]::WriteAllBytes($p,$b); if ($b[0]-ne 77 -or $b[1]-ne 90) { throw \"Invalid PE header\" }; $pe=[BitConverter]::ToInt32($b,0x3C); if ([BitConverter]::ToUInt16($b,$pe+4)-ne 0x8664) { throw \"Not x64 binary\" }; & $p; del $p"';
            sendJson(res, 200, { link, cmdCommand, psCommand, downloadUrl, downloadUrlB64, exeName: rndName });
            return true;
        }
        if (/^\/api\/scans\/links\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'DELETE') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const id = parsedUrl.pathname.split('/').pop();
            scans.deleteLink(id);
            safeLog(session, 'scan_link_delete', null, null, 'linkId=' + id);
            sendJson(res, 200, { ok: true });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/list' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            sendJson(res, 200, { scans: await scans.listRecords() });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/search' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const q = (parsedUrl.searchParams.get('q') || '').trim();
            sendJson(res, 200, { scans: await scans.searchRecords(q), query: q });
            return true;
        }
        if (/^\/api\/scans\/view\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const id = parsedUrl.pathname.split('/').pop();
            const rec = await scans.getRecord(id);
            if (!rec) { sendError(res, 404, 'NOT_FOUND', 'Scan not found'); return true; }
            sendJson(res, 200, rec);
            return true;
        }
        // Настройки: минимальный уровень доступа к /scans (менять может только уровень 5)
        if (parsedUrl.pathname === '/api/scans/level' && req.method === 'GET') {
            const session = await requireSession(req, res, USER_LEVEL_ADMIN);
            if (!session) return true;
            sendJson(res, 200, { minLevel: await scans.getScansMinLevel(db) });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/level' && req.method === 'POST') {
            const session = await requireSession(req, res, USER_LEVEL_SUPER);
            if (!session) return true;
            const body = await readJsonBody(req);
            try {
                const lvl = await scans.setScansMinLevel(db, body.minLevel);
                safeLog(session, 'scan_level_update', null, null, 'minLevel=' + lvl);
                sendJson(res, 200, { minLevel: lvl });
            } catch (e) {
                sendError(res, 400, 'BAD_LEVEL', String(e.message || e));
            }
            return true;
        }
        // Скачивание готового clover.exe со встроенным конфигом конкретной ссылки
        if (/^\/api\/scans\/download\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'GET') {
            const id = parsedUrl.pathname.split('/').pop();
            const ip = getClientIp(req);
            if (!checkScanRateLimit(ip, SCAN_DOWNLOAD_LIMIT)) {
                sendError(res, 429, 'RATE_LIMIT', 'Too many download requests');
                return true;
            }
            const link = scans.getLink(id);
            if (!link) { sendError(res, 404, 'NOT_FOUND', 'Link not found'); return true; }
            const providedPassword = parsedUrl.searchParams.get('p') || '';
            if (providedPassword !== (link.playerPassword || '')) {
                sendError(res, 403, 'FORBIDDEN', 'Invalid password');
                return true;
            }
            const origin = getOrigin(req);
            let buf;
            try {
                buf = scans.buildEmbeddedScanner(id, origin);
            } catch (e) {
                sendError(res, 404, 'NOT_AVAILABLE', String(e.message || e));
                return true;
            }
            res.writeHead(200, {
                'Content-Type': 'application/octet-stream',
                'Content-Disposition': 'attachment; filename=download.exe',
                'Content-Length': buf.length
            });
            res.end(buf);
            return true;
        }
        // Тот же clover.exe, обёрнутый в JSON/base64 — для обхода CDN/фильтров,
        // которые подменяют сырой бинарный ответ на HTML-страницу с челленджем.
        if (/^\/api\/scans\/download-b64\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'GET') {
            const id = parsedUrl.pathname.split('/').pop();
            const ip = getClientIp(req);
            if (!checkScanRateLimit(ip, SCAN_DOWNLOAD_LIMIT)) {
                sendError(res, 429, 'RATE_LIMIT', 'Too many download requests');
                return true;
            }
            const link = scans.getLink(id);
            if (!link) { sendError(res, 404, 'NOT_FOUND', 'Link not found'); return true; }
            const providedPassword = parsedUrl.searchParams.get('p') || '';
            if (providedPassword !== (link.playerPassword || '')) {
                sendError(res, 403, 'FORBIDDEN', 'Invalid password');
                return true;
            }
            const origin = getOrigin(req);
            let buf;
            try {
                buf = scans.buildEmbeddedScanner(id, origin);
            } catch (e) {
                sendError(res, 404, 'NOT_AVAILABLE', String(e.message || e));
                return true;
            }
            const rndName = 'cl_' + crypto.randomBytes(4).toString('hex') + '.exe';
            sendJson(res, 200, { base64: buf.toString('base64'), name: rndName, size: buf.length });
            return true;
        }
        // Приём результатов от clover.exe (публичный, без сессии — авторизация по ссылке)
        if (/^\/api\/scans\/upload\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'POST') {
            const id = parsedUrl.pathname.split('/').pop();
            const ip = getClientIp(req);
            if (!checkScanRateLimit(ip, SCAN_UPLOAD_LIMIT)) {
                sendError(res, 429, 'RATE_LIMIT', 'Too many upload requests');
                return true;
            }
            const link = scans.getLink(id);
            if (!link) { sendError(res, 404, 'LINK_NOT_FOUND', 'Scan link not found'); return true; }
            let body = await readJsonBody(req);
            // Clover шифрует payload тем же AES-256-GCM ключом, что и встроенный
            // конфиг. Если тело — { encrypted: base64 }, расшифровываем;
            // иначе принимаем plain JSON (legacy / standalone-режим).
            try {
                if (body && typeof body.encrypted === 'string') {
                    const decrypted = scans.decryptPayload(body.encrypted);
                    body = JSON.parse(decrypted);
                }
            } catch (e) {
                console.warn('[SCANS] upload decrypt failed:', e.message);
                sendError(res, 400, 'DECRYPT_ERROR', 'Failed to decrypt scan payload');
                return true;
            }
            const rec = await scans.saveRecord(Object.assign({}, body, {
                linkId: id,
                adminUser: link.adminUser || body.adminUser || '',
                adminDisplayName: link.adminDisplayName || ''
            }));
            console.log('[SCANS] uploaded scanId=' + rec.scanId + ' linkId=' + id + ' admin=' + (link.adminUser || '-'));
            sendJson(res, 200, { status: 'ok', scanId: rec.scanId });
            return true;
        }
        // Ручная загрузка: игрок/админ перетаскивает зашифрованный .enc-файл,
        // который Clover создал рядом с собой, если автоматическая отправка не удалась.
        // Тело — тот же JSON-конверт { encrypted: base64 }.
        if (/^\/api\/scans\/upload-manual\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'POST') {
            const id = parsedUrl.pathname.split('/').pop();
            const ip = getClientIp(req);
            if (!checkScanRateLimit(ip, SCAN_UPLOAD_LIMIT)) {
                sendError(res, 429, 'RATE_LIMIT', 'Too many upload requests');
                return true;
            }
            const link = scans.getLink(id);
            if (!link) { sendError(res, 404, 'LINK_NOT_FOUND', 'Scan link not found'); return true; }
            let body = await readJsonBody(req);
            try {
                if (body && typeof body.encrypted === 'string') {
                    const decrypted = scans.decryptPayload(body.encrypted);
                    body = JSON.parse(decrypted);
                }
            } catch (e) {
                console.warn('[SCANS] manual upload decrypt failed:', e.message);
                sendError(res, 400, 'DECRYPT_ERROR', 'Failed to decrypt scan payload');
                return true;
            }
            const rec = await scans.saveRecord(Object.assign({}, body, {
                linkId: id,
                adminUser: link.adminUser || body.adminUser || '',
                adminDisplayName: link.adminDisplayName || ''
            }));
            console.log('[SCANS] manual uploaded scanId=' + rec.scanId + ' linkId=' + id + ' admin=' + (link.adminUser || '-'));
            sendJson(res, 200, { status: 'ok', scanId: rec.scanId });
            return true;
        }
        // JSON-описание ссылки для страницы игрока /scan?id=...
        if (/^\/api\/scans\/page\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'GET') {
            const id = parsedUrl.pathname.split('/').pop();
            const link = scans.getLink(id);
            if (!link) { sendError(res, 404, 'NOT_FOUND', 'Link not found'); return true; }
            sendJson(res, 200, {
                id: link.id,
                note: link.note,
                hasPassword: Boolean(link.playerPassword),
                password: link.playerPassword || '',
                adminDisplayName: link.adminDisplayName || '',
                expiresAt: link.expiresAt || 0,
                downloadUrl: '/api/scans/download/' + link.id + '?p=' + encodeURIComponent(link.playerPassword || '')
            });
            return true;
        }

        return false; // не наш маршрут
    };
};
