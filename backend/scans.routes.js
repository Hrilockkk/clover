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
 * Ожидания от db (через scans.js): saveScanRecord/getScanRecord/listScanRecords/searchScanRecords.
 */

const crypto = require('crypto');

const MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024; // 8 MB — расширенный payload сканера (префетч, shimcache, bam, процессы, драйверы)

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
        getSessionFromReq,
        sendJson,
        sendError,
        getClientIp,
        safeLog = () => {}
    } = deps;

    // Доступ: любой авторизованный пользователь панели (есть в списке админов).
    async function requireScanAccess(req, res) {
        const session = await getSessionFromReq(req);
        if (!session) {
            sendError(res, 401, 'UNAUTHORIZED', 'Требуется авторизация');
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
            sendJson(res, 200, { links: scans.listLinks() });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/links' && req.method === 'POST') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const body = await readJsonBody(req);
            const origin = getOrigin(req);
            // Пакетное создание: count > 1 → массив ссылок (проверка всей команды).
            const count = Math.min(Math.max(1, Number(body.count) || 1), scans.MAX_BATCH_LINKS || 50);
            if (count > 1) {
                const links = scans.createLinks({
                    note: body.note, count,
                    adminUser: session.username,
                    adminDisplayName: session.displayName
                });
                safeLog(session, 'scan_link_create_batch', null, String(body.note || ''), 'count=' + count);
                const withUrls = links.map(link => ({
                    ...link,
                    playerUrl: origin + '/scan?id=' + link.id
                }));
                sendJson(res, 200, { links: withUrls });
                return true;
            }
            const link = scans.createLink({
                note: body.note,
                adminUser: session.username,
                adminDisplayName: session.displayName
            });
            safeLog(session, 'scan_link_create', null, String(body.note || ''), 'linkId=' + link.id);
            const downloadUrl = origin + '/api/scans/download/' + link.id + '?p=' + encodeURIComponent(link.playerPassword || '');
            const downloadUrlB64 = origin + '/api/scans/download-b64/' + link.id + '?p=' + encodeURIComponent(link.playerPassword || '');
            // Случайное имя файла, чтобы бинарь не совпадал с репутационными
            // сигнатурами по известному имени.
            const rndName = 'cl_' + crypto.randomBytes(4).toString('hex') + '.exe';
            // CMD one-liner: скачать clover.exe в TEMP, запустить, удалить.
            // В clover.exe встроен конфиг (uploadUrl, scanId, пароль, админ),
            // поэтому работает полностью автономно и самоуничтожается после скана.
            // exe сам повышается через UAC и самоудаляется после скана;
            // del тут — лишь подстраховка, её ошибки игроку не нужны.
            const cmdCommand = 'curl -sL "' + downloadUrl + '" -o "%TEMP%\\' + rndName + '" && "%TEMP%\\' + rndName + '" && del /f "%TEMP%\\' + rndName + '" >nul 2>&1';
            // PowerShell one-liner: качает JSON с base64-бинарём, декодирует, проверяет PE-заголовок
            // (x64), запускает. Обходит CDN, которые подменяют сырой бинарный ответ HTML-челленджем.
            const psCommand = 'powershell -c "$r=iwr -UseBasicParsing -uri \'' + downloadUrlB64 + '\'; $j=$r.Content|ConvertFrom-Json; $b=[Convert]::FromBase64String($j.base64); $fn=$j.name; $p=$env:TEMP+\'\\\'+$fn; [IO.File]::WriteAllBytes($p,$b); if ($b[0]-ne 77 -or $b[1]-ne 90) { throw \"Invalid PE header\" }; $pe=[BitConverter]::ToInt32($b,0x3C); if ([BitConverter]::ToUInt16($b,$pe+4)-ne 0x8664) { throw \"Not x64 binary\" }; & $p; del $p -ErrorAction SilentlyContinue"';
            sendJson(res, 200, { link, cmdCommand, psCommand, downloadUrl, downloadUrlB64, exeName: rndName, playerUrl: origin + '/scan?id=' + link.id });
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
        if (parsedUrl.pathname === '/api/scans/stats' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            sendJson(res, 200, { stats: await scans.getStats() });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/search' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const q = (parsedUrl.searchParams.get('q') || '').trim();
            sendJson(res, 200, { scans: await scans.searchRecords(q), query: q });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/export' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const rows = await scans.listRecords();
            const csv = ['scanId,timestamp,admin,hostname,hwid,hits', ...rows.map(s => [s.scanId, s.timestamp, s.adminDisplayName || s.adminUser || '', s.hardware?.hostname || '', s.hardware?.hwid || '', s.hitCount || 0].map(v => '"' + String(v ?? '').replace(/"/g, '""') + '"').join(','))].join('\n');
            res.writeHead(200, {
                'Content-Type': 'text/csv; charset=utf-8',
                'Content-Disposition': 'attachment; filename=clover-scans.csv'
            });
            res.end('\ufeff' + csv);
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
        // Админ-метаданные скана: статус проверки + заметка (POST сохраняет).
        if (/^\/api\/scans\/meta\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'POST') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const id = parsedUrl.pathname.split('/').pop();
            const body = await readJsonBody(req);
            const status = String(body.status || '');
            if (status && !['review', 'banned', 'cleared'].includes(status)) {
                sendError(res, 400, 'BAD_STATUS', 'status: review | banned | cleared');
                return true;
            }
            const meta = await scans.setScanMeta(id, { status, note: body.note }, session);
            if (!meta) { sendError(res, 404, 'NOT_FOUND', 'Scan not found'); return true; }
            safeLog(session, 'scan_meta', null, id, 'status=' + (status || '-'));
            sendJson(res, 200, { meta });
            return true;
        }
        // Сравнение двух сканов (например двух проверок одного игрока):
        // какие записи появились/исчезли между ними.
        if (parsedUrl.pathname === '/api/scans/diff' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const aId = parsedUrl.searchParams.get('a') || '';
            const bId = parsedUrl.searchParams.get('b') || '';
            const [a, b] = await Promise.all([scans.getRecord(aId), scans.getRecord(bId)]);
            if (!a || !b) { sendError(res, 404, 'NOT_FOUND', 'Scan not found'); return true; }
            sendJson(res, 200, { a: aId, b: bId, changes: scans.diffRecords(a, b) });
            return true;
        }
        // AI-анализ скана через внешний LLM (если настроен в .env).
        if (/^\/api\/scans\/ai\/[a-f0-9]+$/.test(parsedUrl.pathname) && req.method === 'POST') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const ai = require('./ai');
            if (!await ai.isEnabled()) { sendError(res, 400, 'AI_DISABLED', 'AI-анализ не настроен: страница «Настройки» → раздел AI'); return true; }
            const id = parsedUrl.pathname.split('/').pop();
            const rec = await scans.getRecord(id);
            if (!rec) { sendError(res, 404, 'NOT_FOUND', 'Scan not found'); return true; }
            try {
                const verdict = await ai.analyzeScan(rec);
                rec.aiVerdict = verdict;
                const db = require('./database');
                await db.updateScanRecord(rec);
                safeLog(session, 'scan_ai', null, id, verdict.level + ' ' + verdict.confidence + '%');
                sendJson(res, 200, { ai: verdict });
            } catch (e) {
                sendError(res, 502, 'AI_ERROR', String(e.message || e).slice(0, 300));
            }
            return true;
        }
        // Сигнатуры сканера (страница «Сигнатуры»): читать могут все
        // пользователи панели, менять — только уровень 5.
        if (parsedUrl.pathname === '/api/scans/signatures' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            sendJson(res, 200, { signatures: await scans.getSignatures(), defaults: scans.DEFAULT_SIGNATURES });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/signatures' && req.method === 'PUT') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            if ((session.level || 0) < 5) {
                sendError(res, 403, 'FORBIDDEN', 'Менять сигнатуры может только уровень 5');
                return true;
            }
            const body = await readJsonBody(req);
            try {
                const clean = await scans.setSignatures(body.signatures !== undefined ? body.signatures : body);
                safeLog(session, 'signatures_update', null, null,
                    'rules=' + (clean.rules ? clean.rules.length : 0));
                sendJson(res, 200, { signatures: clean });
            } catch (e) {
                sendError(res, 400, 'BAD_SIGNATURES', String(e.message || e));
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
            // Скан с правами админа может идти дольше 10-минутного TTL ссылки —
            // продлеваем её при скачивании, иначе аплоад результата упадёт с 404.
            scans.extendLinkExpiry(id);
            const origin = getOrigin(req);
            let buf;
            try {
                buf = await scans.buildEmbeddedScanner(id, origin, { ip });
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
            scans.extendLinkExpiry(id);
            const origin = getOrigin(req);
            let buf;
            try {
                buf = await scans.buildEmbeddedScanner(id, origin, { ip });
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
                eventId: link.eventId || undefined,
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
                eventId: link.eventId || undefined,
                adminUser: link.adminUser || body.adminUser || '',
                adminDisplayName: link.adminDisplayName || ''
            }));
            console.log('[SCANS] manual uploaded scanId=' + rec.scanId + ' linkId=' + id + ' admin=' + (link.adminUser || '-'));
            sendJson(res, 200, { status: 'ok', scanId: rec.scanId });
            return true;
        }
        // ─── Турнирный режим ──────────────────────────────────────────────
        // Создать событие + пакет ссылок участникам.
        if (parsedUrl.pathname === '/api/scans/events' && req.method === 'POST') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const body = await readJsonBody(req);
            if (!body.name || !String(body.name).trim()) { sendError(res, 400, 'BAD_NAME', 'Нужно название события'); return true; }
            const { event, links } = await scans.createEventWithLinks({
                name: String(body.name).trim(),
                count: body.count,
                adminUser: session.username,
                adminDisplayName: session.displayName
            });
            safeLog(session, 'event_create', null, String(body.name || ''), 'eventId=' + event.id + ' count=' + links.length);
            const origin = getOrigin(req);
            sendJson(res, 200, {
                event,
                links: links.map(l => ({ ...l, playerUrl: origin + '/scan?id=' + l.id })),
                eventUrl: origin + '/event/' + event.id
            });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/events' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const db = require('./database');
            sendJson(res, 200, { events: await db.listEvents() });
            return true;
        }
        // Публичный живой статус события (страница /event/<id>).
        if (/^\/api\/scans\/event\/[a-f0-9]{16}$/.test(parsedUrl.pathname) && req.method === 'GET') {
            const id = parsedUrl.pathname.split('/').pop();
            const status = await scans.eventStatus(id);
            if (!status) { sendError(res, 404, 'NOT_FOUND', 'Event not found'); return true; }
            sendJson(res, 200, status);
            return true;
        }
        // ─── Trust Badge: публичный статус последней проверки по SteamID ──
        if (/^\/api\/scans\/badge\/\d{10,20}$/.test(parsedUrl.pathname) && req.method === 'GET') {
            const steamId = parsedUrl.pathname.split('/').pop();
            const ip = getClientIp(req);
            if (!checkScanRateLimit(ip, SCAN_DOWNLOAD_LIMIT)) { sendError(res, 429, 'RATE_LIMIT', 'Too many requests'); return true; }
            const db = require('./database');
            const last = await db.getLatestScanBySteamId(steamId);
            if (!last) { sendJson(res, 200, { found: false }); return true; }
            // Наружу отдаём только вердикт и дату — без hostname/находок.
            sendJson(res, 200, { found: true, timestamp: last.timestamp, verdict: last.verdict ? last.verdict.level : 'unknown' });
            return true;
        }
        // ─── Watchlist: регулярные проверки ───────────────────────────────
        if (parsedUrl.pathname === '/api/scans/watchlist' && req.method === 'GET') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            sendJson(res, 200, { watchlist: await scans.watchlistStatus() });
            return true;
        }
        if (parsedUrl.pathname === '/api/scans/watchlist' && req.method === 'PUT') {
            const session = await requireScanAccess(req, res);
            if (!session) return true;
            const body = await readJsonBody(req);
            const list = await scans.setWatchlist(body.watchlist !== undefined ? body.watchlist : body);
            safeLog(session, 'watchlist_update', null, null, 'count=' + list.length);
            sendJson(res, 200, { watchlist: await scans.watchlistStatus() });
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
