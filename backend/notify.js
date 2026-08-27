/**
 * notify.js — уведомления о загруженных сканах в Telegram и/или Discord.
 *
 * Настройка — страница «Настройки» (/settings) или env (.env):
 *   TG_BOT_TOKEN / TG_CHAT_ID / DISCORD_WEBHOOK_URL / PUBLIC_BASE_URL
 *
 * Всё fire-and-forget: ошибки отправки логируются, но не влияют на приём
 * скана. Если ни один канал не настроен, модуль ничего не делает.
 */
'use strict';

const https = require('https');
const config = require('./config');

function postJson(urlString, body) {
    return new Promise((resolve) => {
        let url;
        try { url = new URL(urlString); } catch (_) { return resolve(false); }
        const data = Buffer.from(JSON.stringify(body), 'utf8');
        const req = https.request({
            method: 'POST',
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname + url.search,
            headers: { 'Content-Type': 'application/json', 'Content-Length': data.length },
            timeout: 8000
        }, (res) => { res.resume(); resolve(res.statusCode >= 200 && res.statusCode < 300); });
        req.on('timeout', () => { req.destroy(); resolve(false); });
        req.on('error', () => resolve(false));
        req.write(data);
        req.end(data);
    });
}

function verdictEmoji(level) {
    return level === 'flagged' ? '🔴' : (level === 'suspicious' ? '🟡' : '🟢');
}

function verdictText(level) {
    return level === 'flagged' ? 'находки' : (level === 'suspicious' ? 'подозрительно' : 'чисто');
}

function buildMessage(rec, publicBaseUrl) {
    const hw = rec.hardware || {};
    const steam = (rec.steam && Array.isArray(rec.steam.accounts) ? rec.steam.accounts : [])
        .map(a => a.accountName || a.steamId).filter(Boolean).slice(0, 3).join(', ');
    const v = rec.verdict || { score: 0, level: 'clean', reasons: [] };
    const reasons = (v.reasons || []).slice(0, 3).map(r => '· ' + r.reason).join('\n');
    const base = String(publicBaseUrl || '').replace(/\/+$/, '');
    const linkLine = base ? ('\n🔗 ' + base + '/scans/' + rec.scanId) : '';
    return {
        text: verdictEmoji(v.level) + ' *Clover: новый скан* — ' + verdictText(v.level) + ' (score ' + v.score + ')\n'
            + '🖥 ' + (hw.hostname || '?') + (hw.username ? ' / ' + hw.username : '')
            + (steam ? '\n🎮 ' + steam : '')
            + '\n👮 ' + (rec.adminDisplayName || rec.adminUser || '-')
            + (reasons ? '\n' + reasons : '')
            + linkLine
    };
}

async function sendTelegram(text, cfg) {
    if (!cfg.tgBotToken || !cfg.tgChatId) return null; // не настроено
    return postJson('https://api.telegram.org/bot' + cfg.tgBotToken + '/sendMessage', {
        chat_id: cfg.tgChatId,
        text,
        parse_mode: 'Markdown',
        disable_web_page_preview: true
    });
}

async function sendDiscord(text, cfg) {
    if (!cfg.discordWebhook) return null;
    // Discord не понимает Markdown-звёздочки Telegram — размечаем жирным.
    return postJson(cfg.discordWebhook, { content: text.replace(/\*/g, '**') });
}

// scanReceived вызывается из scans.saveRecord после сохранения скана.
// Асинхронно читает конфиг (страница «Настройки» → БД, фолбэк — env).
function scanReceived(rec) {
    config.getRuntimeConfig().then(cfg => {
        if (!cfg.tgBotToken && !cfg.discordWebhook) return;
        const { text } = buildMessage(rec, cfg.publicBaseUrl);
        return Promise.all([sendTelegram(text, cfg), sendDiscord(text, cfg)]).then(([tg, dc]) => {
            if (tg === false || dc === false) {
                console.warn('[notify] delivery failed: tg=' + tg + ' discord=' + dc);
            }
        });
    }).catch(() => {});
}

module.exports = { scanReceived };
