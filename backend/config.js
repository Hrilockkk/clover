/**
 * config.js — рантайм-конфигурация панели, редактируемая со страницы
 * «Настройки» (/settings, уровень 5). Приоритет: значение в БД (settings →
 * ключ runtimeConfig) > переменная окружения (.env). Секреты в БД хранятся
 * открытым текстом — как и в .env; наружу (GET /api/config) отдаются
 * маской, записать новое значение можно всегда, пустое = «не менять».
 */
'use strict';

const db = require('./database');

const SETTINGS_KEY = 'runtimeConfig';

// Поле → env-фолбэк. secret: true — маскируется при чтении через API.
const FIELDS = [
    { key: 'aiApiUrl',        env: 'AI_API_URL',         secret: false, label: 'AI: API URL' },
    { key: 'aiApiKey',        env: 'AI_API_KEY',         secret: true,  label: 'AI: API ключ' },
    { key: 'aiModel',         env: 'AI_MODEL',           secret: false, label: 'AI: модель' },
    { key: 'tgBotToken',      env: 'TG_BOT_TOKEN',       secret: true,  label: 'Telegram: токен бота' },
    { key: 'tgChatId',        env: 'TG_CHAT_ID',         secret: false, label: 'Telegram: chat ID' },
    { key: 'discordWebhook',  env: 'DISCORD_WEBHOOK_URL', secret: true, label: 'Discord: webhook URL' },
    { key: 'publicBaseUrl',   env: 'PUBLIC_BASE_URL',    secret: false, label: 'Публичный адрес панели' }
];

async function getStored() {
    const raw = await db.getSetting(SETTINGS_KEY, {});
    return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
}

// getRuntimeConfig — полный конфиг для внутренних потребителей (ai, notify).
async function getRuntimeConfig() {
    const stored = await getStored();
    const out = {};
    for (const f of FIELDS) {
        const v = stored[f.key];
        out[f.key] = (typeof v === 'string' && v.trim()) ? v.trim() : (process.env[f.env] || '');
    }
    return out;
}

// getPublicConfig — для GET /api/config: секреты маской + флаг «задано».
async function getPublicConfig() {
    const cfg = await getRuntimeConfig();
    const stored = await getStored();
    const out = {};
    for (const f of FIELDS) {
        const v = cfg[f.key] || '';
        out[f.key] = {
            label: f.label,
            secret: f.secret,
            // set: значение реально задано (в БД или env), fromEnv: из окружения
            set: Boolean(v),
            fromEnv: !stored[f.key] && Boolean(process.env[f.env]),
            value: f.secret ? '' : v,
            hint: f.secret && v ? '••••••' + v.slice(-4) : ''
        };
    }
    return out;
}

// setRuntimeConfig сохраняет переданные поля; пустая строка для секрета =
// «оставить как было», для обычного поля = очистить (вернётся env-фолбэк).
async function setRuntimeConfig(patch) {
    const stored = await getStored();
    for (const f of FIELDS) {
        if (!(f.key in patch)) continue;
        const v = String(patch[f.key] ?? '').trim();
        if (f.secret && !v) continue; // секрет не затираем пустым
        if (v) stored[f.key] = v; else delete stored[f.key];
    }
    await db.setSetting(SETTINGS_KEY, stored);
    return getPublicConfig();
}

module.exports = { getRuntimeConfig, getPublicConfig, setRuntimeConfig, FIELDS };
