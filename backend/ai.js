/**
 * ai.js — AI-анализ скана через внешний LLM API (OpenAI-совместимый).
 *
 * Настройка — страница «Настройки» (/settings) или env (.env):
 *   AI_API_URL  — endpoint chat completions, напр. https://api.openai.com/v1/chat/completions
 *   AI_API_KEY  — ключ провайдера
 *   AI_MODEL    — модель (напр. gpt-4o-mini)
 *
 * Payload скана сжимается в компактный дайджест (только подозрительное и
 * аномальное — не сырые таблицы на сотни КБ), вердикт сохраняется в скан.
 */
'use strict';

const https = require('https');
const http = require('http');
const config = require('./config');

async function getAiConfig() {
    const cfg = await config.getRuntimeConfig();
    return { url: cfg.aiApiUrl, key: cfg.aiApiKey, model: cfg.aiModel };
}

async function isEnabled() {
    const c = await getAiConfig();
    return Boolean(c.url && c.key && c.model);
}

// digestScan выжимает из payload скана форензик-дайджест: то, что реально
// влияет на вердикт. Полные таблицы (USN на 20k записей и т.п.) не уходят.
function digestScan(rec) {
    const len = a => (Array.isArray(a) ? a.length : 0);
    const matchedRows = (a, nameFn) => (Array.isArray(a) ? a : [])
        .filter(x => x && (x.matched || x.Matched))
        .slice(0, 20)
        .map(nameFn);
    const c = rec.cleanup || {};
    const hw = rec.hardware || {};
    return {
        hostname: hw.hostname, username: hw.username,
        verdict: rec.verdict || null,
        envFlags: rec.envFlags || [],
        signatureMatches: (rec.results || []).slice(0, 20).map(r => ({ name: r.Name || r.name, path: r.Path || r.path, matched: r.Matched || r.matched })),
        targetFiles: (rec.namedFiles || []).slice(0, 10).map(f => f.Path || f.path),
        targetDirs: (rec.dirs || []).slice(0, 10).map(d => d.Path || d.path),
        deletedTargets: (rec.deletedFiles || []).slice(0, 15).map(f => f.Path || f.path),
        cs2: { connections: len(rec.cs2Conns), rwxRegions: len(rec.cs2Rwx) },
        matchedLaunches: {
            prefetch: matchedRows(rec.prefetch, r => r.name),
            shimcache: matchedRows(rec.shimcache, r => r.path),
            bam: matchedRows(rec.bam, r => r.path),
            execTraces: matchedRows(rec.execTraces, r => r.source + ':' + (r.path || r.name)),
            processes: matchedRows(rec.processes, r => r.path || r.name),
            windows: matchedRows(rec.windows, r => r.title + ' (' + r.process + ')')
        },
        drivers: (Array.isArray(rec.drivers) ? rec.drivers : []).filter(d => d.flag).slice(0, 15).map(d => ({ name: d.name, flag: d.flag, path: d.imagePath })),
        cleanupEvidence: {
            cleanerInis: [...(c.iniOnDisk || []), ...(c.iniDeleted || [])].slice(0, 10).map(i => i.path || i.Path),
            toolRuns: (c.prefetchTools || []).slice(0, 5).map(t => t.name),
            wipedJournals: (c.journals || []).filter(j => j.wiped).map(j => j.drive)
        },
        stoppedCriticalServices: (Array.isArray(rec.services) ? rec.services : []).filter(s => s.exists && s.status !== 'running').map(s => s.name),
        amcacheHits: (rec.amcache || []).slice(0, 10).map(a => ({ name: a.Name || a.name, path: a.Path || a.path })),
        counts: {
            prefetch: len(rec.prefetch), shimcache: len(rec.shimcache), bam: len(rec.bam),
            execTraces: len(rec.execTraces), usn: len(rec.usn), processes: len(rec.processes)
        }
    };
}

const SYSTEM_PROMPT = [
    'Ты — форензик-аналитик античит-панели для CS2. Получаешь JSON-дайджест проверки ПК игрока.',
    'Оцени вероятность читов/сокрытия следов. Учитывай: совпадения сигнатур, удалённые чит-файлы,',
    'клинеры (PrivaZer и т.п.), пересоздание USN-журнала, fsutil/wevtutil, BYOVD/неподписанные драйверы,',
    'RWX-память в cs2.exe, остановленные службы логирования, запуск под VM, окна-оверлеи.',
    'Ответь строго JSON: {"level":"clean|suspicious|flagged","confidence":0-100,"summary":"2-4 предложения по-русски","findings":["главные улики"],"recommendation":"бан/перепроверка/оправдан"}.'
].join('\n');

function chatCompletions(urlString, apiKey, body) {
    return new Promise((resolve, reject) => {
        let url;
        try { url = new URL(urlString); } catch (_) { return reject(new Error('некорректный AI API URL')); }
        const data = Buffer.from(JSON.stringify(body), 'utf8');
        const lib = url.protocol === 'http:' ? http : https;
        const req = lib.request({
            method: 'POST',
            hostname: url.hostname,
            port: url.port || (url.protocol === 'http:' ? 80 : 443),
            path: url.pathname + url.search,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + apiKey,
                'Content-Length': data.length
            },
            timeout: 60000
        }, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                const raw = Buffer.concat(chunks).toString('utf8');
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return reject(new Error('LLM API HTTP ' + res.statusCode + ': ' + raw.slice(0, 200)));
                }
                resolve(raw);
            });
        });
        req.on('timeout', () => { req.destroy(); reject(new Error('LLM API timeout')); });
        req.on('error', reject);
        req.write(data);
        req.end(data);
    });
}

// analyzeScan возвращает { level, confidence, summary, findings, recommendation }.
async function analyzeScan(rec) {
    const cfg = await getAiConfig();
    if (!cfg.url || !cfg.key || !cfg.model) {
        throw new Error('AI-анализ не настроен: задайте API URL, ключ и модель на странице «Настройки»');
    }
    const digest = digestScan(rec);
    const raw = await chatCompletions(cfg.url, cfg.key, {
        model: cfg.model,
        temperature: 0.2,
        response_format: { type: 'json_object' },
        messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: JSON.stringify(digest) }
        ]
    });
    const parsed = JSON.parse(raw);
    const content = parsed.choices && parsed.choices[0] && parsed.choices[0].message && parsed.choices[0].message.content;
    if (!content) throw new Error('пустой ответ LLM');
    const verdict = JSON.parse(content);
    return {
        level: ['clean', 'suspicious', 'flagged'].includes(verdict.level) ? verdict.level : 'suspicious',
        confidence: Math.max(0, Math.min(100, Number(verdict.confidence) || 0)),
        summary: String(verdict.summary || '').slice(0, 2000),
        findings: Array.isArray(verdict.findings) ? verdict.findings.slice(0, 10).map(f => String(f).slice(0, 300)) : [],
        recommendation: String(verdict.recommendation || '').slice(0, 300),
        model: cfg.model,
        at: Date.now()
    };
}

module.exports = { isEnabled, analyzeScan, digestScan };
