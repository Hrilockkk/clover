// Одноразовый скрипт: скачивает vendor-ассеты (Phosphor regular) в frontend/vendor.
// Запуск: node scripts/fetch-vendor.js
const fs = require('fs');
const path = require('path');
const https = require('https');

const UA = { 'User-Agent': 'Mozilla/5.0' };

function get(url, dest) {
    return new Promise((res, rej) => {
        https.get(url, { headers: UA }, r => {
            if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
                return res(get(new URL(r.headers.location, url).href, dest));
            }
            if (r.statusCode !== 200) return rej(new Error(url + ' -> ' + r.statusCode));
            const chunks = [];
            r.on('data', c => chunks.push(c));
            r.on('end', () => {
                const buf = Buffer.concat(chunks);
                if (dest) {
                    fs.mkdirSync(path.dirname(dest), { recursive: true });
                    fs.writeFileSync(dest, buf);
                }
                res(buf);
            });
        }).on('error', rej);
    });
}

(async () => {
    const base = 'https://unpkg.com/@phosphor-icons/web@2.1.1/src/regular/';
    const dir = path.join(__dirname, '..', 'frontend', 'vendor', 'phosphor');

    let css = (await get(base + 'style.css')).toString('utf8');
    // В CSS шрифт подключается относительным путём — переписываем на локальный.
    const fontFiles = [...new Set([...css.matchAll(/url\(["']?\.?\/?([^"')]+\.(?:woff2?|ttf))["']?\)/g)].map(m => m[1]))];
    console.log('font refs:', fontFiles);
    for (const f of fontFiles) {
        await get(base + f, path.join(dir, f));
        console.log('got', f);
    }
    fs.writeFileSync(path.join(dir, 'style.css'), css);
    console.log('phosphor style.css written');
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
