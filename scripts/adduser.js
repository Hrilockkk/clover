'use strict';

/**
 * adduser.js — добавление пользователя в панель Clover.
 *
 *   npm run adduser -- <логин> <пароль> [уровень 1..5] [--scan]
 *
 * Примеры:
 *   npm run adduser -- vasya secret123 4          # админ с доступом к сканам
 *   npm run adduser -- moderator pass 2 --scan    # модер с точечным доступом
 */

const db = require('../backend/database');

const args = process.argv.slice(2).filter(a => a !== '--scan');
const canScan = process.argv.includes('--scan');
const [username, password, level] = args;

if (!username || !password) {
    console.error('Использование: npm run adduser -- <логин> <пароль> [уровень 1..5] [--scan]');
    process.exit(1);
}

db.getUserByUsername(username).then(existing => {
    if (existing) {
        console.error('Пользователь "' + username + '" уже существует');
        process.exit(1);
    }
    return db.createUser({ username, password, level: Number(level) || 1, canScan });
}).then(user => {
    if (!user) return;
    console.log('Создан пользователь:', user.username, '· уровень', user.level, '· canScan:', user.canScan);
    process.exit(0);
}).catch(e => {
    console.error('Ошибка:', e.message);
    process.exit(1);
});
