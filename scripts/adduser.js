'use strict';

/**
 * adduser.js — добавление пользователя в панель Clover.
 *
 *   npm run adduser -- <логин> <пароль> [уровень 1..5]
 *
 * Примеры:
 *   npm run adduser -- vasya secret123 4          # админ
 *   npm run adduser -- moderator pass 2           # модер
 */

const db = require('../backend/database');

const [username, password, level] = process.argv.slice(2);

if (!username || !password) {
    console.error('Использование: npm run adduser -- <логин> <пароль> [уровень 1..5]');
    process.exit(1);
}

db.initSchema()
.then(() => db.getUserByUsername(username)).then(existing => {
    if (existing) {
        console.error('Пользователь "' + username + '" уже существует');
        process.exit(1);
    }
    return db.createUser({ username, password, level: Number(level) || 1 });
}).then(user => {
    if (!user) return;
    console.log('Создан пользователь:', user.username, '· уровень', user.level);
    process.exit(0);
}).catch(e => {
    console.error('Ошибка:', e.message);
    process.exit(1);
});
