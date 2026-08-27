/* ==========================================================================
   Clover — общий UI-кит панели: esc/toast/auth/logout/даты + светлая тема.
   Раньше эти функции копировались в каждую страницу и расходились между
   собой; теперь единая точка. Подключение: <script src="/js/ui.js"></script>
   ПОСЛЕ session.js. Глобалы: esc, toast, authHeaders, logout, fmtDate, fmtTs.
   ========================================================================== */
(function () {
    'use strict';

    // ─── Текст ────────────────────────────────────────────────────────────
    function esc(s) {
        return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    function fmtDate(s) {
        if (!s) return '-';
        try { return new Date(s).toLocaleString(); } catch (_) { return s; }
    }

    function fmtTs(v) {
        if (!v) return '-';
        const d = new Date(v);
        if (isNaN(d)) return '-';
        if (d.getFullYear() < 2000) return '-'; // нулевые/эпохальные даты не показываем
        return d.toLocaleString();
    }

    // ─── Тосты (единый стиль с иконкой; контейнер создаётся сам) ──────────
    function toast(msg, type) {
        let box = document.getElementById('toast');
        if (!box) {
            box = document.createElement('div');
            box.id = 'toast';
            document.body.appendChild(box);
        }
        const el = document.createElement('div');
        el.className = 'toast-item toast-' + (type || 'success');
        const icon = type === 'error' ? 'ph-x-circle' : 'ph-check-circle';
        el.innerHTML = '<i class="ph ' + icon + '"></i>';
        el.appendChild(document.createTextNode(String(msg)));
        box.appendChild(el);
        setTimeout(() => el.remove(), 4000);
    }

    // ─── Сессия / API ─────────────────────────────────────────────────────
    function authHeaders() {
        let u = {};
        try { u = JSON.parse(localStorage.getItem('user') || '{}'); } catch (_) {}
        return u.sessionToken
            ? { 'Authorization': 'Bearer ' + u.sessionToken, 'Content-Type': 'application/json' }
            : { 'Content-Type': 'application/json' };
    }

    async function logout() {
        try { await fetch('/api/logout', { method: 'POST', headers: authHeaders() }); } catch (_) {}
        localStorage.removeItem('user');
        window.location.href = '/auth';
    }

    // ─── Тема (dark по умолчанию, light — [data-theme="light"] на <html>) ──
    const THEME_KEY = 'clover-theme';

    function currentTheme() {
        try { return localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark'; } catch (_) { return 'dark'; }
    }

    function applyTheme(theme) {
        document.documentElement.dataset.theme = theme;
        try { localStorage.setItem(THEME_KEY, theme); } catch (_) {}
        const btn = document.getElementById('themeToggle');
        if (btn) {
            btn.innerHTML = theme === 'light' ? '<i class="ph ph-moon"></i>' : '<i class="ph ph-sun"></i>';
            btn.title = theme === 'light' ? 'Тёмная тема' : 'Светлая тема';
        }
    }

    function toggleTheme() {
        applyTheme(currentTheme() === 'light' ? 'dark' : 'light');
    }

    // Кнопка переключателя: плавающая, добавляется на все страницы панели.
    function injectThemeToggle() {
        if (document.getElementById('themeToggle')) return;
        const btn = document.createElement('button');
        btn.id = 'themeToggle';
        btn.className = 'theme-toggle';
        btn.setAttribute('aria-label', 'Переключить тему');
        btn.addEventListener('click', toggleTheme);
        document.body.appendChild(btn);
        applyTheme(currentTheme());
    }

    // ─── Доступность ──────────────────────────────────────────────────────
    // Icon-only кнопки (<button title="..."><i class="ph ...">) недоступны
    // скринридерам: копируем title в aria-label там, где его нет. Запускается
    // на весь документ и после мутаций (таблицы перерисовываются динамически).
    function enhanceA11y(root) {
        (root || document).querySelectorAll('button[title]:not([aria-label])').forEach(b => {
            if (b.textContent.trim() === '' || b.querySelector('i.ph')) {
                b.setAttribute('aria-label', b.getAttribute('title'));
            }
        });
    }

    function startA11yObserver() {
        enhanceA11y(document);
        let scheduled = false;
        new MutationObserver(() => {
            if (scheduled) return;
            scheduled = true;
            setTimeout(() => { scheduled = false; enhanceA11y(document); }, 300);
        }).observe(document.body, { childList: true, subtree: true });
    }

    // Тему применяем максимально рано, чтобы не было вспышки тёмного фона.
    document.documentElement.dataset.theme = currentTheme();

    window.App = window.App || {};
    window.App.ui = { esc, toast, authHeaders, logout, fmtDate, fmtTs, toggleTheme, injectThemeToggle };

    // Глобалы-алиасы для существующих страниц (постепенно сойдутся на App.ui).
    if (typeof window.esc === 'undefined') window.esc = esc;
    if (typeof window.toast === 'undefined') window.toast = toast;
    if (typeof window.authHeaders === 'undefined') window.authHeaders = authHeaders;
    if (typeof window.logout === 'undefined') window.logout = logout;
    if (typeof window.fmtDate === 'undefined') window.fmtDate = fmtDate;
    if (typeof window.fmtTs === 'undefined') window.fmtTs = fmtTs;

    document.addEventListener('DOMContentLoaded', () => {
        injectThemeToggle();
        startA11yObserver();
    });
})();
