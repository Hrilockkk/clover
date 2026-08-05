function escapeHtml(s) {
    const x = String(s ?? '');
    return x.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Экранирование для передачи в onclick="addToWhitelist('...', '...')"
function escapeForOnclick(s) {
    if (s == null || s === '') return '';
    return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/[\r\n]/g, ' ').slice(0, 64);
}

function getCurrentUser() {
    try {
        return JSON.parse(localStorage.getItem('user') || '{}');
    } catch (_) { return {}; }
}

function setCurrentUserPatch(patch) {
    try {
        const cur = getCurrentUser();
        localStorage.setItem('user', JSON.stringify({ ...cur, ...patch }));
    } catch (_) {}
}

function getUserLevel() {
    return getCurrentUser().level || 0;
}

function getSessionToken() {
    try { return (JSON.parse(localStorage.getItem('user') || '{}')).sessionToken || ''; } catch { return ''; }
}

function apiAuthHeaders() {
    const token = getSessionToken();
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

window.App = window.App || {};
window.App.session = {
    escapeHtml,
    escapeForOnclick,
    getCurrentUser,
    setCurrentUserPatch,
    getUserLevel,
    getSessionToken,
    apiAuthHeaders
};

