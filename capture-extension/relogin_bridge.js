// 人工验证后的本地 Cookie 回写桥接。
// 只会在服务端明确标记 manual_required，且 preview 返回的账号 ID 与目标账号
// 完全一致时执行 PUT，避免把同一 Profile 的其它账号 Cookie 写错。
const POLL_MS = 30000;
let running = false;

function authuserFromUrl(raw) {
    try {
        const u = new URL(raw || '');
        return u.searchParams.get('authuser') || (u.pathname.match(/\/u\/(\d+)(?:\/|$)/) || [])[1] || '0';
    } catch (_) { return '0'; }
}

async function cfg() {
    return chrome.storage.local.get(['server', 'adminKey']);
}

async function api(server, key, method, path, body) {
    const resp = await fetch(server.replace(/\/$/, '') + path, {
        method,
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
        body: body ? JSON.stringify(body) : undefined,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data?.detail || data?.error?.message || `HTTP ${resp.status}`);
    return data;
}

async function cookieForStore(storeId) {
    const cookies = await chrome.cookies.getAll({ domain: '.google.com', storeId });
    const pick = (name) => (cookies.find(c => c.name === name && c.domain === '.google.com')
        || cookies.find(c => c.name === name))?.value || '';
    const psid = pick('__Secure-1PSID');
    if (!psid) return null;
    return `__Secure-1PSID=${psid}; __Secure-1PSIDTS=${pick('__Secure-1PSIDTS')}`;
}

async function syncPendingRelogins() {
    if (running) return;
    running = true;
    try {
        const { server, adminKey } = await cfg();
        if (!server || !adminKey) return;
        const data = await api(server, adminKey, 'GET', '/admin/accounts');
        const accounts = data.accounts || [];
        const pending = [];
        for (const account of accounts) {
            try {
                const status = await api(server, adminKey, 'GET', `/admin/accounts/${encodeURIComponent(account.id)}/relogin/status`);
                if (status.status === 'manual_required') pending.push(account);
            } catch (_) { /* 单个账号状态失败不影响其它账号 */ }
        }
        if (!pending.length) return;

        const stores = await chrome.cookies.getAllCookieStores();
        const tabs = await chrome.tabs.query({ url: ['https://gemini.google.com/*'] });
        for (const account of pending) {
            const expected = String(account.authuser || '0');
            for (const tab of tabs) {
                const authuser = authuserFromUrl(tab.url);
                if (authuser !== expected) continue;
                for (const store of stores) {
                    const cookie = await cookieForStore(store.id);
                    if (!cookie) continue;
                    let preview;
                    try {
                        preview = await api(server, adminKey, 'POST', '/admin/accounts/preview', {
                            cookie, authuser, no_wipe: true,
                        });
                    } catch (_) { continue; }
                    if (!preview.valid || preview.duplicate_of !== account.id) continue;
                    try {
                        await api(server, adminKey, 'PUT', `/admin/accounts/${encodeURIComponent(account.id)}/cookies`, { cookie });
                        return;
                    } catch (_) { /* 主服务暂不可用，下一次事件/轮询重试 */ }
                }
            }
        }
    } catch (_) {
        // 配置未完成、浏览器权限或服务端暂时不可用时静默重试。
    } finally {
        running = false;
    }
}

chrome.alarms.create('relogin-cookie-sync', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === 'relogin-cookie-sync') syncPendingRelogins();
});
chrome.tabs.onUpdated.addListener((_tabId, changeInfo) => {
    if (changeInfo.status === 'complete' || changeInfo.url) syncPendingRelogins();
});
chrome.tabs.onActivated.addListener(() => syncPendingRelogins());
chrome.runtime.onStartup.addListener(() => syncPendingRelogins());
chrome.runtime.onInstalled.addListener(() => syncPendingRelogins());
