const $ = (id) => document.getElementById(id);
let pendingCookie = null;
let pendingAuthuser = null;

function showStatus(text, cls) {
    const el = $('status');
    el.textContent = text;
    el.className = cls || '';
    el.classList.remove('hidden');
}

async function getCfg() {
    return chrome.storage.local.get(['server', 'adminKey']);
}

async function getPageContext() {
    try {
        const tabs = await chrome.tabs.query({active: true, lastFocusedWindow: true});
        const tab = tabs[0];
        if (!tab?.id || !/^https:\/\/(?:[\w-]+\.)*google\.[^/]+\//.test(tab.url || '')) return {email: '', authuser: null};
        const u = new URL(tab.url);
        // Gemini/Google expose the selected multi-login account as authuser or /u/N.
        const authuser = u.searchParams.get('authuser') || (u.pathname.match(/\/u\/(\d+)(?:\/|$)/) || [])[1] || null;
        const [{result}] = await chrome.scripting.executeScript({target: {tabId: tab.id}, func: () => {
            const text = document.body?.innerText || '';
            return (text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig) || [])[0] || '';
        }});
        return {email: result || '', authuser};
    } catch (_) { return {email: '', authuser: null}; }
}

async function getPageEmail() {
    return (await getPageContext()).email;
}

async function api(server, key, method, path, body) {
    const resp = await fetch(server.replace(/\/$/, '') + path, {
        method,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${key}`,
        },
        body: body ? JSON.stringify(body) : undefined,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
        throw new Error(data?.error?.message || `HTTP ${resp.status}`);
    }
    return data;
}

async function loadStores() {
    try {
        const stores = await chrome.cookies.getAllCookieStores();
        const sel = $('store');
        if (!sel) return;
        sel.innerHTML = '';
        for (const s of stores) {
            const opt = document.createElement('option');
            opt.value = s.id;
            opt.textContent = s.id === '0' ? '🔓 正常窗口（默认账号）' : '🕶️ 无痕窗口（推荐多账号用）';
            sel.appendChild(opt);
        }
        // 有无痕窗口开着时出现来源选择
        $('storeRow').classList.toggle('hidden', stores.length <= 1);
    } catch (e) {
        // 老内核没有该 API 时静默降级
    }
}

// 打开 popup 即显示「当前 Cookie 属于谁」，换号前先看这里
async function whoami() {
    const el = $('whoami');
    if (!el) return;
    const { server, adminKey } = await getCfg();
    if (!server || !adminKey) return;
    el.textContent = '正在识别当前默认账号…';
    try {
        const cookies = await chrome.cookies.getAll({ domain: '.google.com', storeId: $('store')?.value || undefined });
        const pick = (n) => (cookies.find(c => c.name === n && c.domain === '.google.com') || cookies.find(c => c.name === n))?.value || '';
        const psid = pick('__Secure-1PSID');
        if (!psid) {
            el.textContent = '⚠ 该窗口没有 Google 登录态';
            return;
        }
        const page = await getPageContext();
        const r = await api(server, adminKey, 'POST', '/admin/accounts/preview', {
            cookie: `__Secure-1PSID=${psid}; __Secure-1PSIDTS=${pick('__Secure-1PSIDTS')}`,
            authuser: page.authuser,
            no_wipe: true,
        });
        if (!r.valid) {
            el.textContent = '⚠ 当前默认账号会话已失效（需重新登录）';
        } else if (r.duplicate_of) {
            el.textContent = `当前默认账号：${r.email}（已在池中：${r.duplicate_of}）`;
        } else {
            el.textContent = `当前默认账号：${r.email || '（未识别邮箱）'}`;
        }
    } catch (e) {
        el.textContent = '';
    }
}

function refreshUI() {
    getCfg().then(({ server, adminKey }) => {
        const ok = server && adminKey;
        $('config').classList.toggle('hidden', !!ok);
        $('capture').classList.toggle('hidden', !ok);
        if (server) $('server').value = server;
        loadStores().then(whoami);
    });
}

// 切换 Cookie 来源窗口后重新识别
document.addEventListener('DOMContentLoaded', () => {
    $('store')?.addEventListener('change', whoami);
});

$('save').addEventListener('click', async () => {
    await chrome.storage.local.set({ server: $('server').value.trim(), adminKey: $('adminKey').value.trim() });
    showStatus('配置已保存');
    refreshUI();
});

$('capture').addEventListener('click', async () => {
    pendingCookie = null;
    pendingAuthuser = null;
    $('confirm').classList.add('hidden');
    try {
        const cookies = await chrome.cookies.getAll({ domain: '.google.com', storeId: $('store')?.value || undefined });
        const byName = {};
        for (const c of cookies) {
            if (c.name === '__Secure-1PSID' || c.name === '__Secure-1PSIDTS') {
                // 同名多域时优先 .google.com 规范域
                if (!byName[c.name] || c.domain === '.google.com') byName[c.name] = c.value;
            }
        }
        if (!byName['__Secure-1PSID']) {
            showStatus('未找到 __Secure-1PSID：请先在浏览器登录 gemini.google.com 并切换到目标账号', 'err');
            return;
        }
        pendingCookie = `__Secure-1PSID=${byName['__Secure-1PSID']}; __Secure-1PSIDTS=${byName['__Secure-1PSIDTS'] || ''}`;
        const page = await getPageContext();
        pendingAuthuser = page.authuser;
        showStatus('识别中...');

        const { server, adminKey } = await getCfg();
        const preview = await api(server, adminKey, 'POST', '/admin/accounts/preview', { cookie: pendingCookie, authuser: page.authuser });
        if (!preview.valid) {
            showStatus('✗ 该会话 Cookie 无效或已过期（可能需要重新登录 Gemini）', 'err');
            pendingCookie = null;
            return;
        }
        const who = preview.email || `psid…${preview.psid_suffix}`;
        const pageEmail = page.email;
        if (pageEmail && preview.email && pageEmail.toLowerCase() !== preview.email.toLowerCase()) {
            showStatus(`✗ 账号不一致：当前页面是 ${pageEmail}，会话(${preview.authuser ?? "默认"})属于 ${preview.email}。请在 Gemini 页面切换后重试。`, 'err');
            pendingCookie = null;
            return;
        }
        if (preview.duplicate_of) {
            showStatus(`⚠ ${who} 已在号池：${preview.duplicate_of}，无需重复添加`, 'warn');
            pendingCookie = null;
            return;
        }
        showStatus(`→ ${who}\n确认后将上号（标签自动取邮箱）`);
        $('confirm').classList.remove('hidden');
    } catch (e) {
        showStatus(`✗ ${e.message}`, 'err');
    }
});

$('confirm').addEventListener('click', async () => {
    if (!pendingCookie) return;
    $('confirm').disabled = true;
    try {
        const { server, adminKey } = await getCfg();
        const r = await api(server, adminKey, 'POST', '/admin/accounts', { cookie: pendingCookie, authuser: pendingAuthuser });
        if (r.created === false) {
            showStatus(`⚠ 该账号已存在：${r.account.id}，已更新凭据，未重复添加`, 'warn');
        } else {
            showStatus(`✓ 已上号：${r.account.id}（标签自动获取中，稍后可见邮箱）`);
        }
        pendingCookie = null;
        pendingAuthuser = null;
        $('confirm').classList.add('hidden');
    } catch (e) {
        showStatus(`✗ 上号失败：${e.message}`, 'err');
    } finally {
        $('confirm').disabled = false;
    }
});

refreshUI();
