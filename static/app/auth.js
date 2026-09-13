/**
 * 认证模块 - 处理token管理和API调用封装
 */

const TOKEN_KEY = 'gemini2api_token';
// 无操作自动登出时长：默认 8 小时（一个工作日），5 分钟对运维面板太苛刻。
// 可用 localStorage.setItem('gemini2api_session_timeout', '<毫秒数>') 按部署自定义。
const SESSION_TIMEOUT = parseInt(localStorage.getItem('gemini2api_session_timeout'), 10)
    || 8 * 60 * 60 * 1000;
let _sessionTimer = null;

function _resetSessionTimer() {
    if (_sessionTimer) clearTimeout(_sessionTimer);
    _sessionTimer = setTimeout(() => {
        if (isAuthenticated()) {
            clearToken();
            window.location.href = '/login.html';
        }
    }, SESSION_TIMEOUT);
}

function _initSessionWatcher() {
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
    events.forEach(evt => {
        document.addEventListener(evt, _resetSessionTimer, { passive: true });
    });
    _resetSessionTimer();
}

/**
 * 获取存储的token
 * @returns {string|null}
 */
function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

/**
 * 检查是否已认证
 * @returns {boolean}
 */
function isAuthenticated() {
    return !!getToken();
}

/**
 * 保存token到本地存储
 * @param {string} token
 */
function saveToken(token) {
    localStorage.setItem(TOKEN_KEY, token);
}

/**
 * 清除token
 */
function clearToken() {
    localStorage.removeItem(TOKEN_KEY);
}

/**
 * 登出
 */
function logout() {
    clearToken();
    window.location.href = '/login.html';
}

/**
 * 通用API请求方法
 * @param {string} method - HTTP方法
 * @param {string} path - API路径
 * @param {Object} body - 请求体
 * @returns {Promise<any>}
 */
async function apiCall(method, path, body = null) {
    const token = getToken();
    const headers = {
        'Content-Type': 'application/json'
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
        method,
        headers
    };

    if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        config.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(path, config);

        // 如果是401错误，重定向到登录页
        if (response.status === 401) {
            clearToken();
            window.location.href = '/login.html';
            throw new Error('未授权');
        }

        const contentType = response.headers.get('content-type');
        let data;

        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else {
            data = await response.text();
        }

        // 如果响应状态码不是 2xx，抛出错误
        if (!response.ok) {
            const errorMessage = (data && typeof data === 'object' && data.error && data.error.message)
                || (data && typeof data === 'object' && data.detail)
                || (data && typeof data === 'object' && data.message)
                || `请求失败 (状态: ${response.status})`;
            throw new Error(errorMessage);
        }

        return data;
    } catch (error) {
        console.error('API请求错误:', error);
        throw error;
    }
}

/**
 * 初始化认证检查
 * @returns {Promise<boolean>}
 */
async function initAuth() {
    if (!isAuthenticated()) {
        window.location.href = '/login.html';
        return false;
    }

    try {
        await apiCall('GET', '/admin/verify');
        _initSessionWatcher();
        return true;
    } catch (error) {
        clearToken();
        window.location.href = '/login.html';
        return false;
    }
}

/**
 * 登录函数（供登录页面使用）
 * @param {string} apiKey - API密钥
 * @returns {Promise<{success: boolean, message?: string}>}
 */
async function login(apiKey) {
    try {
        // 直接保存API密钥作为token
        saveToken(apiKey);

        // 验证API密钥是否有效
        await apiCall('GET', '/health');

        return { success: true };
    } catch (error) {
        clearToken();
        console.error('登录错误:', error);
        return { success: false, message: error.message || '登录失败，请检查API密钥' };
    }
}

// 导出函数
export {
    TOKEN_KEY,
    getToken,
    isAuthenticated,
    saveToken,
    clearToken,
    logout,
    apiCall,
    initAuth,
    login
};

console.log('认证模块已加载');
