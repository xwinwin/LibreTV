/**
 * 代理请求鉴权模块
 * 为代理请求添加基于 PASSWORD 的鉴权机制
 */

// 从全局配置获取密码哈希（如果存在）
let cachedPasswordHash = null;

// 记录本脚本位置，供动态导入同目录模块使用。
// 经典脚本中 import('./sha256.js') 会相对页面URL解析（得到 /sha256.js 而 404），
// 必须基于脚本自身路径解析到 js/sha256.js。
const PROXY_AUTH_SCRIPT_BASE = (typeof document !== 'undefined' && document.currentScript && document.currentScript.src) || '';

/**
 * 加载 sha256 实现（优先使用页面已加载的库函数，失败时再动态导入模块）
 */
async function loadSha256() {
    if (typeof window._jsSha256 === 'function') {
        return (message) => window._jsSha256(message);
    }
    const base = PROXY_AUTH_SCRIPT_BASE || window.location.href;
    const { sha256 } = await import(new URL('sha256.js', base).href);
    return sha256;
}

/**
 * 获取当前会话的密码哈希
 */
async function getPasswordHash() {
    if (cachedPasswordHash) {
        return cachedPasswordHash;
    }
    
    // 1. 优先从已存储的代理鉴权哈希获取
    const storedHash = localStorage.getItem('proxyAuthHash');
    if (storedHash) {
        cachedPasswordHash = storedHash;
        return storedHash;
    }
    
    // 2. 尝试从密码验证状态获取（password.js 验证后存储的哈希）
    const passwordVerified = localStorage.getItem('passwordVerified');
    const storedPasswordHash = localStorage.getItem('passwordHash');
    if (passwordVerified === 'true' && storedPasswordHash) {
        localStorage.setItem('proxyAuthHash', storedPasswordHash);
        cachedPasswordHash = storedPasswordHash;
        return storedPasswordHash;
    }
    
    // 3. 尝试从用户输入的密码生成哈希
    const userPassword = localStorage.getItem('userPassword');
    if (userPassword) {
        try {
            const sha256 = await loadSha256();
            const hash = await sha256(userPassword);
            localStorage.setItem('proxyAuthHash', hash);
            cachedPasswordHash = hash;
            return hash;
        } catch (error) {
            console.error('生成密码哈希失败:', error);
        }
    }
    
    // 4. 如果用户没有设置密码，尝试使用环境变量中的密码哈希
    if (window.__ENV__ && window.__ENV__.PASSWORD) {
        cachedPasswordHash = window.__ENV__.PASSWORD;
        return window.__ENV__.PASSWORD;
    }
    
    return null;
}

/**
 * 同步获取密码哈希（用于 <img> 等无法异步生成URL的场景）
 */
function getSyncPasswordHash() {
    if (cachedPasswordHash) {
        return cachedPasswordHash;
    }
    try {
        const storedHash = localStorage.getItem('proxyAuthHash');
        if (storedHash) {
            cachedPasswordHash = storedHash;
            return storedHash;
        }
        // password.js 验证后以 JSON 形式存储，其中包含密码哈希
        const pvRaw = localStorage.getItem('passwordVerified');
        if (pvRaw) {
            const pv = JSON.parse(pvRaw);
            if (pv && pv.verified && pv.passwordHash) {
                cachedPasswordHash = pv.passwordHash;
                return pv.passwordHash;
            }
        }
    } catch (e) {
        // 解析失败时返回 null，由调用方决定降级策略
    }
    return null;
}

/**
 * 生成带鉴权参数的代理URL（不带时间戳，适用于图片回退等静态资源场景）
 */
function buildAuthedProxyUrl(targetUrl) {
    const base = (typeof PROXY_URL !== 'undefined' ? PROXY_URL : '/proxy/') + encodeURIComponent(targetUrl);
    const hash = getSyncPasswordHash();
    return hash ? `${base}?auth=${encodeURIComponent(hash)}` : base;
}

/**
 * 封面图加载失败回退：先尝试带鉴权的代理URL，再使用本地占位图
 */
function coverImageFallback(img) {
    const step = parseInt(img.dataset.coverFallback || '0', 10) + 1;
    img.dataset.coverFallback = String(step);
    if (step === 1 && img.dataset.proxiedSrc) {
        img.src = img.dataset.proxiedSrc;
    } else {
        img.onerror = null;
        img.src = 'image/nomedia.png';
        img.classList.remove('object-cover');
        img.classList.add('object-contain');
    }
}

/**
 * 为代理请求URL添加鉴权参数
 */
async function addAuthToProxyUrl(url) {
    try {
        const hash = await getPasswordHash();
        if (!hash) {
            console.warn('无法获取密码哈希，代理请求可能失败');
            return url;
        }
        
        // 添加时间戳防止重放攻击
        const timestamp = Date.now();
        
        // 检查URL是否已包含查询参数
        const separator = url.includes('?') ? '&' : '?';
        
        return `${url}${separator}auth=${encodeURIComponent(hash)}&t=${timestamp}`;
    } catch (error) {
        console.error('添加代理鉴权失败:', error);
        return url;
    }
}

/**
 * 验证代理请求的鉴权
 */
function validateProxyAuth(authHash, serverPasswordHash, timestamp) {
    if (!authHash || !serverPasswordHash) {
        return false;
    }
    
    // 验证哈希是否匹配
    if (authHash !== serverPasswordHash) {
        return false;
    }
    
    // 验证时间戳（10分钟有效期）
    const now = Date.now();
    const maxAge = 10 * 60 * 1000; // 10分钟
    
    if (timestamp && (now - parseInt(timestamp)) > maxAge) {
        console.warn('代理请求时间戳过期');
        return false;
    }
    
    return true;
}

/**
 * 清除缓存的鉴权信息
 */
function clearAuthCache() {
    cachedPasswordHash = null;
    localStorage.removeItem('proxyAuthHash');
}

// 监听密码变化，清除缓存
window.addEventListener('storage', (e) => {
    if (e.key === 'userPassword' || (window.PASSWORD_CONFIG && e.key === window.PASSWORD_CONFIG.localStorageKey)) {
        clearAuthCache();
    }
});

// 导出函数
window.ProxyAuth = {
    addAuthToProxyUrl,
    validateProxyAuth,
    clearAuthCache,
    getPasswordHash,
    getSyncPasswordHash,
    buildAuthedProxyUrl
};

// 封面图回退供内联 onerror 处理器调用
window.coverImageFallback = coverImageFallback;
