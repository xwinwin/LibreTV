// /netlify/functions/proxy.mjs - Netlify Function (ES Module)

import fetch from 'node-fetch';
import { URL } from 'url'; // Use Node.js built-in URL
import crypto from 'crypto'; // 导入 crypto 模块用于密码哈希

// --- Configuration (Read from Environment Variables) ---
const DEBUG_ENABLED = process.env.DEBUG === 'true';
const CACHE_TTL = parseInt(process.env.CACHE_TTL || '86400', 10); // Default 24 hours
const MAX_RECURSION = parseInt(process.env.MAX_RECURSION || '5', 10); // Default 5 levels

// --- User Agent Handling ---
let USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
];
try {
    const agentsJsonString = process.env.USER_AGENTS_JSON;
    if (agentsJsonString) {
        const parsedAgents = JSON.parse(agentsJsonString);
        if (Array.isArray(parsedAgents) && parsedAgents.length > 0) {
            USER_AGENTS = parsedAgents;
            console.log(`[Proxy Log Netlify] Loaded ${USER_AGENTS.length} user agents from environment variable.`);
        } else {
            console.warn("[Proxy Log Netlify] USER_AGENTS_JSON environment variable is not a valid non-empty array, using default.");
        }
    } else {
        console.log("[Proxy Log Netlify] USER_AGENTS_JSON environment variable not set, using default user agents.");
    }
} catch (e) {
    console.error(`[Proxy Log Netlify] Error parsing USER_AGENTS_JSON environment variable: ${e.message}. Using default user agents.`);
}
const FILTER_DISCONTINUITY = false; // Ad filtering disabled

// --- Helper Functions (Same as Vercel version, except rewriteUrlToProxy) ---

function logDebug(message) {
    if (DEBUG_ENABLED) {
        console.log(`[Proxy Log Netlify] ${message}`);
    }
}

// --- SSRF 防护：校验目标 URL 是否允许代理 ---
// 阻止回环地址、私有网段、链路本地（云元数据）、CGNAT 等内网目标。
// 注意：URL 规范化后，十进制/十六进制 IP 写法（如 http://2130706433）也会变成点分形式，可被下方规则覆盖。
function isValidTargetUrl(rawUrl) {
    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch (e) {
        return false;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return false;
    }
    const host = parsed.hostname.toLowerCase();
    // 常见回环/保留域名
    const blockedHostnames = ['localhost', '0.0.0.0', '127.0.0.1', '::1', '[::1]', 'localtest.me', 'lvh.me'];
    if (blockedHostnames.includes(host)) {
        return false;
    }
    // IPv4 私有/保留网段
    const ipv4Match = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (ipv4Match) {
        const a = parseInt(ipv4Match[1], 10);
        const b = parseInt(ipv4Match[2], 10);
        if (a === 0 || a === 10 || a === 127) return false;            // 0.0.0.0/8, 10/8, 127/8
        if (a === 192 && b === 168) return false;                      // 192.168/16
        if (a === 172 && b >= 16 && b <= 31) return false;             // 172.16/12
        if (a === 169 && b === 254) return false;                      // 169.254/16（云元数据）
        if (a === 100 && b >= 64 && b <= 127) return false;            // 100.64/10（CGNAT）
        return true;
    }
    // IPv6
    const v6 = host.replace(/^\[|\]$/g, '');
    if (v6.includes(':')) {
        if (v6 === '::' || v6 === '::1') return false;                 // 未指定/回环
        const mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);      // IPv4-mapped 地址（点分形式）按 IPv4 规则校验
        if (mapped) {
            return isValidTargetUrl('http://' + mapped[1] + '/');
        }
        const mappedHex = v6.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i); // WHATWG 会规范化为 hex 形式（如 ::ffff:7f00:1）
        if (mappedHex) {
            const hi = parseInt(mappedHex[1], 16);                      // 高 16 位 = IPv4 前两个八位组
            const a = Math.floor(hi / 256);
            const b = hi % 256;
            if (a === 0 || a === 10 || a === 127) return false;         // 0/8, 10/8, 127/8
            if (a === 192 && b === 168) return false;                   // 192.168/16
            if (a === 172 && b >= 16 && b <= 31) return false;          // 172.16/12
            if (a === 169 && b === 254) return false;                   // 169.254/16（云元数据）
            if (a === 100 && b >= 64 && b <= 127) return false;         // 100.64/10（CGNAT）
            return true;
        }
        const firstGroup = v6.split(':')[0];                           // ULA fc00::/7
        if (/^[0-9a-f]{1,4}$/.test(firstGroup)) {
            const n = parseInt(firstGroup, 16);
            if (n >= 0xfc00 && n <= 0xfdff) return false;
        }
        return true;
    }
    // 普通域名放行（DNS 解析在服务器端完成，重定向会再次校验）
    return true;
}

function getTargetUrlFromPath(encodedPath) {
    if (!encodedPath) { logDebug("getTargetUrlFromPath received empty path."); return null; }
    try {
        const decodedUrl = decodeURIComponent(encodedPath);
        if (decodedUrl.match(/^https?:\/\/.+/i)) { return decodedUrl; }
        else {
            logDebug(`Invalid decoded URL format: ${decodedUrl}`);
            if (encodedPath.match(/^https?:\/\/.+/i)) { logDebug(`Warning: Path was not encoded but looks like URL: ${encodedPath}`); return encodedPath; }
            return null;
        }
    } catch (e) { logDebug(`Error decoding target URL: ${encodedPath} - ${e.message}`); return null; }
}

function getBaseUrl(urlStr) {
    if (!urlStr) return '';
    try {
        const parsedUrl = new URL(urlStr);
        const pathSegments = parsedUrl.pathname.split('/').filter(Boolean);
        if (pathSegments.length <= 1) { return `${parsedUrl.origin}/`; }
        pathSegments.pop(); return `${parsedUrl.origin}/${pathSegments.join('/')}/`;
    } catch (e) {
        logDebug(`Getting BaseUrl failed for "${urlStr}": ${e.message}`);
        const lastSlashIndex = urlStr.lastIndexOf('/');
        if (lastSlashIndex > urlStr.indexOf('://') + 2) { return urlStr.substring(0, lastSlashIndex + 1); }
        return urlStr + '/';
    }
}

function resolveUrl(baseUrl, relativeUrl) {
    if (!relativeUrl) return ''; if (relativeUrl.match(/^https?:\/\/.+/i)) { return relativeUrl; } if (!baseUrl) return relativeUrl;
    try { return new URL(relativeUrl, baseUrl).toString(); }
    catch (e) {
        logDebug(`URL resolution failed: base="${baseUrl}", relative="${relativeUrl}". Error: ${e.message}`);
        if (relativeUrl.startsWith('/')) { try { const baseOrigin = new URL(baseUrl).origin; return `${baseOrigin}${relativeUrl}`; } catch { return relativeUrl; } }
        else { return `${baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1)}${relativeUrl}`; }
    }
}

// ** MODIFIED for Netlify redirect **
function rewriteUrlToProxy(targetUrl) {
    if (!targetUrl || typeof targetUrl !== 'string') return '';
    // Use the path defined in netlify.toml 'from' field
    return `/proxy/${encodeURIComponent(targetUrl)}`;
}

function getRandomUserAgent() { return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)]; }

/**
 * 验证代理请求的鉴权
 */
function validateAuth(event) {
    const params = new URLSearchParams(event.queryStringParameters || {});
    const authHash = params.get('auth');
    const timestamp = params.get('t');
    
    // 获取服务器端密码哈希
    const serverPassword = process.env.PASSWORD;
    if (!serverPassword) {
        console.error('服务器未设置 PASSWORD 环境变量，代理访问被拒绝');
        return false;
    }
    
    // 使用 crypto 模块计算 SHA-256 哈希
    const serverPasswordHash = crypto.createHash('sha256').update(serverPassword).digest('hex');
    
    if (!authHash || authHash !== serverPasswordHash) {
        console.warn('代理请求鉴权失败：密码哈希不匹配');
        return false;
    }
    
    // 验证时间戳（10分钟有效期）
    if (timestamp) {
        const now = Date.now();
        const maxAge = 10 * 60 * 1000; // 10分钟
        if (now - parseInt(timestamp) > maxAge) {
            console.warn('代理请求鉴权失败：时间戳过期');
            return false;
        }
    }
    
    return true;
}

async function fetchContentWithType(targetUrl, requestHeaders) {
    const baseHeaders = {
        'User-Agent': getRandomUserAgent(),
        'Accept': (requestHeaders && requestHeaders['accept']) || '*/*',
        'Accept-Language': (requestHeaders && requestHeaders['accept-language']) || 'zh-CN,zh;q=0.9,en;q=0.8',
    };
    const MAX_REDIRECTS = 5;
    let currentUrl = targetUrl;

    for (let redirectCount = 0; ; redirectCount++) {
        // SSRF 防护：每一跳（含重定向目标）都重新校验
        if (!isValidTargetUrl(currentUrl)) {
            logDebug(`Target URL failed SSRF check: ${currentUrl}`);
            const err = new Error(`Invalid target URL: ${currentUrl}`);
            err.status = 400;
            throw err;
        }

        const headers = { ...baseHeaders };
        // 尝试设置一个合理的 Referer（同域，部分图床防盗链依赖此头）
        try {
            headers['Referer'] = (requestHeaders && requestHeaders['referer']) || new URL(currentUrl).origin;
        } catch (e) { /* currentUrl 已通过校验，此处不会失败 */ }
        Object.keys(headers).forEach(key => headers[key] === undefined || headers[key] === null || headers[key] === '' ? delete headers[key] : {});
        logDebug(`Fetching target: ${currentUrl} with headers: ${JSON.stringify(headers)}`);

        try {
            // 手动处理重定向：每跳都重新做 SSRF 校验，防止被 302 跳到内网地址
            const response = await fetch(currentUrl, { headers, redirect: 'manual' });

            if ([301, 302, 303, 307, 308].includes(response.status)) {
                const location = response.headers.get('location');
                if (!location) {
                    throw new Error(`Redirect response missing Location header: ${currentUrl}`);
                }
                if (redirectCount >= MAX_REDIRECTS) {
                    throw new Error(`Too many redirects (${MAX_REDIRECTS}): ${targetUrl}`);
                }
                logDebug(`Following redirect (${response.status}) -> ${location}`);
                currentUrl = new URL(location, currentUrl).toString();
                continue;
            }

            if (!response.ok) {
                const errorBody = await response.text().catch(() => '');
                logDebug(`Fetch failed: ${response.status} ${response.statusText} - ${currentUrl}`);
                const err = new Error(`HTTP error ${response.status}: ${response.statusText}. URL: ${currentUrl}. Body: ${errorBody.substring(0, 200)}`);
                err.status = response.status; throw err;
            }

            // 用 ArrayBuffer 保留二进制原样，避免 .text() 的 UTF-8 编解码损坏图片等二进制数据
            const buffer = await response.arrayBuffer();
            const content = new TextDecoder('utf-8').decode(buffer);
            const contentType = response.headers.get('content-type') || '';
            logDebug(`Fetch success: ${currentUrl}, Content-Type: ${contentType}, Length: ${buffer.byteLength}`);
            return { buffer, content, contentType, responseHeaders: response.headers };
        } catch (error) {
            logDebug(`Fetch exception for ${currentUrl}: ${error.message}`);
            const wrapped = new Error(`Failed to fetch target URL ${currentUrl}: ${error.message}`, { cause: error });
            if (error.status) wrapped.status = error.status;
            throw wrapped;
        }
    }
}

function isM3u8Content(content, contentType) {
    if (contentType && (contentType.includes('application/vnd.apple.mpegurl') || contentType.includes('application/x-mpegurl') || contentType.includes('audio/mpegurl'))) { return true; }
    return content && typeof content === 'string' && content.trim().startsWith('#EXTM3U');
}

function processKeyLine(line, baseUrl) { return line.replace(/URI="([^"]+)"/, (match, uri) => { const absoluteUri = resolveUrl(baseUrl, uri); logDebug(`Processing KEY URI: Original='${uri}', Absolute='${absoluteUri}'`); return `URI="${rewriteUrlToProxy(absoluteUri)}"`; }); }
function processMapLine(line, baseUrl) { return line.replace(/URI="([^"]+)"/, (match, uri) => { const absoluteUri = resolveUrl(baseUrl, uri); logDebug(`Processing MAP URI: Original='${uri}', Absolute='${absoluteUri}'`); return `URI="${rewriteUrlToProxy(absoluteUri)}"`; }); }
function processMediaPlaylist(url, content) {
    const baseUrl = getBaseUrl(url); if (!baseUrl) { logDebug(`Could not determine base URL for media playlist: ${url}. Cannot process relative paths.`); }
    const lines = content.split('\n'); const output = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim(); if (!line && i === lines.length - 1) { output.push(line); continue; } if (!line) continue;
        if (line.startsWith('#EXT-X-KEY')) { output.push(processKeyLine(line, baseUrl)); continue; }
        if (line.startsWith('#EXT-X-MAP')) { output.push(processMapLine(line, baseUrl)); continue; }
        if (line.startsWith('#EXTINF')) { output.push(line); continue; }
        if (!line.startsWith('#')) { const absoluteUrl = resolveUrl(baseUrl, line); logDebug(`Rewriting media segment: Original='${line}', Resolved='${absoluteUrl}'`); output.push(rewriteUrlToProxy(absoluteUrl)); continue; }
        output.push(line);
    } return output.join('\n');
}
async function processM3u8Content(targetUrl, content, recursionDepth = 0) {
    if (content.includes('#EXT-X-STREAM-INF') || content.includes('#EXT-X-MEDIA:')) { logDebug(`Detected master playlist: ${targetUrl} (Depth: ${recursionDepth})`); return await processMasterPlaylist(targetUrl, content, recursionDepth); }
    logDebug(`Detected media playlist: ${targetUrl} (Depth: ${recursionDepth})`); return processMediaPlaylist(targetUrl, content);
}
async function processMasterPlaylist(url, content, recursionDepth) {
    if (recursionDepth > MAX_RECURSION) { throw new Error(`Max recursion depth (${MAX_RECURSION}) exceeded for master playlist: ${url}`); }
    const baseUrl = getBaseUrl(url); const lines = content.split('\n'); let highestBandwidth = -1; let bestVariantUrl = '';
    for (let i = 0; i < lines.length; i++) { if (lines[i].startsWith('#EXT-X-STREAM-INF')) { const bandwidthMatch = lines[i].match(/BANDWIDTH=(\d+)/); const currentBandwidth = bandwidthMatch ? parseInt(bandwidthMatch[1], 10) : 0; let variantUriLine = ''; for (let j = i + 1; j < lines.length; j++) { const line = lines[j].trim(); if (line && !line.startsWith('#')) { variantUriLine = line; i = j; break; } } if (variantUriLine && currentBandwidth >= highestBandwidth) { highestBandwidth = currentBandwidth; bestVariantUrl = resolveUrl(baseUrl, variantUriLine); } } }
    if (!bestVariantUrl) { logDebug(`No BANDWIDTH found, trying first URI in: ${url}`); for (let i = 0; i < lines.length; i++) { const line = lines[i].trim(); if (line && !line.startsWith('#') && line.match(/\.m3u8($|\?.*)/i)) { bestVariantUrl = resolveUrl(baseUrl, line); logDebug(`Fallback: Found first sub-playlist URI: ${bestVariantUrl}`); break; } } }
    if (!bestVariantUrl) { logDebug(`No valid sub-playlist URI found in master: ${url}. Processing as media playlist.`); return processMediaPlaylist(url, content); }
    logDebug(`Selected sub-playlist (Bandwidth: ${highestBandwidth}): ${bestVariantUrl}`);
    const { content: variantContent, contentType: variantContentType } = await fetchContentWithType(bestVariantUrl, {});
    if (!isM3u8Content(variantContent, variantContentType)) { logDebug(`Fetched sub-playlist ${bestVariantUrl} is not M3U8 (Type: ${variantContentType}). Treating as media playlist.`); return processMediaPlaylist(bestVariantUrl, variantContent); }
    return await processM3u8Content(bestVariantUrl, variantContent, recursionDepth + 1);
}


// --- Netlify Handler ---
export const handler = async (event, context) => {
    console.log('--- Netlify Proxy Request ---');
    console.log('Time:', new Date().toISOString());
    console.log('Method:', event.httpMethod);
    console.log('Path:', event.path);
    // Note: event.queryStringParameters contains query params if any
    // Note: event.headers contains incoming headers

    // --- CORS Headers (for all responses) ---
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': '*', // Allow all headers client might send
    };

    // --- Handle OPTIONS Preflight Request ---
    if (event.httpMethod === 'OPTIONS') {
        logDebug("Handling OPTIONS request");
        return {
            statusCode: 204,
            headers: {
                ...corsHeaders,
                'Access-Control-Max-Age': '86400', // Cache preflight for 24 hours
            },
            body: '',
        };
    }

    // --- 验证鉴权 ---
    if (!validateAuth(event)) {
        console.warn('Netlify 代理请求鉴权失败');
        return {
            statusCode: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                success: false,
                error: '代理访问未授权：请检查密码配置或鉴权参数'
            }),
        };
    }

    // --- Extract Target URL ---
    // Based on netlify.toml rewrite: from = "/proxy/*" to = "/.netlify/functions/proxy/:splat"
    // The :splat part should be available in event.path after the base path
    let encodedUrlPath = '';
    const proxyPrefix = '/proxy/'; // Match the 'from' path in netlify.toml
    if (event.path && event.path.startsWith(proxyPrefix)) {
        encodedUrlPath = event.path.substring(proxyPrefix.length);
        logDebug(`Extracted encoded path from event.path: ${encodedUrlPath}`);
    } else {
        logDebug(`Could not extract encoded path from event.path: ${event.path}`);
        // Potentially handle direct calls too? Less likely needed.
        // const functionPath = '/.netlify/functions/proxy/';
        // if (event.path && event.path.startsWith(functionPath)) {
        //     encodedUrlPath = event.path.substring(functionPath.length);
        // }
    }

    const targetUrl = getTargetUrlFromPath(encodedUrlPath);
    logDebug(`Resolved target URL: ${targetUrl || 'null'}`);

    if (!targetUrl) {
        logDebug('Error: Invalid proxy request path.');
        return {
            statusCode: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify({ success: false, error: "Invalid proxy request path. Could not extract target URL." }),
        };
    }

    logDebug(`Processing proxy request for target: ${targetUrl}`);

    try {
        // 验证鉴权
        const isValidAuth = validateAuth(event);
        if (!isValidAuth) {
            return {
                statusCode: 403,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                body: JSON.stringify({ success: false, error: "Forbidden: Invalid auth credentials." }),
            };
        }

        // Fetch Original Content (Pass Netlify event headers)
        const { buffer, content, contentType, responseHeaders } = await fetchContentWithType(targetUrl, event.headers);

        // --- Process if M3U8 ---
        if (isM3u8Content(content, contentType)) {
            logDebug(`Processing M3U8 content: ${targetUrl}`);
            const processedM3u8 = await processM3u8Content(targetUrl, content);

            logDebug(`Successfully processed M3U8 for ${targetUrl}`);
            return {
                statusCode: 200,
                headers: {
                    ...corsHeaders, // Include CORS headers
                    'Content-Type': 'application/vnd.apple.mpegurl;charset=utf-8',
                    'Cache-Control': `public, max-age=${CACHE_TTL}`,
                    // Note: Do NOT include content-encoding or content-length from original response
                    // as node-fetch likely decompressed it and length changed.
                },
                body: processedM3u8, // Netlify expects body as string
            };
        } else {
            // --- Return Original Content (Non-M3U8) ---
            logDebug(`Returning non-M3U8 content directly: ${targetUrl}, Type: ${contentType}`);

            // Prepare headers for Netlify response object
            const netlifyHeaders = { ...corsHeaders };
            responseHeaders.forEach((value, key) => {
                 const lowerKey = key.toLowerCase();
                 // Exclude problematic headers and CORS headers (already added)
                 if (!lowerKey.startsWith('access-control-') &&
                     lowerKey !== 'content-encoding' &&
                     lowerKey !== 'content-length') {
                     netlifyHeaders[key] = value; // Add other original headers
                 }
             });
            netlifyHeaders['Cache-Control'] = `public, max-age=${CACHE_TTL}`; // Set our cache policy

            return {
                statusCode: 200,
                headers: netlifyHeaders,
                body: Buffer.from(buffer).toString('base64'), // 二进制原样转发（base64），避免字符串编解码损坏图片等数据
                isBase64Encoded: true,
            };
        }

    } catch (error) {
        logDebug(`ERROR in proxy processing for ${targetUrl}: ${error.message}`);
        console.error(`[Proxy Error Stack Netlify] ${error.stack}`); // Log full stack

        const statusCode = error.status || 500; // Get status from error if available

        return {
            statusCode: statusCode,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                success: false,
                error: `Proxy processing error: ${error.message}`,
                targetUrl: targetUrl
            }),
        };
    }
};
