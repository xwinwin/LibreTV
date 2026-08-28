import path from 'path';
import express from 'express';
import axios from 'axios';
import cors from 'cors';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const config = {
  port: process.env.PORT || 8080,
  password: process.env.PASSWORD || '',
  corsOrigin: process.env.CORS_ORIGIN || '*',
  timeout: parseInt(process.env.REQUEST_TIMEOUT || '5000'),
  maxRetries: parseInt(process.env.MAX_RETRIES || '2'),
  cacheMaxAge: process.env.CACHE_MAX_AGE || '1d',
  userAgent: process.env.USER_AGENT || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  debug: process.env.DEBUG === 'true'
};

const log = (...args) => {
  if (config.debug) {
    console.log('[DEBUG]', ...args);
  }
};

const app = express();

app.use(cors({
  origin: config.corsOrigin,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

function sha256Hash(input) {
  return new Promise((resolve) => {
    const hash = crypto.createHash('sha256');
    hash.update(input);
    resolve(hash.digest('hex'));
  });
}

async function renderPage(filePath, password) {
  let content = fs.readFileSync(filePath, 'utf8');
  if (password !== '') {
    const sha256 = await sha256Hash(password);
    content = content.replace('{{PASSWORD}}', sha256);
  } else {
    content = content.replace('{{PASSWORD}}', '');
  }
  return content;
}

app.get(['/', '/index.html', '/player.html'], async (req, res) => {
  try {
    let filePath;
    switch (req.path) {
      case '/player.html':
        filePath = path.join(__dirname, 'player.html');
        break;
      default: // '/' 和 '/index.html'
        filePath = path.join(__dirname, 'index.html');
        break;
    }
    
    const content = await renderPage(filePath, config.password);
    res.send(content);
  } catch (error) {
    console.error('页面渲染错误:', error);
    res.status(500).send('读取静态页面失败');
  }
});

app.get('/s=:keyword', async (req, res) => {
  try {
    const filePath = path.join(__dirname, 'index.html');
    const content = await renderPage(filePath, config.password);
    res.send(content);
  } catch (error) {
    console.error('搜索页面渲染错误:', error);
    res.status(500).send('读取静态页面失败');
  }
});

function isValidUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    const allowedProtocols = ['http:', 'https:'];
    
    // 从环境变量获取阻止的主机名列表（内置回环/保留域名兜底）
    const envBlockedHosts = (process.env.BLOCKED_HOSTS || '').split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
    const blockedHostnames = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]', 'localtest.me', 'lvh.me', ...envBlockedHosts];
    
    // 从环境变量获取阻止的 IP 前缀（保持向后兼容）
    const blockedPrefixes = (process.env.BLOCKED_IP_PREFIXES || '').split(',').map(p => p.trim().toLowerCase()).filter(Boolean);
    
    if (!allowedProtocols.includes(parsed.protocol)) return false;
    
    const host = parsed.hostname.toLowerCase();
    if (blockedHostnames.includes(host)) return false;
    
    for (const prefix of blockedPrefixes) {
      if (host.startsWith(prefix)) return false;
    }
    
    // IPv4 私有/保留网段（URL 规范化后，十进制/十六进制 IP 写法也会变成点分形式）
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
        return isValidUrl('http://' + mapped[1] + '/');
      }
      const mappedHex = v6.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i); // WHATWG 会规范化为 hex 形式（如 ::ffff:7f00:1）
      if (mappedHex) {
        const hi = parseInt(mappedHex[1], 16);                        // 高 16 位 = IPv4 前两个八位组
        const a = Math.floor(hi / 256);
        const b = hi % 256;
        if (a === 0 || a === 10 || a === 127) return false;           // 0/8, 10/8, 127/8
        if (a === 192 && b === 168) return false;                     // 192.168/16
        if (a === 172 && b >= 16 && b <= 31) return false;            // 172.16/12
        if (a === 169 && b === 254) return false;                     // 169.254/16（云元数据）
        if (a === 100 && b >= 64 && b <= 127) return false;           // 100.64/10（CGNAT）
        return true;
      }
      const firstGroup = v6.split(':')[0];                           // ULA fc00::/7
      if (/^[0-9a-f]{1,4}$/.test(firstGroup)) {
        const n = parseInt(firstGroup, 16);
        if (n >= 0xfc00 && n <= 0xfdff) return false;
      }
      return true;
    }
    
    // 普通域名放行（重定向会再次校验）
    return true;
  } catch {
    return false;
  }
}

// 验证代理请求的鉴权
function validateProxyAuth(req) {
  const authHash = req.query.auth;
  const timestamp = req.query.t;
  
  // 获取服务器端密码哈希
  const serverPassword = config.password;
  if (!serverPassword) {
    console.error('服务器未设置 PASSWORD 环境变量，代理访问被拒绝');
    return false;
  }
  
  // 使用 crypto 模块计算 SHA-256 哈希
  const serverPasswordHash = crypto.createHash('sha256').update(serverPassword).digest('hex');
  
  if (!authHash || authHash !== serverPasswordHash) {
    console.warn('代理请求鉴权失败：密码哈希不匹配');
    console.warn(`期望: ${serverPasswordHash}, 收到: ${authHash}`);
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

app.get('/proxy/:encodedUrl', async (req, res) => {
  try {
    // 验证鉴权
    if (!validateProxyAuth(req)) {
      return res.status(401).json({
        success: false,
        error: '代理访问未授权：请检查密码配置或鉴权参数'
      });
    }

    const encodedUrl = req.params.encodedUrl;
    const targetUrl = decodeURIComponent(encodedUrl);

    // 安全验证
    if (!isValidUrl(targetUrl)) {
      return res.status(400).send('无效的 URL');
    }

    log(`代理请求: ${targetUrl}`);

    // 添加请求超时和重试逻辑
    const maxRetries = config.maxRetries;
    const MAX_REDIRECTS = 5;
    let retries = 0;
    
    const makeRequest = async (requestUrl, redirectCount) => {
      try {
        return await axios({
          method: 'get',
          url: requestUrl,
          responseType: 'stream',
          timeout: config.timeout,
          maxRedirects: 0, // 手动跟随重定向，每跳重新做 SSRF 校验
          headers: {
            'User-Agent': config.userAgent
          }
        });
      } catch (error) {
        // 重定向响应：校验目标地址后继续请求
        if (error.response && [301, 302, 303, 307, 308].includes(error.response.status)) {
          const location = error.response.headers['location'];
          if (!location) throw error;
          const nextUrl = new URL(location, requestUrl).toString();
          if (redirectCount >= MAX_REDIRECTS) {
            throw new Error(`重定向次数超过上限 (${MAX_REDIRECTS}): ${requestUrl}`);
          }
          log(`跟随重定向 (${error.response.status}) -> ${nextUrl}`);
          if (!isValidUrl(nextUrl)) {
            const err = new Error(`重定向目标URL未通过校验: ${nextUrl}`);
            err.status = 400;
            throw err;
          }
          return makeRequest(nextUrl, redirectCount + 1);
        }
        if (retries < maxRetries) {
          retries++;
          log(`重试请求 (${retries}/${maxRetries}): ${requestUrl}`);
          return makeRequest(requestUrl, redirectCount);
        }
        throw error;
      }
    };

    const response = await makeRequest(targetUrl, 0);

    // 转发响应头（过滤敏感头）
    const headers = { ...response.headers };
    const sensitiveHeaders = (
      process.env.FILTERED_HEADERS || 
      'content-security-policy,cookie,set-cookie,x-frame-options,access-control-allow-origin'
    ).split(',');
    
    sensitiveHeaders.forEach(header => delete headers[header]);
    res.set(headers);

    // 管道传输响应流
    response.data.pipe(res);
  } catch (error) {
    console.error('代理请求错误:', error.message);
    if (error.response) {
      res.status(error.response.status || 500);
      error.response.data.pipe(res);
    } else {
      res.status(error.status || 500).send(`请求失败: ${error.message}`);
    }
  }
});

app.use(express.static(path.join(__dirname), {
  maxAge: config.cacheMaxAge
}));

app.use((err, req, res, next) => {
  console.error('服务器错误:', err);
  res.status(500).send('服务器内部错误');
});

app.use((req, res) => {
  res.status(404).send('页面未找到');
});

// 启动服务器
app.listen(config.port, () => {
  console.log(`服务器运行在 http://localhost:${config.port}`);
  if (config.password !== '') {
    console.log('用户登录密码已设置');
  } else {
    console.log('警告: 未设置 PASSWORD 环境变量，用户将被要求设置密码');
  }
  if (config.debug) {
    console.log('调试模式已启用');
    console.log('配置:', { ...config, password: config.password ? '******' : '' });
  }
});
