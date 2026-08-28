import { sha256 } from './js/sha256.js'; // 需新建或引入SHA-256实现

// Vercel Middleware to inject environment variables
export default async function middleware(request) {
  // Get the URL from the request
  const url = new URL(request.url);
  
  // Only process HTML pages
  const isHtmlPage = url.pathname.endsWith('.html') || url.pathname.endsWith('/');
  if (!isHtmlPage) {
    return; // Let the request pass through unchanged
  }

  // Fetch the original response
  const response = await fetch(request);
  
  // Check if it's an HTML response
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) {
    return response; // Return the original response if not HTML
  }

  // Get the HTML content
  const originalHtml = await response.text();
  
  // Replace the placeholder with actual environment variable
  // If PASSWORD is not set, replace with empty string
  const password = process.env.PASSWORD || '';
  let passwordHash = '';
  if (password) {
    passwordHash = await sha256(password);
  }
  
  // 替换密码占位符
  let modifiedHtml = originalHtml.replace(
    'window.__ENV__.PASSWORD = "{{PASSWORD}}";',
    `window.__ENV__.PASSWORD = "${passwordHash}"; // SHA-256 hash`
  );

  // 修复Response构造
  // 注意：body 已经过 response.text() 解码，不能再保留原始 content-encoding/content-length，
  // 否则浏览器会对已解压的 body 再次解压导致内容损坏
  const finalHeaders = new Headers(response.headers);
  finalHeaders.delete('content-encoding');
  finalHeaders.delete('content-length');

  return new Response(modifiedHtml, {
    status: response.status,
    statusText: response.statusText,
    headers: finalHeaders
  });
}

export const config = {
  matcher: ['/', '/((?!api|_next/static|_vercel|favicon.ico).*)'],
};