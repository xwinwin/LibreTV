import { sha256 } from '../js/sha256.js';

export async function onRequest(context) {
  const { request, env, next } = context;
  const response = await next();
  const contentType = response.headers.get("content-type") || "";
  
  if (contentType.includes("text/html")) {
    let html = await response.text();
    
    // 处理普通密码
    const password = env.PASSWORD || "";
    let passwordHash = "";
    if (password) {
      passwordHash = await sha256(password);
    }
    html = html.replace('window.__ENV__.PASSWORD = "{{PASSWORD}}";', 
      `window.__ENV__.PASSWORD = "${passwordHash}";`);
    
    // 注意：body 已经过 response.text() 解码，不能再保留原始 content-encoding/content-length，
    // 否则浏览器会对已解压的 body 再次解压导致内容损坏
    const finalHeaders = new Headers(response.headers);
    finalHeaders.delete('content-encoding');
    finalHeaders.delete('content-length');

    return new Response(html, {
      headers: finalHeaders,
      status: response.status,
      statusText: response.statusText,
    });
  }
  
  return response;
}