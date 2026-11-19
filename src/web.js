'use strict';
// Web surfaces of a node.
//   portal    http://127.0.0.1:7777  — your control room (map of the net, sites, messages, internet)
//   content   http://127.0.0.1:7778/<address>/…  — Jāla sites, on their own origin so a hostile site
//             can never reach the portal's API
//   gateway   optional, public, read-only: lets anyone on the regular internet read Jāla sites
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Jāla sites may load only from themselves: no trackers, no calls home to the regular internet.
const SITE_CSP = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; connect-src 'self'; form-action 'self'; base-uri 'self'";
// The reader: pages fetched through the net (or Tor) shown with NO JavaScript, no cookies, nothing loaded from
// outside — every link and image is rewritten to come back through the reader.
const READER_CSP = "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; media-src 'self'; form-action 'self'; base-uri 'self'";
const hv = (v) => String(v).replace(/[^\x20-\x7e]/g, (c) => encodeURIComponent(c)); // header-safe (node names can be any script)
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function send(res, code, type, body, extra = {}) {
  const b = Buffer.from(body);
  res.writeHead(code, { 'content-type': type, 'content-length': b.length, 'x-content-type-options': 'nosniff', ...extra });
  res.end(b);
}

function page(title, body) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>
body{margin:0;min-height:100vh;background:radial-gradient(1200px 600px at 50% -10%,#1b1206 0,#07060b 60%);color:#e9e3d6;font:15px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;display:flex;justify-content:center}
main{max-width:760px;width:100%;padding:56px 24px}h1{font:500 30px/1.2 ui-serif,"Iowan Old Style",Palatino,Georgia,serif;color:#ffb347;letter-spacing:.04em;margin:0 0 8px}
a{color:#ffb347;text-decoration:none}a:hover{text-decoration:underline}code{color:#d4af37;font:13px ui-monospace,Menlo,monospace}.m{color:#8f8aa0;font-size:13px}
ul{list-style:none;padding:0}li{margin:0 0 10px;padding:14px 16px;border:1px solid rgba(212,175,55,.16);border-radius:12px;background:rgba(255,255,255,.02)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;background:#5f5a6e}.on{background:#ff9933;box-shadow:0 0 10px #ff9933}
</style><main>${body}</main></html>`;
}

function directory(node, sites, gateway) {
  const list = sites.list().sort((a, b) => Number(b.online) - Number(a.online) || (a.hops || 0) - (b.hops || 0));
  const items = list.map((s) => `<li><span class="dot ${s.online ? 'on' : ''}"></span><a href="/${s.addr}/">${esc(s.title)}</a>
    <div class="m">${esc(s.owner)}${s.mine ? ' (you)' : ''} · ${s.online ? (s.mine ? 'this node' : `${s.hops} hop${s.hops === 1 ? '' : 's'} away`) : 'owner offline'}${s.mirrored ? ' · mirrored here' : ''} · <code>${s.addr}</code></div></li>`).join('');
  return page('Jāla sites', `<h1>◈ Jāla</h1><p class="m">${gateway ? `A public gateway into Jāla, run by <b>${esc(node.opts.name)}</b>. These sites live on people's own machines — no hosting company in between; every page is signed by its owner and checked on arrival.` : 'Sites on the net you can see from this node.'}</p>
  <ul>${items || '<li class="m">No sites visible yet.</li>'}</ul>`);
}

function rewriteHtml(html, pageUrl, prefix) {
  let base = pageUrl;
  const b = /<base\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)/i.exec(html);
  if (b) {
    try {
      base = new URL(b[1].replace(/&amp;/g, '&'), pageUrl).href;
    } catch { /* keep the page's own URL */ }
  }
  const toView = (v) => {
    const raw = v.trim();
    if (!raw || raw.startsWith('#') || /^(data|mailto|tel|about|blob):/i.test(raw)) return v;
    let abs;
    try {
      abs = new URL(raw.replace(/&amp;/g, '&'), base);
    } catch {
      return '#';
    }
    if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return '#'; // javascript:, file:, …
    return (prefix + abs.href).replace(/&/g, '&amp;').replace(/"/g, '%22').replace(/'/g, '%27');
  };
  html = html
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, '')
    .replace(/<\/?noscript\b[^>]*>/gi, '')
    .replace(/<base\b[^>]*>/gi, '')
    .replace(/\starget\s*=\s*(["'])[\s\S]*?\1/gi, '')
    .replace(/(<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']\s*\d+\s*;\s*url\s*=\s*)([^"'>]+)/gi, (m, pre, v) => pre + toView(v))
    .replace(/(\s(?:href|src|action|poster|formaction|background|data)\s*=\s*)(["'])([\s\S]*?)\2/gi, (m, pre, q, v) => pre + q + toView(v) + q)
    .replace(/(\s(?:href|src|action|poster|formaction|background)\s*=\s*)([^\s"'>][^\s>]*)/gi, (m, pre, v) => `${pre}"${toView(v)}"`);
  const tag = `<base href="${toView(base)}">`;
  return /<head\b[^>]*>/i.test(html) ? html.replace(/<head\b[^>]*>/i, (h) => h + tag) : tag + html;
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let n = 0;
    req.on('data', (d) => {
      n += d.length;
      if (n > max) {
        reject(new Error('form too large'));
        req.destroy();
      } else parts.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', reject);
  });
}

async function readerPage(req, res, bridge, prefix, rest) {
  let target = rest.replace(/^(https?):\/(?!\/)/i, '$1://');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) target = 'http://' + target;
  let u;
  try {
    u = new URL(target);
  } catch {
    return send(res, 400, 'text/html; charset=utf-8', page('Bad address', '<h1>That is not a web address</h1>'));
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return send(res, 400, 'text/html; charset=utf-8', page('Bad address', '<h1>http and https only</h1>'));
  if (!['GET', 'HEAD', 'POST'].includes(req.method)) return send(res, 405, 'text/plain', 'GET, HEAD or POST\n');
  let r;
  try {
    const body = req.method === 'POST' ? await readBody(req, 1 << 20) : null;
    r = await bridge.fetchVia(u.href, {
      method: req.method === 'POST' ? 'POST' : 'GET',
      body,
      headers: body ? { 'content-type': String(req.headers['content-type'] || 'application/x-www-form-urlencoded'), 'content-length': String(body.length) } : {},
    });
  } catch (e) {
    return send(res, 502, 'text/html; charset=utf-8', page('Unreachable', `<h1>Couldn't reach it</h1><p>${esc(e.message)}</p><p class="m"><code>${esc(u.href)}</code></p>`), { 'content-security-policy': READER_CSP });
  }
  const via = r.via.tor ? (r.via.self ? 'Tor on this node' : `Tor via ${r.via.name}`) : r.via.self ? 'straight out of this node' : `exit ${r.via.name}`;
  if (r.status >= 300 && r.status < 400 && r.headers.location) {
    let loc = null;
    try {
      loc = new URL(r.headers.location, u.href).href;
    } catch { /* unusable redirect */ }
    if (loc && /^https?:/i.test(loc)) {
      res.writeHead(302, { location: prefix + loc, 'x-jaal-via': hv(via) });
      return res.end();
    }
  }
  const type = String(r.headers['content-type'] || 'application/octet-stream');
  let out = r.body;
  if (/^(text\/html|application\/xhtml)/i.test(type)) out = Buffer.from(rewriteHtml(out.toString('latin1'), u.href, prefix), 'latin1');
  res.writeHead(r.status, {
    'content-type': hv(type), 'content-length': out.length, 'content-security-policy': READER_CSP,
    'x-content-type-options': 'nosniff', 'referrer-policy': 'same-origin', 'cache-control': 'no-store', 'x-jaal-via': hv(via),
  });
  res.end(req.method === 'HEAD' ? undefined : out);
}

function makeContentHandler(node, sites, { gateway = false, reader = null, readerToken = null } = {}) {
  const prefix = readerToken ? `/view/${readerToken}/` : null;
  return async function handle(req, res, forced) {
    const u = new URL(req.url, 'http://jaal.invalid');
    if (!forced && u.pathname.startsWith('/view/')) {
      // Only the local site server has a reader, and only with this run's secret in the path: a web page
      // you visit elsewhere can't make your node fetch things through Tor or an exit.
      if (!reader || !prefix || !req.url.startsWith(prefix)) return send(res, 404, 'text/plain', 'not found\n');
      return readerPage(req, res, reader, prefix, req.url.slice(prefix.length));
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'text/plain', 'read-only\n');
    let addr;
    let rest;
    let rootMode = false;
    if (forced) {
      addr = forced.addr;
      rest = u.pathname;
      rootMode = true;
    } else {
      const host = String(req.headers.host || '').toLowerCase();
      const sub = /^([a-z2-7]{32})\.(?:localhost|jaal)(?::\d+)?$/.exec(host);
      if (sub) {
        addr = sub[1];
        rest = u.pathname;
        rootMode = true;
      } else {
        const m = /^\/([a-z2-7]{32})(\/.*)?$/.exec(u.pathname);
        if (!m) {
          // a page used a root-relative link ("/about.html"): put it back under the page it came from
          const vref = prefix && new RegExp(`^https?://[^/]+${prefix}(https?://[^/]+)`).exec(String(req.headers.referer || ''));
          if (vref && u.pathname !== '/') {
            res.writeHead(302, { location: prefix + vref[1] + u.pathname + u.search });
            return res.end();
          }
          const ref = /^https?:\/\/[^/]+\/([a-z2-7]{32})\//.exec(String(req.headers.referer || ''));
          if (ref && u.pathname !== '/') {
            res.writeHead(302, { location: `/${ref[1]}${u.pathname}${u.search}` });
            return res.end();
          }
          if (u.pathname === '/') return send(res, 200, 'text/html; charset=utf-8', directory(node, sites, gateway));
          if (u.pathname === '/favicon.ico') return send(res, 404, 'text/plain', '');
          return send(res, 404, 'text/html; charset=utf-8', page('Not on Jāla', '<h1>Not on Jāla</h1><p>Jāla addresses look like <code>/&lt;32-letter address&gt;/</code>. <a href="/">See the sites</a>.</p>'));
        }
        if (!m[2]) {
          res.writeHead(301, { location: `/${m[1]}/${u.search}` });
          return res.end();
        }
        addr = m[1];
        rest = m[2];
      }
    }
    try {
      const f = await sites.getFile(addr, rest);
      if (f.redirect) {
        res.writeHead(301, { location: (rootMode ? '/' : `/${addr}/`) + f.redirect });
        return res.end();
      }
      res.writeHead(200, {
        'content-type': f.type,
        'content-length': f.buf.length,
        'content-security-policy': SITE_CSP,
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'same-origin',
        'cache-control': 'no-cache',
        'x-jaal-site': addr,
        'x-jaal-source': hv(f.source),
      });
      res.end(req.method === 'HEAD' ? undefined : f.buf);
    } catch (e) {
      const code = e.status || 502;
      send(res, code, 'text/html; charset=utf-8', page(code === 404 ? 'Not found' : 'Unreachable',
        `<h1>${code === 404 ? 'No such page' : 'Site unreachable'}</h1><p>${esc(e.message)}</p><p class="m"><code>jaal://${esc(addr)}${esc(rest)}</code> · <a href="${rootMode ? '/' : `/${addr}/`}">site home</a></p>`));
    }
  };
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const parts = [];
    req.on('data', (d) => {
      size += d.length;
      if (size > 1 << 20) {
        reject(new Error('body too large'));
        req.destroy();
      } else parts.push(d);
    });
    req.on('end', () => {
      try {
        resolve(parts.length ? JSON.parse(Buffer.concat(parts).toString()) : {});
      } catch {
        reject(new Error('bad JSON'));
      }
    });
    req.on('error', reject);
  });
}

function makeApi(node, sites, msgs, bridge) {
  return async (method, route, body) => {
    switch (`${method} ${route}`) {
      case 'GET status':
        return { ...node.status(), sites: sites.list(), bridge: bridge.info(), unread: msgs.unread() };
      case 'GET messages':
        return { messages: msgs.list() };
      case 'POST send':
        return msgs.send(String(body.to || ''), String(body.text || ''));
      case 'POST read':
        return { marked: msgs.markRead(String(body.with || '')) };
      case 'POST publish':
        return sites.publish(String(body.dir || ''), body.title ? String(body.title) : undefined);
      case 'POST mirror':
        return body.off ? sites.unmirror(String(body.addr || '')) : sites.mirror(String(body.addr || ''));
      case 'POST connect':
        node.addPeer(String(body.peer || ''));
        return { ok: true };
      case 'POST webcheck':
        return bridge.webcheck(String(body.url || 'https://example.com/'));
      case 'POST tor':
        return bridge.setTorAll(!!body.all);
      case 'POST torcheck':
        return bridge.torcheck();
      case 'POST ping': {
        const t0 = Date.now();
        const r = await node.request(String(body.addr || ''), 'ping', {}, 8000);
        return { ...r, rtt: Date.now() - t0 };
      }
      default:
        throw Object.assign(new Error('no such api'), { status: 404 });
    }
  };
}

async function startPortal(node, sites, msgs, bridge, { port = 7777, contentPort, host = '127.0.0.1' } = {}) {
  const token = crypto.randomBytes(18).toString('base64url');
  const readerToken = crypto.randomBytes(12).toString('hex');
  const html = fs.readFileSync(path.join(__dirname, 'portal.html'), 'utf8');
  const content = makeContentHandler(node, sites, { reader: bridge, readerToken });
  const contentServer = http.createServer((req, res) => {
    const h = String(req.headers.host || '').toLowerCase();
    if (!/^(?:127\.0\.0\.1|localhost|\[::1\]|[a-z2-7]{32}\.localhost)(?::\d+)?$/.test(h)) return send(res, 403, 'text/plain', 'forbidden host\n');
    content(req, res);
  });
  const cport = await listen(contentServer, contentPort ?? (port ? port + 1 : 0), host);
  const api = makeApi(node, sites, msgs, bridge);
  const portal = http.createServer(async (req, res) => {
    // Host check: a web page that re-points its own DNS at 127.0.0.1 still can't talk to us.
    if (!/^(?:127\.0\.0\.1|localhost|\[::1\]):\d+$/.test(String(req.headers.host || ''))) return send(res, 403, 'text/plain', 'forbidden host\n');
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/' && req.method === 'GET') {
      const nonce = crypto.randomBytes(16).toString('base64');
      const contentBase = `http://127.0.0.1:${cport}`;
      const body = html.replaceAll('__TOKEN__', token).replaceAll('__NONCE__', nonce).replaceAll('__CONTENT__', contentBase).replaceAll('__READER__', `${contentBase}/view/${readerToken}/`);
      return send(res, 200, 'text/html; charset=utf-8', body, {
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
        'x-frame-options': 'DENY',
        'content-security-policy': `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src ${contentBase}; connect-src 'self'; base-uri 'none'; form-action 'none'`,
      });
    }
    if (u.pathname.startsWith('/api/')) {
      // Every API call carries the token baked into the portal page. Other web pages can't read
      // that page, so they can't send messages or publish in your name.
      if (req.headers['x-jaal-token'] !== token) return send(res, 401, 'application/json', '{"error":"missing token"}');
      try {
        const bodyIn = req.method === 'POST' ? await readJsonBody(req) : Object.fromEntries(u.searchParams);
        const out = await api(req.method, u.pathname.slice(5), bodyIn);
        return send(res, 200, 'application/json', JSON.stringify(out), { 'cache-control': 'no-store' });
      } catch (e) {
        return send(res, e.status || 400, 'application/json', JSON.stringify({ error: e.message }));
      }
    }
    send(res, 404, 'text/plain', 'not found\n');
  });
  const uiPort = await listen(portal, port, host);
  const info = { ui: uiPort, content: cport, token, reader: `/view/${readerToken}/` };
  fs.writeFileSync(path.join(node.dataDir, 'ui.json'), JSON.stringify(info), { mode: 0o600 });
  return { portal, contentServer, ...info };
}

async function startGateway(node, sites, bridge, { port = 8080, host = '0.0.0.0' } = {}) {
  const content = makeContentHandler(node, sites, { gateway: true });
  const server = http.createServer((req, res) => content(req, res));
  const p = await listen(server, port, host);
  if (bridge) bridge.gatewayPort = p;
  return { server, port: p };
}

module.exports = { makeContentHandler, startPortal, startGateway, esc, rewriteHtml, READER_CSP };
