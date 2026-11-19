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

function makeContentHandler(node, sites, { gateway = false } = {}) {
  return async function handle(req, res, forced) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'text/plain', 'read-only\n');
    const u = new URL(req.url, 'http://jaal.invalid');
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
          // a site used a root-relative link ("/about.html"): put it back under the site it came from
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
        'x-jaal-source': f.source,
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
  const html = fs.readFileSync(path.join(__dirname, 'portal.html'), 'utf8');
  const content = makeContentHandler(node, sites);
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
      const body = html.replaceAll('__TOKEN__', token).replaceAll('__NONCE__', nonce).replaceAll('__CONTENT__', contentBase);
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
  const info = { ui: uiPort, content: cport, token };
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

module.exports = { makeContentHandler, startPortal, startGateway, esc };
