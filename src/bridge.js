'use strict';
// The bridge between Jāla and the regular internet — both directions.
//
//   exit      a node that has internet carries other nodes' TCP streams out to the world.
//             Off by default. Refuses to run open on the public net unless you say --exit-open.
//             Never dials private / local addresses (see netpolicy.js).
//   proxy     a local HTTP + HTTPS (CONNECT) proxy. Point any browser or app at it and
//               - normal sites go through the nearest exit, across the mesh
//               - http://<address>.jaal/ opens Jāla sites directly
//             HTTPS stays end-to-end TLS between your browser and the real site: relays and the
//             exit only ever see encrypted bytes.
//   webcheck  a one-shot "can I reach the internet through the net?" probe for the portal.
//   (gateway  — the other direction, normal browsers reading Jāla sites — lives in web.js)
const http = require('node:http');
const tls = require('node:tls');
const { dialOut } = require('./netpolicy');
const { makeContentHandler } = require('./web');

const HOP = ['connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'];
const strip = (h) => {
  const o = { ...h };
  for (const k of HOP) delete o[k];
  return o;
};

// Join two byte streams both ways. Errors tear both down; a clean end is passed along.
function splice(a, b) {
  a.pipe(b);
  b.pipe(a);
  let dead = false;
  const kill = () => {
    if (dead) return;
    dead = true;
    a.destroy();
    b.destroy();
  };
  a.on('error', kill);
  b.on('error', kill);
  a.on('close', () => !b.destroyed && !b.writableFinished && b.end());
  b.on('close', () => !a.destroyed && !a.writableFinished && a.end());
}

class Bridge {
  constructor(node, sites, opts = {}) {
    this.node = node;
    this.sites = sites;
    this.opts = { via: null, ...opts };
    this.policy = null;
    this.proxyPort = null;
    this.proxyHost = null;
    this.gatewayPort = null;
    this.exitLog = [];
    this.content = makeContentHandler(node, sites);
  }

  // ------------------------------------------------------------------ exit

  enableExit({ ports = [80, 443], open = false, lan = false } = {}) {
    if (!this.node.privateNet && !open) {
      throw new Error('refusing to run an open internet exit on the public net — start with --net <secret> so only your nodes can use it, or pass --exit-open');
    }
    this.policy = { ports: ports.map(Number).filter((p) => p > 0 && p < 65536), lan: !!lan, open: !!open };
    this.node.exit = { ports: this.policy.ports };
    this.node.streamHandler = (src, m) => this._exitStream(src, m);
    this.node.announce();
  }

  async _exitStream(src, m) {
    const node = this.node;
    const fail = (err) => node.sendSealed(src, { k: 's.err', sid: m.sid, err });
    const host = typeof m.host === 'string' ? m.host : '';
    const port = Number(m.port);
    if (!host || host.length > 255 || !Number.isInteger(port)) return fail('bad destination');
    if (!this.policy.ports.includes(port)) return fail(`port ${port} is closed on this exit (open: ${this.policy.ports.join(', ')})`);
    let mine = 0;
    for (const s of node.streams.values()) if (s.peer === src) mine++;
    if (mine >= 64) return fail('too many open streams from you');
    let sock;
    try {
      sock = await dialOut(host, port, this.policy);
    } catch (e) {
      return fail(e.message || e.code || 'connect failed');
    }
    if (node.stopped) return sock.destroy();
    node.log(`exit  ${node.nameOf(src)} → ${host}:${port}`);
    this.exitLog.unshift({ from: src, host, port, at: Date.now() });
    this.exitLog.length = Math.min(this.exitLog.length, 50);
    const ms = node.acceptStream(src, m.sid);
    sock.setTimeout(300_000, () => sock.destroy());
    splice(sock, ms);
  }

  // ------------------------------------------------------------------ getting out

  pickExit(port) {
    if (this.opts.via) return this.opts.via;
    const ex = this.node.exits().filter((e) => e.ports.includes(port));
    return ex.length ? ex[0].addr : null;
  }

  // A byte stream to host:port on the internet: across the mesh to an exit, or straight out if
  // this node is an exit itself.
  async dial(host, port) {
    if (this.policy && !this.opts.via) return dialOut(host, port, this.policy);
    const exit = this.pickExit(port);
    if (!exit) {
      throw new Error(this.node.exits().length ? `no exit on the net opens port ${port}` : 'no internet exit on the net yet — start one node with --exit');
    }
    const s = this.node.openStream(exit, host, port);
    await new Promise((resolve, reject) => {
      s.once('connect', resolve);
      s.once('error', reject);
    });
    s.exitAddr = exit;
    return s;
  }

  // ------------------------------------------------------------------ local proxy

  startProxy({ port = 8118, host = '127.0.0.1' } = {}) {
    const server = http.createServer((req, res) => this._proxyHttp(req, res));
    server.on('connect', (req, sock, head) => this._proxyConnect(req, sock, head));
    server.on('clientError', (e, sock) => sock.destroy());
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        server.off('error', reject);
        this.proxy = server;
        this.proxyPort = server.address().port;
        this.proxyHost = host;
        resolve(server);
      });
    });
  }

  async _proxyHttp(req, res) {
    let u;
    try {
      u = new URL(req.url);
    } catch {
      res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end('This is the Jāla proxy — set it as your HTTP and HTTPS proxy.\n');
    }
    if (u.hostname.endsWith('.jaal')) {
      const addr = u.hostname.slice(0, -5);
      return this.content(req, res, { addr });
    }
    if (u.protocol !== 'http:') {
      res.writeHead(400);
      return res.end('only http:// here (https goes through CONNECT)\n');
    }
    let sock;
    try {
      sock = await this.dial(u.hostname, Number(u.port) || 80);
    } catch (e) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end(`Jāla: ${e.message}\n`);
    }
    const up = http.request({
      method: req.method,
      path: u.pathname + u.search,
      headers: { ...strip(req.headers), host: u.host, connection: 'close' },
      createConnection: () => sock,
    });
    up.on('response', (r) => {
      res.writeHead(r.statusCode, r.statusMessage, strip(r.headers));
      r.pipe(res);
    });
    up.on('error', (e) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        res.end(`Jāla: ${e.message}\n`);
      } else res.destroy();
    });
    res.on('close', () => !res.writableFinished && up.destroy());
    req.pipe(up);
  }

  async _proxyConnect(req, client, head) {
    client.on('error', () => {});
    const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(req.url || '');
    if (!m) return client.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    const host = m[1];
    const port = Number(m[2]);
    if (host.endsWith('.jaal')) {
      return client.end('HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\n\r\nJaal sites are http:// - the net already encrypts them end to end.\n');
    }
    let up;
    try {
      up = await this.dial(host, port);
    } catch (e) {
      return client.end(`HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\n\r\nJāla: ${e.message}\n`);
    }
    if (client.destroyed) return up.destroy();
    client.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: jaal\r\n\r\n');
    if (head && head.length) up.write(head);
    splice(client, up);
  }

  // ------------------------------------------------------------------ probe

  async webcheck(url) {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('http(s) addresses only');
    const t0 = Date.now();
    const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
    const raw = await this.dial(u.hostname, port);
    const via = raw.exitAddr
      ? { addr: raw.exitAddr, name: this.node.nameOf(raw.exitAddr), hops: this.node.nodes.get(raw.exitAddr)?.hops ?? 1 }
      : { self: true, name: this.node.opts.name, hops: 0 };
    const sock = u.protocol === 'https:' ? tls.connect({ socket: raw, servername: u.hostname, ALPNProtocols: ['http/1.1'] }) : raw;
    return new Promise((resolve, reject) => {
      const req = http.request({
        method: 'GET',
        path: u.pathname + u.search,
        headers: { host: u.host, 'user-agent': 'jaal/0.1', accept: 'text/html,*/*', connection: 'close' },
        createConnection: () => sock,
      });
      const timer = setTimeout(() => req.destroy(new Error('timed out')), 20_000);
      req.on('response', (r) => {
        let body = '';
        r.setEncoding('utf8');
        r.on('data', (d) => {
          if (body.length < 200_000) body += d;
        });
        r.on('end', () => {
          clearTimeout(timer);
          const t = /<title[^>]*>([^<]{0,200})/i.exec(body);
          resolve({
            url: u.href, status: r.statusCode, title: t ? t[1].trim() : null, ms: Date.now() - t0, bytes: body.length, via,
            tls: u.protocol === 'https:' ? { verified: sock.authorized === true, cert: sock.getPeerCertificate()?.subject?.CN || null } : null,
          });
        });
      });
      req.on('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
      req.end();
    });
  }

  info() {
    return {
      exit: this.policy ? { ports: this.policy.ports, open: this.policy.open, recent: this.exitLog.slice(0, 10).map((x) => ({ ...x, from: this.node.nameOf(x.from) })) } : null,
      proxy: this.proxyPort ? { host: this.proxyHost, port: this.proxyPort } : null,
      gateway: this.gatewayPort ? { port: this.gatewayPort } : null,
      via: this.opts.via,
      exits: this.node.exits(),
    };
  }
}

module.exports = { Bridge, splice };
