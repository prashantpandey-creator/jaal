'use strict';
// The bridge between Jāla and the regular internet (and Tor) — both directions.
//
//   exit      a node that has internet carries other nodes' TCP streams out to the world.
//             Off by default. Refuses to run open on the public net unless you say --exit-open.
//             Never dials private / local addresses (see netpolicy.js). With Tor on the exit
//             (--exit --tor) it also opens .onion sites, and any stream that asks for Tor.
//             A Tor turned on from the portal is for this node only: the exit never opens .onion sites with it.
//   proxy     a local HTTP + HTTPS (CONNECT) proxy. Point any browser or app at it and
//               - normal sites go through the nearest exit, across the mesh
//               - .onion sites go through Tor (this node's, or a Jāla exit's)
//               - http://<address>.jaal/ opens Jāla sites directly
//             --tor-all sends ALL internet traffic through Tor and fails closed: no Tor, nothing sent.
//             HTTPS stays end-to-end TLS between the browser and the real site.
//   fetchVia  one request through the same paths (portal probe, Tor check, the no-JavaScript reader).
//   (gateway  — the other direction, normal browsers reading Jāla sites — lives in web.js)
const http = require('node:http');
const tls = require('node:tls');
const zlib = require('node:zlib');
const { dialOut } = require('./netpolicy');
const { makeContentHandler } = require('./web');
const { Tor, isOnion, maskOnion, findTor } = require('./tor');

const HOP = ['connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'];
const strip = (h) => {
  const o = { ...h };
  for (const k of HOP) delete o[k];
  return o;
};
// What Tor Browser sends, so requests made through Tor don't stand out more than they must.
const TOR_UA = 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0';

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

function decodeBody(buf, encoding) {
  const enc = String(encoding || '').toLowerCase().trim();
  try {
    if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buf);
    if (enc === 'br') return zlib.brotliDecompressSync(buf);
    if (enc === 'deflate') {
      try {
        return zlib.inflateSync(buf);
      } catch {
        return zlib.inflateRawSync(buf);
      }
    }
  } catch {
    return buf;
  }
  return buf;
}

const connected = (s) => new Promise((resolve, reject) => {
  s.once('connect', resolve);
  s.once('error', reject);
});

class Bridge {
  constructor(node, sites, opts = {}) {
    this.node = node;
    this.sites = sites;
    this.opts = { via: null, torAll: false, ...opts };
    this.policy = null;
    this.tor = null;
    this.torForPeers = false;
    this.proxyPort = null;
    this.proxyHost = null;
    this.gatewayPort = null;
    this.exitLog = [];
    this.content = makeContentHandler(node, sites);
    // the exit's announcement follows its Tor: .onion sites open for others only if that Tor was started with the node
    this.node.on('tor-ready', (t) => {
      if (t !== this.tor || !this.policy) return;
      this.node.exit = { ports: this.policy.ports, tor: this.torForPeers };
      this.node.announce();
    });
  }

  // ------------------------------------------------------------------ Tor on this node

  // forPeers: may an exit on this node open .onion sites for the rest of the net? Flags at start-up say yes
  // (--exit --tor). A Tor turned on from the portal says no: it is for this node's own traffic.
  useTor(tor, { forPeers = true } = {}) {
    this.tor = tor;
    this.torForPeers = !!forPeers;
    this.node.onionDialer = (host, port) => tor.connect(host, port);
    return this;
  }

  // The portal's switch: start a Tor for this node now, with no flag and no restart. It never publishes the node as
  // an onion service and never makes it an exit or a relay for others. Returns the Tor's state at once; the
  // bootstrap goes on in the background and the portal polls it. opts.torPath picks the tor binary; opts.torPorts is
  // the SOCKS ports to look for a Tor already running first (default 9050, 9150).
  async startTor() {
    if (this.tor && ['starting', 'ready'].includes(this.tor.state)) return this.tor.info();
    const tor = new Tor(this.node, { torPath: this.opts.torPath, probePorts: this.opts.torPorts });
    this.useTor(tor, { forPeers: false });
    try {
      await tor.start();
    } catch (e) {
      tor.state = 'error';
      tor.error = e.message;
    }
    return tor.info();
  }

  stopTor() {
    const was = this.tor;
    this.tor = null;
    this.node.onionDialer = null;
    if (was) was.stop();
    if (this.policy && this.node.exit && this.node.exit.tor) {
      this.node.exit = { ports: this.policy.ports, tor: false };
      this.node.announce();
    }
    return { state: 'off', torAll: this.opts.torAll };
  }

  setTorAll(on) {
    this.opts.torAll = !!on;
    return { torAll: this.opts.torAll };
  }

  // ------------------------------------------------------------------ exit

  enableExit({ ports = [80, 443], open = false, lan = false } = {}) {
    if (!this.node.privateNet && !open) {
      throw new Error('refusing to run an open internet exit on the public net — start with --net <secret> so only your nodes can use it, or pass --exit-open');
    }
    this.policy = { ports: ports.map(Number).filter((p) => p > 0 && p < 65536), lan: !!lan, open: !!open };
    this.node.exit = { ports: this.policy.ports, tor: !!(this.tor && this.tor.ready && this.torForPeers) };
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
    const onion = isOnion(host);
    const viaTor = onion || m.tor === true;
    if (viaTor && !(this.torForPeers && this.tor && this.tor.ready)) return fail(onion ? 'this exit has no Tor, so it cannot open .onion sites' : 'this exit has no Tor');
    let sock;
    try {
      // Through Tor, names are resolved by Tor and Tor refuses internal addresses itself.
      sock = viaTor ? await this.tor.connect(host, port, { waitMs: 5000 }) : await dialOut(host, port, this.policy);
    } catch (e) {
      return fail(e.message || e.code || 'connect failed');
    }
    if (node.stopped) return sock.destroy();
    node.log(`exit  ${node.nameOf(src)} → ${maskOnion(host)}:${port}${viaTor ? '  via Tor' : ''}`);
    this.exitLog.unshift({ from: src, host: maskOnion(host), port, tor: viaTor, at: Date.now() });
    this.exitLog.length = Math.min(this.exitLog.length, 50);
    const ms = node.acceptStream(src, m.sid);
    sock.setTimeout(300_000, () => sock.destroy());
    splice(sock, ms);
  }

  // ------------------------------------------------------------------ getting out

  pickExit(port, { tor = false } = {}) {
    if (this.opts.via) return this.opts.via;
    const ex = this.node.exits().filter((e) => e.ports.includes(port) && (!tor || e.tor));
    return ex.length ? ex[0].addr : null;
  }

  // A byte stream to host:port. .onion (and everything, in Tor-only mode) goes through Tor: this
  // node's own if it has one, else a Jāla exit that has one. Never silently over a plain exit.
  async dial(host, port, { tor = false } = {}) {
    const onion = isOnion(host);
    if (onion || tor || this.opts.torAll) {
      const exit = this.pickExit(port, { tor: true });
      const local = this.tor && ['starting', 'ready'].includes(this.tor.state);
      if (local && (this.tor.ready || !exit)) {
        const s = await this.tor.connect(host, port, { waitMs: 20_000 });
        s.viaTor = 'self';
        return s;
      }
      if (!exit) {
        if (this.opts.torAll) throw new Error('Tor-only mode is on, but no Tor is reachable — nothing was sent');
        throw new Error('no Tor on this node or the net — turn Tor on under Internet, or start an exit with --exit --tor');
      }
      const s = this.node.openStream(exit, host, port, { tor: true });
      await connected(s);
      s.exitAddr = exit;
      s.viaTor = 'exit';
      return s;
    }
    if (this.policy && !this.opts.via) return dialOut(host, port, this.policy);
    const exit = this.pickExit(port);
    if (!exit) {
      throw new Error(this.node.exits().length ? `no exit on the net opens port ${port}` : 'no internet exit on the net yet — start one node with --exit');
    }
    const s = this.node.openStream(exit, host, port);
    await connected(s);
    s.exitAddr = exit;
    return s;
  }

  _via(raw) {
    if (raw.viaTor === 'self') return { tor: true, self: true, name: this.node.opts.name, hops: 0 };
    if (raw.exitAddr) return { tor: raw.viaTor === 'exit', addr: raw.exitAddr, name: this.node.nameOf(raw.exitAddr), hops: this.node.nodes.get(raw.exitAddr)?.hops ?? 1 };
    return { tor: false, self: true, name: this.node.opts.name, hops: 0 };
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

  // ------------------------------------------------------------------ one request through the same paths

  async fetchVia(url, { method = 'GET', headers = {}, body = null, tor = false, maxBytes = 15 << 20, timeoutMs = 90_000 } = {}) {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('http(s) addresses only');
    const t0 = Date.now();
    const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
    const onion = isOnion(u.hostname);
    const raw = await this.dial(u.hostname, port, { tor });
    const via = this._via(raw);
    // An onion address IS the server's key, so Tor already proved who answers; CA certificates
    // (often self-signed on onions) are only checked for the regular internet.
    const sock = u.protocol === 'https:' ? tls.connect({ socket: raw, servername: u.hostname, ALPNProtocols: ['http/1.1'], rejectUnauthorized: !onion }) : raw;
    return new Promise((resolve, reject) => {
      const req = http.request({
        method,
        path: u.pathname + u.search,
        headers: {
          host: u.host, 'user-agent': via.tor ? TOR_UA : 'jaal/0.2', accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          'accept-language': 'en-US,en;q=0.5', 'accept-encoding': 'identity', connection: 'close', ...headers,
        },
        createConnection: () => sock,
      });
      const timer = setTimeout(() => req.destroy(new Error('timed out')), timeoutMs);
      req.on('response', (r) => {
        const parts = [];
        let n = 0;
        r.on('data', (d) => {
          n += d.length;
          if (n > maxBytes) req.destroy(new Error('response too large'));
          else parts.push(d);
        });
        r.on('end', () => {
          clearTimeout(timer);
          const tlsInfo = u.protocol === 'https:' ? { verified: sock.authorized === true, cert: sock.getPeerCertificate()?.subject?.CN || null } : null;
          resolve({ url: u.href, status: r.statusCode, headers: r.headers, body: decodeBody(Buffer.concat(parts), r.headers['content-encoding']), ms: Date.now() - t0, via, tls: tlsInfo, onion });
        });
      });
      req.on('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
      req.end(body || undefined);
    });
  }

  async webcheck(url) {
    if (!/^[a-z]+:\/\//i.test(url)) url = 'http://' + url;
    const r = await this.fetchVia(url, { maxBytes: 2 << 20 });
    const t = /<title[^>]*>([^<]{0,200})/i.exec(r.body.toString('utf8'));
    return { url: r.url, status: r.status, title: t ? t[1].trim() : null, ms: r.ms, bytes: r.body.length, via: r.via, tls: r.tls, onion: r.onion };
  }

  // Ask the Tor Project's own checker whether our traffic really arrives from the Tor network.
  async torcheck() {
    const r = await this.fetchVia('https://check.torproject.org/api/ip', { tor: true, maxBytes: 64 << 10 });
    let j = {};
    try {
      j = JSON.parse(r.body.toString('utf8'));
    } catch { /* not JSON */ }
    return { isTor: j.IsTor === true, ip: j.IP || null, status: r.status, ms: r.ms, via: r.via };
  }

  info() {
    return {
      exit: this.policy ? {
        ports: this.policy.ports, open: this.policy.open, tor: !!(this.tor && this.tor.ready && this.torForPeers),
        recent: this.exitLog.slice(0, 10).map((x) => ({ ...x, from: this.node.nameOf(x.from) })),
      } : null,
      proxy: this.proxyPort ? { host: this.proxyHost, port: this.proxyPort } : null,
      gateway: this.gatewayPort ? { port: this.gatewayPort } : null,
      via: this.opts.via,
      exits: this.node.exits(),
      tor: this.tor ? this.tor.info() : null,
      torInstalled: !!findTor(this.opts.torPath),
      torAll: this.opts.torAll,
    };
  }
}

module.exports = { Bridge, splice, decodeBody };
