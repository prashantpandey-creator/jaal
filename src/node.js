'use strict';
// The Jāla node. It
//   - keeps encrypted links to neighbours (dialled peers, LAN discoveries, peer exchange)
//   - floods signed announcements; each node keeps, per address, the neighbour with the freshest /
//     shortest path (sequence numbers stop routing loops, DSDV-style)
//   - routes sealed packets hop by hop — relays see only "from X to Y", never the content
//   - answers requests (sites, messages, …) and carries byte streams (the internet bridge)
const net = require('node:net');
const dgram = require('node:dgram');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const C = require('./crypto');
const { Link } = require('./link');
const { MeshStream } = require('./stream');
const { isPrivateIp } = require('./netpolicy');

const isOnion = (h) => /\.onion\.?$/i.test(String(h || ''));

const MAX_HOPS = 16;
const LAN_PORT = 42424;
const LAN_GROUP = '239.255.42.99';
const short = C.short;

function remember(map, k, v, cap) {
  map.delete(k);
  map.set(k, v);
  if (map.size > cap) map.delete(map.keys().next().value);
}

function loadOrCreateIdentity(dir) {
  const f = path.join(dir, 'identity.json');
  if (fs.existsSync(f)) return C.loadIdentity(JSON.parse(fs.readFileSync(f, 'utf8')));
  const id = C.createIdentity();
  fs.writeFileSync(f, JSON.stringify(id.json), { mode: 0o600 });
  return id;
}

function validAnn(a) {
  if (a.v !== 1 || typeof a.ed !== 'string' || typeof a.x !== 'string') return false;
  if (typeof a.name !== 'string' || a.name.length > 64) return false;
  if (a.site !== null && (typeof a.site !== 'object' || typeof a.site.title !== 'string' || a.site.title.length > 200 || !Number.isSafeInteger(a.site.ts))) return false;
  if (a.exit !== null && (typeof a.exit !== 'object' || !Array.isArray(a.exit.ports) || a.exit.ports.length > 64)) return false;
  if (!Array.isArray(a.mirrors) || a.mirrors.length > 32 || !a.mirrors.every((m) => typeof m === 'string' && C.ADDR_RE.test(m))) return false;
  return JSON.stringify(a).length < 8192;
}

function parseHostPort(spec) {
  const s = String(spec).trim();
  const m = /^\[([^\]]+)\]:(\d+)$/.exec(s) || /^([^:\s]+):(\d+)$/.exec(s);
  if (m && Number(m[2]) > 0 && Number(m[2]) < 65536) return { host: m[1], port: Number(m[2]) };
  if (/^[^:\s]+$/.test(s)) return { host: s, port: 4747 };
  throw new Error(`peer must look like host:port (got "${s}")`);
}

function lanAddrs() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list || []) {
      if ((i.family !== 'IPv4' && i.family !== 4) || i.internal) continue;
      const a = i.address.split('.').map(Number);
      const m = i.netmask.split('.').map(Number);
      out.push({ address: i.address, broadcast: a.map((x, k) => x | (~m[k] & 255)).join('.') });
    }
  }
  return out;
}

class JaalNode extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.setMaxListeners(0);
    this.opts = {
      port: 4747, host: undefined, name: os.hostname().split('.')[0].slice(0, 64), netKey: null,
      lan: true, pex: true, maxLinks: 8, announceMs: 30_000, peers: [],
      log: (...a) => console.log('[jaal]', ...a),
    };
    for (const [k, v] of Object.entries(opts)) if (v !== undefined) this.opts[k] = v;
    this.opts.name = String(this.opts.name).slice(0, 64);
    this.log = this.opts.log;
    this.dataDir = path.resolve(this.opts.dataDir || path.join(os.homedir(), '.jaal'));
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    this.id = loadOrCreateIdentity(this.dataDir);
    this.addr = this.id.addr;
    this.privateNet = !!this.opts.netKey;
    this.netTag = C.sha256(Buffer.from('jaal-net-tag:' + (this.opts.netKey || 'public'))).toString('hex').slice(0, 12);

    this.links = new Set();
    this.pendingLinks = new Set();
    this.byAddr = new Map(); // addr -> direct link
    this.nodes = new Map(); // addr -> route entry {ann, sig, seq, hops, link, seenAt, broken}
    this.keys = new Map(); // addr -> {ed, x} (verified)
    this.handlers = new Map();
    this.pending = new Map();
    this.streams = new Map();
    this.streamHandler = null;
    this.seenReq = new Map();
    this.wantSent = new Map();
    this.wantSeen = new Map();
    this.statics = new Map();
    this.tried = new Map();
    this.lanSeen = new Map();
    this.lanDialing = new Set();
    this.seq = 0;
    this.site = null;
    this.mirrors = [];
    this.exit = null;
    this.stats = { sent: 0, delivered: 0, relayed: 0 };
    this.onionDialer = null; // set when this node has Tor: (host, port) => Promise<socket>
    this.stopped = false;
    this.handle('ping', () => ({ pong: true, name: this.opts.name, t: Date.now() }));
  }

  handle(method, fn) {
    this.handlers.set(method, fn);
  }

  nameOf(addr) {
    if (addr === this.addr) return this.opts.name;
    return this.nodes.get(addr)?.ann.name || this.byAddr.get(addr)?.peer.name || short(addr);
  }

  async start() {
    this.server = net.createServer((s) => this._attach(s, false, null));
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.opts.port, this.opts.host, () => {
        this.server.off('error', reject);
        resolve();
      });
    });
    this.server.on('error', (e) => this.log('listener error:', e.message));
    this.port = this.server.address().port;
    for (const p of this.opts.peers) this.addPeer(p);
    if (this.opts.lan) this._startLan();
    this.timers = [setInterval(() => this.announce(), this.opts.announceMs), setInterval(() => this._sweep(), 10_000)];
    for (const t of this.timers) t.unref?.();
    this.announce();
    return this;
  }

  async stop() {
    this.stopped = true;
    for (const t of this.timers || []) clearInterval(t);
    clearInterval(this.lanTimer);
    for (const st of this.statics.values()) clearTimeout(st.timer);
    try { this.lanSock?.close(); } catch { /* already closed */ }
    for (const s of [...this.streams.values()]) s.destroy();
    for (const l of [...this.links, ...this.pendingLinks]) l.close('node stopping');
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error('node stopped'));
    }
    this.pending.clear();
    if (this.server) await new Promise((r) => this.server.close(() => r()));
  }

  // ------------------------------------------------------------------ links

  connect(host, port) {
    if (isOnion(host)) {
      if (!this.onionDialer) return Promise.reject(new Error('linking to a .onion peer needs Tor on this node (turn it on under Internet, or start with --tor)'));
      return this.onionDialer(host, port).then((sock) => this._linkOver(sock, { host, port }));
    }
    return new Promise((resolve, reject) => {
      const sock = net.connect({ host, port });
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error('connect timeout'));
      }, 10_000);
      sock.once('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
      sock.once('connect', () => {
        clearTimeout(timer);
        this._linkOver(sock, { host, port }).then(resolve, reject);
      });
    });
  }

  _linkOver(sock, dialed) {
    return new Promise((resolve, reject) => {
      const link = this._attach(sock, true, dialed);
      link.once('up', () => resolve(link));
      link.once('down', (r) => reject(Object.assign(new Error(r), { addr: link.peer?.addr })));
    });
  }

  // A peer we always want to be linked to: redial with back-off whenever the link drops.
  addPeer(spec) {
    const { host, port } = parseHostPort(spec);
    const key = host + ':' + port;
    if (this.statics.has(key)) return;
    const st = { host, port, addr: null, delay: 1000, timer: null };
    this.statics.set(key, st);
    const again = (ms) => {
      if (this.stopped) return;
      st.timer = setTimeout(dial, ms);
      st.timer.unref?.();
    };
    const dial = () => {
      if (this.stopped) return;
      if (st.addr && this.byAddr.has(st.addr)) return again(5000); // already linked (they dialled us)
      this.connect(host, port).then(
        (link) => {
          st.addr = link.peer.addr;
          st.delay = 1000;
          link.once('down', () => again(1000));
        },
        (e) => {
          if (e.addr) st.addr = e.addr;
          st.delay = Math.min(st.delay * 2, 30_000);
          again(st.addr && this.byAddr.has(st.addr) ? 5000 : st.delay);
        },
      );
    };
    dial();
  }

  _attach(sock, initiator, dialed) {
    const link = new Link(sock, { id: this.id, netKey: this.opts.netKey, initiator, listen: this.port, name: this.opts.name });
    link.dialed = dialed;
    this.pendingLinks.add(link);
    link.once('up', (peer) => {
      this.pendingLinks.delete(link);
      if (this.stopped) return link.close('stopping');
      if (peer.addr === this.addr) return link.close('self');
      const old = this.byAddr.get(peer.addr);
      if (old) {
        // Two links to the same node (both dialled at once): both ends keep the one dialled by the
        // lower address, so they agree without talking about it.
        const by = (l) => (l.initiator ? this.addr : l.peer.addr);
        if (by(link) >= by(old)) return link.close('duplicate');
        for (const e of this.nodes.values()) if (e.link === old) e.link = link; // same neighbour, keep its routes
        this.byAddr.set(peer.addr, link);
        old.close('duplicate');
      } else if (this.links.size >= this.opts.maxLinks * 4) {
        return link.close('too many links');
      }
      this.links.add(link);
      this.byAddr.set(peer.addr, link);
      remember(this.keys, peer.addr, { ed: peer.ed, x: peer.x }, 20_000);
      this._onLinkUp(link);
    });
    link.on('msg', (m) => {
      try {
        this._onMsg(link, m);
      } catch (e) {
        this.log('bad message:', e.message);
      }
    });
    link.once('down', (reason) => {
      this.pendingLinks.delete(link);
      if (!this.links.delete(link)) return;
      if (this.byAddr.get(link.peer.addr) === link) this.byAddr.delete(link.peer.addr);
      this._onLinkDown(link, reason);
    });
    return link;
  }

  _onLinkUp(link) {
    const p = link.peer;
    const where = link.dialed ? `${isOnion(link.dialed.host) ? link.dialed.host.slice(0, 6) + '….onion' : link.dialed.host}:${link.dialed.port}` : `${link.remote.host}:${link.remote.port}`;
    this.log(`link up   ${link.initiator ? '→' : '←'} ${p.name || '?'} ${short(p.addr)}  ${where}`);
    this.announce();
    for (const e of this.nodes.values()) if (!e.broken && e.link !== link) link.send({ t: 'ann', a: e.ann, s: e.sig, h: e.hops });
    if (this.opts.pex) link.send({ t: 'peers', l: this._peerList(link) });
    this.emit('reachable', p.addr);
    this.emit('link', link);
  }

  _onLinkDown(link, reason) {
    if (reason !== 'duplicate') this.log(`link down   ${link.peer.name || '?'} ${short(link.peer.addr)}  (${reason})`);
    const gone = [];
    for (const [addr, e] of this.nodes) {
      if (e.link === link && !e.broken) {
        e.broken = true;
        gone.push([addr, e.seq]);
      }
    }
    if (gone.length) for (const l of this.links) l.send({ t: 'gone', l: gone });
    this.emit('linkdown', link);
  }

  routeTo(addr) {
    const direct = this.byAddr.get(addr);
    if (direct && !direct.closed) return direct;
    const e = this.nodes.get(addr);
    return e && !e.broken && !e.link.closed ? e.link : null;
  }

  // ------------------------------------------------------------------ routing

  announce() {
    this.seq = Math.max(this.seq + 1, Date.now());
    const a = {
      v: 1, addr: this.addr, ed: this.id.ed, x: this.id.x, seq: this.seq, name: this.opts.name,
      site: this.site, exit: this.exit, mirrors: this.mirrors.slice(0, 32),
    };
    const s = C.sign(this.id, C.canon(a));
    for (const l of this.links) l.send({ t: 'ann', a, s, h: 0 });
  }

  _onMsg(link, m) {
    switch (m.t) {
      case 'ann': return this._onAnn(link, m);
      case 'pkt': return this._onPkt(link, m);
      case 'want': return this._onWant(link, m);
      case 'gone': return this._onGone(link, m);
      case 'peers': return this._onPeers(link, m);
      default:
    }
  }

  _onAnn(link, m) {
    const a = m.a;
    if (!a || typeof a !== 'object' || typeof a.addr !== 'string' || !C.ADDR_RE.test(a.addr)) return;
    if (a.addr === this.addr || !Number.isSafeInteger(a.seq)) return;
    const hops = Number.isInteger(m.h) ? m.h + 1 : 0;
    if (hops < 1 || hops > MAX_HOPS) return;
    const cur = this.nodes.get(a.addr);
    // Older news, or the same news by a path no shorter — ignore. After a break only strictly newer
    // news counts: that is what keeps a stale path from looping back through us.
    if (cur && (a.seq < cur.seq || (a.seq === cur.seq && (cur.broken || hops >= cur.hops)))) return;
    if (!validAnn(a) || !C.checkKeys(a.addr, a.ed, a.x) || !C.verify(a.ed, C.canon(a), m.s)) return;
    const wasUp = cur && !cur.broken;
    const entry = { ann: a, sig: m.s, seq: a.seq, hops, link, seenAt: Date.now(), broken: false, firstSeen: cur ? cur.firstSeen : Date.now() };
    this.nodes.set(a.addr, entry);
    remember(this.keys, a.addr, { ed: a.ed, x: a.x }, 20_000);
    for (const l of this.links) if (l !== link) l.send({ t: 'ann', a, s: m.s, h: hops });
    if (!wasUp) this.emit('reachable', a.addr);
    this.emit('ann', entry, cur);
  }

  // A neighbour lost its path to some nodes. Only routes that go through that neighbour are touched.
  _onGone(link, m) {
    if (!Array.isArray(m.l)) return;
    const gone = [];
    for (const item of m.l.slice(0, 4096)) {
      if (!Array.isArray(item)) continue;
      const [addr, seq] = item;
      const e = this.nodes.get(addr);
      if (e && !e.broken && e.link === link && Number.isSafeInteger(seq) && e.seq <= seq) {
        e.broken = true;
        gone.push([addr, e.seq]);
      }
    }
    if (gone.length) for (const l of this.links) if (l !== link) l.send({ t: 'gone', l: gone });
  }

  // "Does anyone have a path to X?" floods; X answers with a fresh announcement. Heals a broken
  // route in a round trip instead of waiting for X's next periodic announcement.
  _want(addr) {
    if (!C.ADDR_RE.test(addr) || addr === this.addr) return;
    const now = Date.now();
    if (now - (this.wantSent.get(addr) || 0) < 3000) return;
    remember(this.wantSent, addr, now, 10_000);
    const m = { t: 'want', a: addr, n: crypto.randomBytes(9).toString('base64'), ttl: MAX_HOPS };
    remember(this.wantSeen, m.n, now, 20_000);
    for (const l of this.links) l.send(m);
  }

  _onWant(link, m) {
    if (typeof m.n !== 'string' || typeof m.a !== 'string' || this.wantSeen.has(m.n)) return;
    remember(this.wantSeen, m.n, Date.now(), 20_000);
    if (m.a === this.addr) {
      if (Date.now() - (this.lastWantAnnounce || 0) > 1000) {
        this.lastWantAnnounce = Date.now();
        this.announce();
      }
      return;
    }
    if (Number.isInteger(m.ttl) && m.ttl > 1) for (const l of this.links) if (l !== link) l.send({ t: 'want', a: m.a, n: m.n, ttl: m.ttl - 1 });
  }

  _peerList(except) {
    const out = [];
    for (const l of this.links) {
      if (l === except) continue;
      const host = l.dialed ? l.dialed.host : l.remote.host;
      const port = l.dialed ? l.dialed.port : l.peer.listen;
      if (host && port) out.push({ a: l.peer.addr, h: host, p: port });
      if (out.length >= 16) break;
    }
    return out;
  }

  _onPeers(link, m) {
    if (!this.opts.pex || !Array.isArray(m.l)) return;
    const fromPrivate = isPrivateIp(link.remote.host);
    for (const e of m.l.slice(0, 16)) {
      if (this.links.size + this.pendingLinks.size >= this.opts.maxLinks) return;
      if (!e || typeof e.a !== 'string' || !C.ADDR_RE.test(e.a) || e.a === this.addr || this.byAddr.has(e.a)) continue;
      if (typeof e.h !== 'string' || e.h.length > 255 || !Number.isInteger(e.p) || e.p < 1 || e.p > 65535) continue;
      if (!fromPrivate && net.isIP(e.h) && isPrivateIp(e.h)) continue; // a public peer can't point us into our own LAN
      if (isOnion(e.h) && !this.onionDialer) continue;
      if (Date.now() - (this.tried.get(e.a) || 0) < 10 * 60_000) continue;
      remember(this.tried, e.a, Date.now(), 5000);
      this.connect(e.h, e.p).catch(() => {});
    }
  }

  // ------------------------------------------------------------------ packets

  sendSealed(dst, inner) {
    const link = this.routeTo(dst);
    const k = this.keys.get(dst);
    if (!link || !k) {
      this._want(dst);
      return false;
    }
    const pkt = { t: 'pkt', d: dst, s: this.addr, ttl: MAX_HOPS, ed: this.id.ed, x: this.id.x, b: C.seal(this.id, k.x, JSON.stringify(inner)) };
    this.stats.sent++;
    return link.send(pkt);
  }

  _onPkt(link, p) {
    if (typeof p.d !== 'string' || typeof p.s !== 'string' || !p.b || typeof p.b !== 'object') return;
    if (p.d !== this.addr) {
      if (!(p.ttl > 1)) return;
      const next = this.routeTo(p.d);
      if (!next || next === link) return this._want(p.d);
      p.ttl -= 1;
      this.stats.relayed++;
      this.emit('relay', p);
      next.send(p);
      return;
    }
    let k = this.keys.get(p.s);
    if (!k) {
      if (!C.checkKeys(p.s, p.ed, p.x)) return;
      k = { ed: p.ed, x: p.x };
      remember(this.keys, p.s, k, 20_000);
    }
    let inner;
    try {
      inner = JSON.parse(C.open(this.id, k.x, p.b).toString());
    } catch {
      return; // not for us, or tampered with on the way
    }
    if (!inner || typeof inner !== 'object') return;
    this.stats.delivered++;
    this._deliver(p.s, inner);
  }

  _deliver(src, m) {
    if (m.k === 'req') return this._onReq(src, m);
    if (m.k === 'res') {
      const p = this.pending.get(m.id);
      if (!p || p.dst !== src) return;
      this.pending.delete(m.id);
      clearTimeout(p.timer);
      return m.ok ? p.resolve(m.r) : p.reject(new Error(String(m.err || 'remote error')));
    }
    if (m.k === 's.open') return this._onStreamOpen(src, m);
    if (typeof m.k === 'string' && m.k.startsWith('s.') && typeof m.sid === 'string') {
      const s = this.streams.get(src + ':' + m.sid);
      if (s) return s._onPacket(m);
      if (m.k === 's.d') this.sendSealed(src, { k: 's.rst', sid: m.sid });
    }
  }

  // ------------------------------------------------------------------ requests

  async _onReq(src, m) {
    if (typeof m.id !== 'string' || typeof m.m !== 'string' || !Number.isFinite(m.ts)) return;
    if (Math.abs(Date.now() - m.ts) > 3_600_000 || this.seenReq.has(m.id)) return; // stale or replayed
    remember(this.seenReq, m.id, Date.now(), 50_000);
    const h = this.handlers.get(m.m);
    let res;
    try {
      if (!h) throw new Error('unknown method ' + m.m);
      res = { k: 'res', id: m.id, ok: true, r: await h(m.a && typeof m.a === 'object' ? m.a : {}, src) };
    } catch (e) {
      res = { k: 'res', id: m.id, ok: false, err: String((e && e.message) || e).slice(0, 500) };
    }
    if (!this.sendSealed(src, res)) setTimeout(() => this.sendSealed(src, res), 1500).unref?.();
  }

  request(dst, method, args = {}, timeoutMs = 15_000) {
    if (dst === this.addr) {
      const h = this.handlers.get(method);
      return h ? Promise.resolve().then(() => h(args, this.addr)) : Promise.reject(new Error('unknown method ' + method));
    }
    return this.waitRoute(dst).then(() => new Promise((resolve, reject) => {
      const id = crypto.randomBytes(12).toString('base64');
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`no answer from ${this.nameOf(dst)} (timeout)`));
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer, dst });
      if (!this.sendSealed(dst, { k: 'req', id, m: method, a: args, ts: Date.now() })) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error(`no route to ${this.nameOf(dst)}`));
      }
    }));
  }

  waitRoute(dst, ms = 3000) {
    if (this.routeTo(dst) && this.keys.has(dst)) return Promise.resolve();
    this._want(dst);
    return new Promise((resolve, reject) => {
      const on = (a) => {
        if (a === dst && this.routeTo(dst) && this.keys.has(dst)) {
          clearTimeout(t);
          this.off('reachable', on);
          resolve();
        }
      };
      const t = setTimeout(() => {
        this.off('reachable', on);
        reject(new Error(`${this.nameOf(dst)} is unreachable (offline or unknown)`));
      }, ms);
      t.unref?.();
      this.on('reachable', on);
    });
  }

  // ------------------------------------------------------------------ streams

  openStream(dst, host, port, extra = {}) {
    const sid = crypto.randomBytes(8).toString('hex');
    const s = new MeshStream(this, dst, sid);
    s.on('error', () => {}); // callers attach their own; this just keeps a stray error from killing the node
    this.streams.set(s.key, s);
    const timer = setTimeout(() => {
      if (!s.connected) s.destroy(new Error('exit did not answer (timeout)'));
    }, 20_000);
    timer.unref?.();
    s.once('connect', () => clearTimeout(timer));
    s.once('close', () => clearTimeout(timer));
    this.waitRoute(dst).then(
      () => {
        if (!s.destroyed && !this.sendSealed(dst, { k: 's.open', sid, host, port, ...extra })) s.destroy(new Error('no route to exit'));
      },
      (e) => s.destroy(e),
    );
    return s;
  }

  acceptStream(src, sid) {
    const s = new MeshStream(this, src, sid, { connected: true });
    s.on('error', () => {});
    this.streams.set(s.key, s);
    this.sendSealed(src, { k: 's.ok', sid });
    return s;
  }

  _onStreamOpen(src, m) {
    if (typeof m.sid !== 'string' || m.sid.length > 32 || this.streams.has(src + ':' + m.sid)) return;
    if (!this.streamHandler) return this.sendSealed(src, { k: 's.err', sid: m.sid, err: 'this node is not an internet exit' });
    Promise.resolve(this.streamHandler(src, m)).catch((e) => this.sendSealed(src, { k: 's.err', sid: m.sid, err: e.message }));
  }

  // ------------------------------------------------------------------ LAN discovery

  _startLan() {
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.lanSock = sock;
    sock.on('error', (e) => {
      this.log('LAN discovery off:', e.message);
      clearInterval(this.lanTimer);
      try { sock.close(); } catch { /* closed */ }
    });
    sock.on('message', (buf, rinfo) => this._onBeacon(buf, rinfo));
    sock.bind(LAN_PORT, () => {
      try {
        sock.setBroadcast(true);
        sock.setMulticastTTL(1);
        sock.setMulticastLoopback(true);
      } catch { /* not supported here */ }
      let joined = 0;
      for (const { address } of lanAddrs()) {
        try {
          sock.addMembership(LAN_GROUP, address);
          joined++;
        } catch { /* interface without multicast */ }
      }
      if (!joined) try { sock.addMembership(LAN_GROUP); } catch { /* loopback only */ }
      this._beacon();
      this.lanTimer = setInterval(() => this._beacon(), 5000);
      this.lanTimer.unref?.();
    });
  }

  _beacon() {
    if (this.stopped) return;
    const msg = Buffer.from(JSON.stringify({ jaal: 1, a: this.addr, p: this.port, n: this.netTag }));
    for (const t of new Set([LAN_GROUP, ...lanAddrs().map((x) => x.broadcast)])) this.lanSock.send(msg, LAN_PORT, t, () => {});
  }

  _onBeacon(buf, rinfo) {
    let b;
    try {
      b = JSON.parse(buf.toString());
    } catch {
      return;
    }
    if (!b || b.jaal !== 1 || b.n !== this.netTag || typeof b.a !== 'string' || !C.ADDR_RE.test(b.a)) return;
    if (b.a === this.addr || !Number.isInteger(b.p) || this.byAddr.has(b.a) || this.lanDialing.has(b.a)) return;
    const seen = (this.lanSeen.get(b.a) || 0) + 1;
    remember(this.lanSeen, b.a, seen, 1000);
    if (this.addr > b.a && seen < 3) return; // the lower address dials; the other only if that never happens
    this.lanDialing.add(b.a);
    this.connect(rinfo.address, b.p)
      .then(() => this.lanSeen.delete(b.a), () => {})
      .finally(() => this.lanDialing.delete(b.a));
  }

  // ------------------------------------------------------------------ upkeep + views

  _sweep() {
    const now = Date.now();
    const stale = this.opts.announceMs * 4;
    for (const [addr, e] of this.nodes) {
      if (!e.broken && now - e.seenAt > stale) e.broken = true;
      if (e.broken && now - e.seenAt > 3_600_000) this.nodes.delete(addr);
    }
    for (const [id, t] of this.seenReq) {
      if (now - t < 2 * 3_600_000) break;
      this.seenReq.delete(id);
    }
  }

  exits() {
    const out = [];
    for (const [addr, e] of this.nodes) {
      if (!e.broken && e.ann.exit && this.routeTo(addr)) out.push({ addr, name: e.ann.name, hops: e.hops, ports: e.ann.exit.ports, tor: e.ann.exit.tor === true });
    }
    return out.sort((a, b) => a.hops - b.hops);
  }

  status() {
    const now = Date.now();
    return {
      me: {
        addr: this.addr, name: this.opts.name, port: this.port, net: this.privateNet ? 'private' : 'public',
        lan: !!this.opts.lan, site: this.site, exit: this.exit, mirrors: this.mirrors,
      },
      links: [...this.links].map((l) => ({
        addr: l.peer.addr, name: l.peer.name, host: l.dialed ? l.dialed.host : l.remote.host, port: l.dialed ? l.dialed.port : l.remote.port,
        out: l.initiator, since: l.since, rx: l.bytesIn, tx: l.bytesOut,
      })),
      nodes: [...this.nodes.values()].map((e) => ({
        addr: e.ann.addr, name: e.ann.name, hops: e.hops, via: e.link.peer?.addr || null,
        online: !e.broken && !!this.routeTo(e.ann.addr), seen: now - e.seenAt, direct: this.byAddr.has(e.ann.addr),
        site: e.ann.site, exit: e.ann.exit, mirrors: e.ann.mirrors,
      })),
      stats: { ...this.stats, streams: this.streams.size },
    };
  }
}

module.exports = { JaalNode, parseHostPort, MAX_HOPS };
