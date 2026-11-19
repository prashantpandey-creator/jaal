'use strict';
// Sites on Jāla. A site is a folder. Publishing hashes every file (sha256) into a manifest that the
// owner signs; the site's address is the owner's node address. Nobody hosts it for you, nobody can
// edit it on the way (every byte is checked against the signed hash), and any node can keep a
// mirror so the site stays up when its owner is offline.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const C = require('./crypto');

const CHUNK = 192 * 1024;
const MAX_BLOB = 64 * 1024 * 1024;
const MAX_FILES = 4000;
const MAX_MANIFEST = 600 * 1024;
const TYPE_RE = /^[a-z0-9.+-]+\/[a-z0-9.+-]+(?:; ?charset=[a-z0-9-]+)?$/i;
const MIME = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8', json: 'application/json',
  txt: 'text/plain; charset=utf-8', md: 'text/markdown; charset=utf-8', svg: 'image/svg+xml', png: 'image/png',
  jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif',
  ico: 'image/x-icon', pdf: 'application/pdf', mp3: 'audio/mpeg', ogg: 'audio/ogg', wav: 'audio/wav',
  mp4: 'video/mp4', webm: 'video/webm', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf',
  wasm: 'application/wasm', xml: 'application/xml', zip: 'application/zip',
};
const mime = (p) => MIME[path.extname(p).slice(1).toLowerCase()] || 'application/octet-stream';

function readJson(f, fallback) {
  try {
    return JSON.parse(fs.readFileSync(f, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeAtomic(f, data) {
  const tmp = `${f}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, f);
}

const httpError = (status, msg) => Object.assign(new Error(msg), { status });

class Sites {
  constructor(node) {
    this.node = node;
    this.blobDir = path.join(node.dataDir, 'blobs');
    this.siteDir = path.join(node.dataDir, 'sites');
    fs.mkdirSync(this.blobDir, { recursive: true });
    fs.mkdirSync(this.siteDir, { recursive: true });
    this.mirrorFile = path.join(node.dataDir, 'mirrors.json');
    this.mirrored = new Set(readJson(this.mirrorFile, []).filter((a) => C.ADDR_RE.test(a)));
    this.served = new Set();
    this.fetching = new Map();
    this.memo = new Map();
    this.refreshing = new Set();
    const own = this._load(node.addr);
    if (own) node.site = { title: own.m.title, ts: own.m.ts };
    this._refreshServed();
    node.handle('site.manifest', (a) => this._serveManifest(a));
    node.handle('site.blob', (a) => this._serveBlob(a));
    node.on('ann', (e) => this._onAnn(e));
  }

  // ---------------------------------------------------------------- publish

  publish(dir, title) {
    if (!dir) throw new Error('give a folder to publish');
    dir = path.resolve(String(dir).replace(/^~(?=$|\/)/, os.homedir()));
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) throw new Error('not a folder: ' + dir);
    const files = {};
    let count = 0;
    let bytes = 0;
    const walk = (rel) => {
      for (const ent of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
        if (ent.name.startsWith('.') || ent.name === 'node_modules') continue; // never publish dotfiles (.ssh, .env, .git)
        const r = rel ? `${rel}/${ent.name}` : ent.name;
        if (ent.isDirectory()) walk(r);
        else if (ent.isFile()) {
          if (++count > MAX_FILES) throw new Error(`too many files (max ${MAX_FILES})`);
          const buf = fs.readFileSync(path.join(dir, r));
          if (buf.length > MAX_BLOB) throw new Error(`${r} is bigger than ${MAX_BLOB >> 20} MB`);
          bytes += buf.length;
          const h = C.sha256hex(buf);
          this._putBlob(h, buf);
          files[r] = { h, s: buf.length, t: mime(r) };
        }
      }
    };
    walk('');
    if (!files['index.html']) throw new Error('a site needs an index.html at the top of the folder');
    if (!title) {
      const t = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(fs.readFileSync(path.join(dir, 'index.html'), 'utf8'));
      title = t ? t[1].trim() : `${this.node.opts.name}'s site`;
    }
    const id = this.node.id;
    const prev = this._load(id.addr);
    const m = { v: 1, addr: id.addr, ed: id.ed, x: id.x, title: String(title).slice(0, 200), ts: Math.max(Date.now(), prev ? prev.m.ts + 1 : 0), files };
    const body = C.canon(m);
    if (body.length > MAX_MANIFEST) throw new Error('site has too many / too long file names');
    this._save({ m, s: C.sign(id, body) });
    this.memo.delete(id.addr);
    this.node.site = { title: m.title, ts: m.ts };
    this._refreshServed();
    this.node.announce();
    return { addr: id.addr, title: m.title, files: count, bytes, dir };
  }

  // ---------------------------------------------------------------- storage

  _load(addr) {
    const s = readJson(path.join(this.siteDir, addr + '.json'), null);
    return s && this._valid(s, addr) ? s : null;
  }

  _save(s) {
    writeAtomic(path.join(this.siteDir, s.m.addr + '.json'), JSON.stringify(s));
  }

  _putBlob(h, buf) {
    const f = path.join(this.blobDir, h);
    if (!fs.existsSync(f)) writeAtomic(f, buf);
  }

  // A manifest is only ever trusted if the address's own key signed it, and every entry is sane
  // (a hash must be 64 hex chars — never a path — so a hostile manifest can't make us read files).
  _valid(s, addr) {
    const m = s && s.m;
    if (!m || m.v !== 1 || m.addr !== addr || typeof m.title !== 'string' || !Number.isSafeInteger(m.ts)) return false;
    if (!m.files || typeof m.files !== 'object' || Array.isArray(m.files)) return false;
    const entries = Object.entries(m.files);
    if (entries.length > MAX_FILES) return false;
    for (const [p, f] of entries) {
      if (p.length > 512 || p.startsWith('/') || p.split('/').includes('..')) return false;
      if (!f || !C.HEX64.test(f.h) || !Number.isSafeInteger(f.s) || f.s < 0 || f.s > MAX_BLOB) return false;
      if (typeof f.t !== 'string' || !TYPE_RE.test(f.t)) return false;
    }
    const body = C.canon(m);
    return body.length <= MAX_MANIFEST && C.checkKeys(addr, m.ed, m.x) && C.verify(m.ed, body, s.s);
  }

  _refreshServed() {
    const hs = new Set();
    for (const a of [this.node.addr, ...this.mirrored]) {
      const s = this._load(a);
      if (s) for (const f of Object.values(s.m.files)) hs.add(f.h);
    }
    this.served = hs;
    this.node.mirrors = [...this.mirrored];
  }

  // ---------------------------------------------------------------- serving others
  // Only our own site and sites we chose to mirror are served — never pages we merely visited,
  // so nobody can probe a node for what its owner has been reading.

  _serveManifest({ addr }) {
    const s = addr === this.node.addr || this.mirrored.has(addr) ? this._load(addr) : null;
    if (!s) throw new Error('not hosting that site');
    return s;
  }

  _serveBlob({ h, off = 0 }) {
    if (typeof h !== 'string' || !C.HEX64.test(h) || !this.served.has(h)) throw new Error('no such file here');
    if (!Number.isSafeInteger(off) || off < 0) throw new Error('bad offset');
    const f = path.join(this.blobDir, h);
    const size = fs.statSync(f).size;
    const fd = fs.openSync(f, 'r');
    try {
      const buf = Buffer.alloc(Math.max(0, Math.min(CHUNK, size - off)));
      fs.readSync(fd, buf, 0, buf.length, off);
      return { size, d: buf.toString('base64') };
    } finally {
      fs.closeSync(fd);
    }
  }

  // ---------------------------------------------------------------- fetching

  _mirrorsOf(addr) {
    const out = [];
    for (const [a, e] of this.node.nodes) if (!e.broken && e.ann.mirrors.includes(addr) && this.node.routeTo(a)) out.push([e.hops, a]);
    return out.sort((x, y) => x[0] - y[0]).map((x) => x[1]);
  }

  // who can hand us this site's files right now: its owner if reachable, then mirrors, nearest first
  _sourcesOf(addr) {
    return [...(this.node.routeTo(addr) ? [addr] : []), ...this._mirrorsOf(addr)];
  }

  async getManifest(addr) {
    if (addr === this.node.addr) {
      const own = this._load(addr);
      if (!own) throw httpError(404, 'you have not published a site yet — start with --site <folder>');
      return { s: own, source: 'local' };
    }
    const hit = this.memo.get(addr);
    if (hit && Date.now() - hit.at < 15_000 && (hit.r.source !== 'origin' || this.node.routeTo(addr))) return hit.r;
    const r = await this._findManifest(addr);
    this.memo.set(addr, { at: Date.now(), r });
    return r;
  }

  async _findManifest(addr) {
    const cached = this._load(addr);
    const e = this.node.nodes.get(addr);
    const announced = e && e.ann.site ? e.ann.site.ts : null;
    const online = !!this.node.routeTo(addr);
    if (cached && online && announced && cached.m.ts >= announced) return { s: cached, source: 'cache' };
    const errors = [];
    if (online) {
      try {
        const s = await this.node.request(addr, 'site.manifest', { addr }, 10_000);
        if (this._valid(s, addr)) return { s: this._keep(s, cached), source: 'origin' };
        errors.push('origin sent a manifest that fails its signature');
      } catch (err) {
        errors.push(err.message);
      }
    }
    for (const mirror of this._mirrorsOf(addr)) {
      try {
        const s = await this.node.request(mirror, 'site.manifest', { addr }, 10_000);
        if (this._valid(s, addr)) return { s: this._keep(s, cached), source: 'mirror', via: mirror };
        errors.push(`mirror ${this.node.nameOf(mirror)} sent a forged manifest`);
      } catch (err) {
        errors.push(err.message);
      }
    }
    if (cached) return { s: cached, source: 'cache (origin offline)' };
    throw httpError(502, online ? `site unavailable: ${errors[0]}` : 'site offline — its owner is unreachable and no mirror holds it');
  }

  _keep(s, cached) {
    if (!cached || s.m.ts >= cached.m.ts) {
      this._save(s);
      return s;
    }
    return cached;
  }

  async getBlob(h, sources) {
    if (!C.HEX64.test(h)) throw new Error('bad hash');
    const f = path.join(this.blobDir, h);
    if (fs.existsSync(f)) return fs.readFileSync(f);
    if (this.fetching.has(h)) return this.fetching.get(h);
    const p = (async () => {
      let last;
      for (const src of sources) {
        if (src === this.node.addr) continue;
        try {
          const parts = [];
          let off = 0;
          let size = 1;
          while (off < size) {
            const r = await this.node.request(src, 'site.blob', { h, off }, 20_000);
            const chunk = Buffer.from(String(r.d), 'base64');
            if (!Number.isSafeInteger(r.size) || r.size > MAX_BLOB || (chunk.length === 0 && off < r.size)) throw new Error('bad blob reply');
            size = r.size;
            parts.push(chunk);
            off += chunk.length;
            if (size === 0) break;
          }
          const buf = Buffer.concat(parts);
          if (C.sha256hex(buf) !== h) throw new Error(`${this.node.nameOf(src)} sent bytes that don't match the signed hash`);
          this._putBlob(h, buf);
          return buf;
        } catch (e) {
          last = e;
        }
      }
      throw last || new Error('nobody online has this file');
    })();
    this.fetching.set(h, p);
    p.then(() => this.fetching.delete(h), () => this.fetching.delete(h));
    return p;
  }

  async getFile(addr, reqPath) {
    const { s, source, via } = await this.getManifest(addr);
    const files = s.m.files;
    let p = String(reqPath || '/');
    try {
      p = decodeURIComponent(p);
    } catch { /* keep raw */ }
    p = p.replace(/^\/+/, '');
    let key = p === '' || p.endsWith('/') ? p + 'index.html' : p;
    if (!Object.hasOwn(files, key)) {
      if (Object.hasOwn(files, key + '/index.html')) return { redirect: key + '/' };
      if (Object.hasOwn(files, key + '.html')) key += '.html';
      else throw httpError(404, `/${p} is not part of this site`);
    }
    const f = files[key];
    const buf = await this.getBlob(f.h, this._sourcesOf(addr));
    return { buf, type: f.t, title: s.m.title, source: via ? `${source} ${this.node.nameOf(via)}` : source };
  }

  // ---------------------------------------------------------------- mirrors

  async mirror(addr) {
    if (!C.ADDR_RE.test(addr)) throw new Error('not a Jāla address');
    if (addr === this.node.addr) throw new Error('that is your own site');
    this.memo.delete(addr);
    const { s } = await this.getManifest(addr);
    const sources = this._sourcesOf(addr);
    let bytes = 0;
    for (const f of Object.values(s.m.files)) {
      await this.getBlob(f.h, sources);
      bytes += f.s;
    }
    const added = !this.mirrored.has(addr);
    this.mirrored.add(addr);
    writeAtomic(this.mirrorFile, JSON.stringify([...this.mirrored]));
    this._refreshServed();
    if (added) this.node.announce();
    return { addr, title: s.m.title, files: Object.keys(s.m.files).length, bytes, mirrored: true };
  }

  unmirror(addr) {
    if (this.mirrored.delete(addr)) {
      writeAtomic(this.mirrorFile, JSON.stringify([...this.mirrored]));
      this._refreshServed();
      this.node.announce();
    }
    return { addr, mirrored: false };
  }

  _onAnn(e) {
    const a = e.ann;
    if (!a.site) return;
    const hit = this.memo.get(a.addr);
    if (hit && hit.r.s.m.ts < a.site.ts) this.memo.delete(a.addr);
    if (!this.mirrored.has(a.addr) || this.refreshing.has(a.addr)) return;
    const cached = this._load(a.addr);
    if (cached && cached.m.ts >= a.site.ts) return;
    this.refreshing.add(a.addr);
    setTimeout(() => {
      this.mirror(a.addr).then(
        (r) => this.node.log(`mirror refreshed: "${r.title}"`),
        (err) => this.node.log('mirror refresh failed:', err.message),
      ).finally(() => this.refreshing.delete(a.addr));
    }, 300).unref?.();
  }

  list() {
    const out = [];
    const own = this._load(this.node.addr);
    if (own) out.push({ addr: this.node.addr, title: own.m.title, owner: this.node.opts.name, mine: true, online: true, files: Object.keys(own.m.files).length, ts: own.m.ts });
    for (const [addr, e] of this.node.nodes) {
      if (!e.ann.site) continue;
      out.push({
        addr, title: e.ann.site.title, owner: e.ann.name, hops: e.hops, ts: e.ann.site.ts,
        online: !e.broken && !!this.node.routeTo(addr), mirrored: this.mirrored.has(addr), mirrors: this._mirrorsOf(addr).length,
      });
    }
    for (const addr of this.mirrored) {
      if (this.node.nodes.has(addr)) continue;
      const s = this._load(addr);
      if (s) out.push({ addr, title: s.m.title, owner: '(offline)', online: false, mirrored: true, ts: s.m.ts });
    }
    return out;
  }
}

module.exports = { Sites, mime };
