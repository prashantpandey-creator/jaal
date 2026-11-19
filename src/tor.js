'use strict';
// Tor inside Jāla.
//   - reach .onion sites (the "dark web") from any node — through this node's Tor, or a Jāla exit's
//   - send any internet traffic through Tor instead of a plain exit (--tor-all fails closed: no Tor, no traffic)
//   - link to Jāla peers by .onion address, and (--onion) BE one: reachable from anywhere, no public IP
// Uses a Tor that is already running (port 9050 / 9150), or starts its own `tor` that lives and dies with the
// node (no login service, no system config touched). Names are resolved by Tor, never locally — no DNS leaks.
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const isOnion = (h) => /\.onion\.?$/i.test(String(h || ''));
const maskOnion = (h) => (isOnion(h) ? `${String(h).slice(0, 6)}….onion` : h);

const SOCKS_ERR = {
  1: 'Tor: general failure', 2: 'Tor: not allowed', 3: 'Tor: network unreachable', 4: 'Tor: host unreachable',
  5: 'Tor: connection refused', 6: 'Tor: timed out', 7: 'Tor: command not supported', 8: 'Tor: address type not supported',
  0xf0: 'onion site not found — it is offline or the address is wrong', 0xf1: 'onion site descriptor is invalid',
  0xf2: 'onion site introduction failed', 0xf3: 'onion site rendezvous failed', 0xf4: 'onion site needs client authorization',
  0xf5: 'onion site rejected our client authorization', 0xf6: 'not a valid onion address', 0xf7: 'onion site introduction timed out',
};

// SOCKS5 CONNECT by host NAME (address type 3), so Tor resolves it — .onion names never touch local DNS.
function socks5(host, port, { socksHost = '127.0.0.1', socksPort = 9050, timeoutMs = 90_000 } = {}) {
  return new Promise((resolve, reject) => {
    const name = Buffer.from(String(host).replace(/\.$/, ''));
    if (!name.length || name.length > 255) return reject(new Error('bad host name'));
    const sock = net.connect({ host: socksHost, port: socksPort });
    let stage = 0;
    let buf = Buffer.alloc(0);
    const t = setTimeout(() => fail(new Error('Tor took too long to connect')), timeoutMs);
    const fail = (e) => {
      clearTimeout(t);
      sock.destroy();
      reject(e);
    };
    const onErr = (e) => fail(new Error(e.code === 'ECONNREFUSED' ? `no Tor at ${socksHost}:${socksPort}` : e.message));
    sock.once('error', onErr);
    sock.once('connect', () => sock.write(Buffer.from([5, 1, 0])));
    // Read the handshake in non-flowing mode (readable + read()), so the socket is handed back in its natural
    // state: whoever takes it — pipe(), an HTTP client, a TLS wrapper — starts the flow, and no byte is lost.
    const onReadable = () => {
      let chunk;
      while ((chunk = sock.read()) !== null) buf = Buffer.concat([buf, chunk]);
      step();
    };
    const step = () => {
      if (stage === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 5 || buf[1] !== 0) return fail(new Error('Tor SOCKS refused the handshake'));
        buf = buf.subarray(2);
        stage = 1;
        sock.write(Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name, Buffer.from([port >> 8, port & 255])]));
      }
      if (stage === 1) {
        if (buf.length < 2) return;
        if (buf[0] !== 5) return fail(new Error('bad SOCKS reply'));
        if (buf[1] !== 0) return fail(new Error(SOCKS_ERR[buf[1]] || `Tor could not connect (code ${buf[1]})`));
        if (buf.length < 5) return;
        const need = buf[3] === 1 ? 10 : buf[3] === 4 ? 22 : buf[3] === 3 ? 7 + buf[4] : -1;
        if (need < 0) return fail(new Error('bad SOCKS reply address'));
        if (buf.length < need) return;
        stage = 2;
        clearTimeout(t);
        sock.off('readable', onReadable);
        sock.off('error', onErr);
        if (buf.length > need) sock.unshift(buf.subarray(need));
        resolve(sock);
      }
    };
    sock.on('readable', onReadable);
  });
}

function probeSocks(socksHost, socksPort, ms = 1500) {
  return new Promise((resolve) => {
    const s = net.connect({ host: socksHost, port: socksPort });
    const done = (ok) => {
      clearTimeout(t);
      s.destroy();
      resolve(ok);
    };
    const t = setTimeout(() => done(false), ms);
    s.once('error', () => done(false));
    s.once('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.once('data', (d) => done(d.length >= 2 && d[0] === 5 && d[1] === 0));
  });
}

function findTor(explicit) {
  const dirs = (process.env.PATH || '').split(path.delimiter).concat(['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin']);
  for (const f of explicit ? [explicit] : dirs.map((d) => path.join(d, 'tor'))) {
    try {
      fs.accessSync(f, fs.constants.X_OK);
      if (fs.statSync(f).isFile()) return f;
    } catch { /* not here */ }
  }
  return null;
}

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.once('error', reject);
  s.listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => resolve(port));
  });
});

const parseSpec = (spec) => {
  const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(String(spec));
  if (!m) throw new Error(`--tor-socks must look like host:port (got "${spec}")`);
  return { host: m[1], port: Number(m[2]) };
};

class Tor {
  // opts: { socks: 'host:port' — use this Tor; onion: publish this node as an onion service; torPath }
  constructor(node, opts = {}) {
    this.node = node;
    this.opts = opts;
    this.state = 'off'; // off · missing · starting · ready · error
    this.progress = 0;
    this.source = null; // 'system' (a Tor that was already running) or 'jaal' (ours)
    this.socksHost = '127.0.0.1';
    this.socksPort = null;
    this.onion = null;
    this.error = null;
    this.proc = null;
    this.waiters = [];
    this.log = (...a) => node.log(...a);
  }

  get ready() {
    return this.state === 'ready';
  }

  async start() {
    this.state = 'starting';
    if (this.opts.socks) {
      const { host, port } = parseSpec(this.opts.socks);
      if (await probeSocks(host, port)) return this._ready('system', host, port);
      this.state = 'error';
      this.error = `nothing answers as Tor at ${host}:${port}`;
      return this;
    }
    if (!this.opts.onion) {
      for (const port of [9050, 9150]) if (await probeSocks('127.0.0.1', port)) return this._ready('system', '127.0.0.1', port);
    }
    const bin = findTor(this.opts.torPath);
    if (!bin) {
      this.state = 'missing';
      this.error = 'Tor is not installed (macOS: brew install tor · Debian/Ubuntu: apt install tor)';
      this.log('tor: ' + this.error);
      return this;
    }
    const dir = path.join(this.node.dataDir, 'tor');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    const socksPort = await freePort();
    const args = [
      '--DataDirectory', dir, '--SocksPort', `127.0.0.1:${socksPort} ExtendedErrors`, '--ControlPort', '0',
      '--ClientOnly', '1', '--AvoidDiskWrites', '1', '--Log', 'notice stdout',
      '--__OwningControllerProcess', String(process.pid), // Tor exits by itself if this node dies
    ];
    let hsDir = null;
    if (this.opts.onion) {
      hsDir = path.join(dir, 'onion');
      fs.mkdirSync(hsDir, { recursive: true, mode: 0o700 });
      fs.chmodSync(hsDir, 0o700);
      args.push('--HiddenServiceDir', hsDir, '--HiddenServicePort', `4747 127.0.0.1:${this.node.port}`);
    }
    this.socksPort = socksPort;
    this.source = 'jaal';
    this.proc = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    this.log(`tor: starting our own Tor (${bin}), SOCKS 127.0.0.1:${socksPort}${hsDir ? ' + onion service' : ''}`);
    let tail = '';
    const onLine = (line) => {
      const b = /Bootstrapped (\d+)%/.exec(line);
      if (b) {
        this.progress = Number(b[1]);
        if (this.progress === 100 && this.state !== 'ready') {
          if (hsDir) {
            try {
              this.onion = fs.readFileSync(path.join(hsDir, 'hostname'), 'utf8').trim();
            } catch { /* written at start-up; missing means the service failed */ }
          }
          this._ready('jaal', '127.0.0.1', socksPort);
        }
      }
      if (/\[(err|warn)\]/.test(line)) this.error = line.replace(/^.*\[(err|warn)\]\s*/, '');
    };
    this.proc.stdout.on('data', (d) => {
      tail += d.toString();
      const lines = tail.split('\n');
      tail = lines.pop();
      lines.forEach(onLine);
    });
    this.proc.stderr.on('data', (d) => (this.error = d.toString().trim().slice(0, 300)));
    this.proc.once('exit', (code) => {
      if (this.stopping) return;
      this.state = 'error';
      this.error = `tor exited (code ${code})${this.error ? ': ' + this.error : ''}`;
      this.log('tor: ' + this.error);
      this._flush(new Error(this.error));
    });
    return this;
  }

  _ready(source, host, port) {
    this.state = 'ready';
    this.source = source;
    this.socksHost = host;
    this.socksPort = port;
    this.progress = 100;
    this.error = null;
    this.log(`tor: ready (${source === 'jaal' ? 'our own Tor' : 'Tor already running here'}, SOCKS ${host}:${port})${this.onion ? `  ·  this node: ${this.onion}:4747` : ''}`);
    this._flush(null);
    this.node.emit('tor-ready', this);
    return this;
  }

  _flush(err) {
    const w = this.waiters;
    this.waiters = [];
    for (const f of w) f(err);
  }

  whenReady(ms = 120_000) {
    if (this.ready) return Promise.resolve();
    if (this.state === 'missing' || this.state === 'error' || this.state === 'off') {
      return Promise.reject(new Error(this.error || 'Tor is off'));
    }
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`Tor is still starting (${this.progress}%)`)), ms);
      t.unref?.();
      this.waiters.push((err) => {
        clearTimeout(t);
        err ? reject(err) : resolve();
      });
    });
  }

  async connect(host, port, { waitMs = 120_000 } = {}) {
    await this.whenReady(waitMs);
    return socks5(host, port, { socksHost: this.socksHost, socksPort: this.socksPort });
  }

  stop() {
    this.stopping = true;
    if (this.proc && this.proc.exitCode === null) this.proc.kill('SIGTERM');
    this.state = 'off';
  }

  info() {
    return { state: this.state, progress: this.progress, source: this.source, socks: this.socksPort ? `${this.socksHost}:${this.socksPort}` : null, onion: this.onion, error: this.error };
  }
}

module.exports = { Tor, socks5, probeSocks, findTor, isOnion, maskOnion };
