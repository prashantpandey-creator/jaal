'use strict';
// One encrypted, authenticated hop between two Jāla nodes, over any TCP socket
// (the internet, a LAN, a VPN, an SSH tunnel — anything that carries bytes).
//
//   1. both sides send  HELLO {jaal:1, eph}                      plaintext, a fresh X25519 key
//   2. keys = HKDF(DH(eph, eph'), salt = H(net key) | lo | hi)   one ChaCha20-Poly1305 key per direction
//   3. both sides send  AUTH {ed, x, sig(my eph | your eph)}     encrypted: proves identity, binds it to
//                                                                this session (no replay, no MITM)
//   4. every frame:     4-byte length | ChaCha20-Poly1305(JSON), nonce = per-direction counter
//
// A node started with a different --net secret derives different keys, its AUTH frame fails to
// decrypt and the link is dropped: that is how private nets work.
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const C = require('./crypto');

const MAX_FRAME = 1 << 20;
const HANDSHAKE_MS = 10_000;
const PING_MS = 20_000;
const IDLE_MS = 65_000;
const AUTH_LABEL = Buffer.from('jaal-link-auth-v1');

const netSalt = (netKey) => C.sha256(Buffer.from('jaal-net-v1:' + (netKey || 'public')));
const normHost = (h) => String(h || '').replace(/^::ffff:/, '');

class Link extends EventEmitter {
  constructor(socket, { id, netKey, initiator, listen, name }) {
    super();
    this.socket = socket;
    this.id = id;
    this.salt = netSalt(netKey);
    this.initiator = initiator;
    this.listen = listen;
    this.name = name;
    this.state = 'hello';
    this.peer = null;
    this.closed = false;
    this.remote = { host: normHost(socket.remoteAddress), port: socket.remotePort };
    this.since = Date.now();
    this.lastRx = Date.now();
    this.bytesIn = 0;
    this.bytesOut = 0;
    this.txN = 0n;
    this.rxN = 0n;
    this.buf = Buffer.alloc(0);
    this.eph = crypto.generateKeyPairSync('x25519');
    this.ephRaw = C.rawPub(this.eph.publicKey);

    socket.setNoDelay(true);
    socket.setKeepAlive(true, 30_000);
    socket.on('data', (d) => this._onData(d));
    socket.on('error', (e) => this.close(e.code || e.message));
    socket.on('close', () => this.close('connection closed'));
    socket.resume(); // a socket handed over by a SOCKS dialer arrives paused
    this.hsTimer = setTimeout(() => this.close('handshake timeout'), HANDSHAKE_MS);
    this.hsTimer.unref?.();
    this._frame(Buffer.from(JSON.stringify({ jaal: 1, eph: this.ephRaw.toString('base64') })));
  }

  _frame(payload) {
    if (this.closed || this.socket.destroyed) return false;
    const out = Buffer.allocUnsafe(4 + payload.length);
    out.writeUInt32BE(payload.length, 0);
    payload.copy(out, 4);
    this.bytesOut += out.length;
    this.socket.write(out);
    return true; // queued (back-pressure is visible through .congested)
  }

  _nonce(n) {
    const b = Buffer.alloc(12);
    b.writeBigUInt64BE(n, 4);
    return b;
  }

  _seal(obj) {
    const pt = Buffer.from(JSON.stringify(obj));
    if (pt.length + 16 > MAX_FRAME) return false; // never burn a nonce on a frame we won't send
    return this._frame(C.aeadSeal(this.txKey, this._nonce(this.txN++), pt));
  }

  send(obj) {
    return this.state === 'up' && !this.closed ? this._seal(obj) : false;
  }

  get congested() {
    return this.socket.writableLength > 8 << 20;
  }

  _onData(d) {
    this.lastRx = Date.now();
    this.bytesIn += d.length;
    this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
    while (!this.closed && this.buf.length >= 4) {
      const n = this.buf.readUInt32BE(0);
      if (n > MAX_FRAME) return this.close('oversized frame');
      if (this.buf.length < 4 + n) return;
      const frame = this.buf.subarray(4, 4 + n);
      this.buf = this.buf.subarray(4 + n);
      try {
        this._onFrame(frame);
      } catch (e) {
        return this.close(e.message);
      }
    }
  }

  _onFrame(frame) {
    if (this.state === 'hello') return this._onHello(frame);
    let msg;
    try {
      msg = JSON.parse(C.aeadOpen(this.rxKey, this._nonce(this.rxN++), frame).toString());
    } catch {
      throw new Error(this.state === 'auth' ? 'handshake failed (different --net secret?)' : 'corrupt frame');
    }
    if (this.state === 'auth') return this._onAuth(msg);
    if (msg && typeof msg === 'object' && msg.t !== 'ping') this.emit('msg', msg);
  }

  _onHello(frame) {
    const h = JSON.parse(frame.toString());
    if (!h || h.jaal !== 1 || typeof h.eph !== 'string') throw new Error('not a jaal peer');
    const theirs = Buffer.from(h.eph, 'base64');
    if (theirs.length !== 32 || theirs.equals(this.ephRaw)) throw new Error('bad hello');
    const ss = C.dh(this.eph.privateKey, C.okp('X25519', theirs));
    const mineLow = Buffer.compare(this.ephRaw, theirs) < 0;
    const lo = mineLow ? this.ephRaw : theirs;
    const hi = mineLow ? theirs : this.ephRaw;
    const okm = C.hkdf(ss, Buffer.concat([this.salt, lo, hi]), 'jaal-link-v1', 64);
    this.txKey = mineLow ? okm.subarray(0, 32) : okm.subarray(32);
    this.rxKey = mineLow ? okm.subarray(32) : okm.subarray(0, 32);
    this.theirEph = theirs;
    this.state = 'auth';
    this._seal({
      ed: this.id.ed,
      x: this.id.x,
      listen: this.listen,
      name: this.name,
      sig: C.sign(this.id, Buffer.concat([AUTH_LABEL, this.ephRaw, theirs])),
    });
  }

  _onAuth(m) {
    if (!m || !C.verify(m.ed, Buffer.concat([AUTH_LABEL, this.theirEph, this.ephRaw]), m.sig)) throw new Error('bad identity proof');
    const e = Buffer.from(String(m.ed), 'base64');
    const x = Buffer.from(String(m.x), 'base64');
    if (e.length !== 32 || x.length !== 32) throw new Error('bad identity keys');
    this.peer = {
      addr: C.addrOf(e, x),
      ed: m.ed,
      x: m.x,
      listen: Number.isInteger(m.listen) && m.listen > 0 && m.listen < 65536 ? m.listen : null,
      name: typeof m.name === 'string' ? m.name.slice(0, 64) : '',
    };
    this.state = 'up';
    clearTimeout(this.hsTimer);
    this.pinger = setInterval(() => {
      if (Date.now() - this.lastRx > IDLE_MS) this.close('peer went silent');
      else this._seal({ t: 'ping' });
    }, PING_MS);
    this.pinger.unref?.();
    this.emit('up', this.peer);
  }

  close(reason) {
    if (this.closed) return;
    this.closed = true;
    this.reason = reason;
    clearTimeout(this.hsTimer);
    clearInterval(this.pinger);
    this.socket.destroy();
    this.emit('down', reason);
  }
}

module.exports = { Link, MAX_FRAME, normHost };
