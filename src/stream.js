'use strict';
// A reliable byte stream between two nodes, carried in sealed packets across any number of relays.
// It is what lets the net carry real internet traffic (a browser's HTTPS connection, say).
//   - credit window: at most 512 KiB unacknowledged, so a slow hop never piles up memory
//   - sequence numbers: if a route changes mid-stream, the receiver puts bytes back in order
const { Duplex } = require('node:stream');

const CHUNK = 32 * 1024;
const WINDOW = 512 * 1024;
const ACK_EVERY = 64 * 1024;
const IDLE_MS = 300_000;

class MeshStream extends Duplex {
  constructor(node, peer, sid, { connected = false } = {}) {
    super({ allowHalfOpen: true });
    this.node = node;
    this.peer = peer;
    this.sid = sid;
    this.connected = connected;
    this.txSeq = 0;
    this.rxSeq = 0;
    this.endSeq = -1;
    this.ooo = new Map();
    this.inflight = 0;
    this.unacked = 0;
    this.blockedCb = null;
    this.localEnded = false;
    this.remoteEnded = false;
    this.peerReset = false;
    this.lastActivity = Date.now();
    this.idleTimer = setInterval(() => {
      if (Date.now() - this.lastActivity > IDLE_MS) this.destroy(new Error('stream idle'));
    }, 15_000);
    this.idleTimer.unref?.();
  }

  get key() {
    return this.peer + ':' + this.sid;
  }

  _send(m) {
    m.sid = this.sid;
    return this.node.sendSealed(this.peer, m);
  }

  _write(chunk, enc, cb) {
    if (!this.connected) return this.once('connect', () => this._write(chunk, enc, cb));
    this.lastActivity = Date.now();
    for (let off = 0; off < chunk.length; off += CHUNK) {
      const part = chunk.subarray(off, off + CHUNK);
      if (!this._send({ k: 's.d', q: this.txSeq++, d: part.toString('base64') })) return cb(new Error('route to peer lost'));
      this.inflight += part.length;
    }
    if (this.inflight > WINDOW) this.blockedCb = cb;
    else cb();
  }

  _final(cb) {
    if (!this.connected) return this.once('connect', () => this._final(cb));
    this.localEnded = true;
    this._send({ k: 's.end', q: this.txSeq });
    cb();
  }

  _read() {
    if (this.unacked >= ACK_EVERY) this._ack();
  }

  _ack() {
    this._send({ k: 's.ack', n: this.unacked });
    this.unacked = 0;
  }

  _onPacket(m) {
    this.lastActivity = Date.now();
    switch (m.k) {
      case 's.ok':
        if (!this.connected) {
          this.connected = true;
          this.emit('connect');
        }
        return;
      case 's.err':
        this.peerReset = true;
        return this.destroy(new Error(String(m.err || 'refused')));
      case 's.rst':
        this.peerReset = true;
        return this.destroy(new Error('stream reset by peer'));
      case 's.ack': {
        this.inflight = Math.max(0, this.inflight - (Number(m.n) || 0));
        if (this.blockedCb && this.inflight <= WINDOW) {
          const cb = this.blockedCb;
          this.blockedCb = null;
          cb();
        }
        return;
      }
      case 's.d':
        if (!Number.isInteger(m.q) || m.q < this.rxSeq || typeof m.d !== 'string') return;
        if (this.ooo.size >= 256) return this.destroy(new Error('reorder buffer overflow'));
        this.ooo.set(m.q, m.d);
        return this._drain();
      case 's.end':
        if (Number.isInteger(m.q) && m.q >= this.rxSeq) {
          this.endSeq = m.q;
          this._drain();
        }
        return;
      default:
    }
  }

  _drain() {
    let room = true;
    while (this.ooo.has(this.rxSeq)) {
      const buf = Buffer.from(this.ooo.get(this.rxSeq), 'base64');
      this.ooo.delete(this.rxSeq++);
      this.unacked += buf.length;
      room = this.push(buf);
    }
    if (this.endSeq >= 0 && this.rxSeq === this.endSeq && !this.remoteEnded) {
      this.remoteEnded = true;
      this.push(null);
    }
    if (room && this.unacked >= ACK_EVERY) this._ack();
  }

  _destroy(err, cb) {
    clearInterval(this.idleTimer);
    if (!this.peerReset && !(this.localEnded && this.remoteEnded)) this._send({ k: 's.rst' });
    this.node.streams.delete(this.key);
    cb(err);
  }
}

module.exports = { MeshStream, CHUNK, WINDOW };
