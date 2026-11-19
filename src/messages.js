'use strict';
// Direct messages, end to end encrypted (sealed boxes). If the other node is offline the message
// waits in your outbox and goes the moment a route to it appears.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const C = require('./crypto');

class Messages {
  constructor(node) {
    this.node = node;
    this.file = path.join(node.dataDir, 'messages.json');
    try {
      this.items = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch {
      this.items = [];
    }
    this.ids = new Set(this.items.map((m) => m.id));
    this.retrying = new Set();
    node.handle('msg', (a, src) => this._receive(a, src));
    node.on('reachable', (addr) => this._flush(addr));
    this.timer = setInterval(() => {
      for (const m of this.items) if (m.status === 'queued' && node.routeTo(m.to)) this._flush(m.to);
    }, 20_000);
    this.timer.unref?.();
  }

  _save() {
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.items.slice(-5000)), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  list() {
    return this.items;
  }

  unread() {
    return this.items.filter((m) => m.to === this.node.addr && !m.read).length;
  }

  markRead(addr) {
    let n = 0;
    for (const m of this.items) {
      if (m.from === addr && m.to === this.node.addr && !m.read) {
        m.read = true;
        n++;
      }
    }
    if (n) this._save();
    return n;
  }

  async send(to, text) {
    if (!C.ADDR_RE.test(to)) throw new Error('not a Jāla address');
    if (to === this.node.addr) throw new Error("that's you");
    text = String(text).trim();
    if (!text || text.length > 4000) throw new Error('a message is 1–4000 characters');
    const m = { id: crypto.randomBytes(12).toString('base64url'), from: this.node.addr, to, text, ts: Date.now(), status: 'sending' };
    this.items.push(m);
    this.ids.add(m.id);
    this._save();
    await this._deliver(m);
    return m;
  }

  async _deliver(m) {
    try {
      await this.node.request(m.to, 'msg', { id: m.id, text: m.text, ts: m.ts }, 10_000);
      m.status = 'delivered';
      m.at = Date.now();
      delete m.err;
    } catch (e) {
      m.status = 'queued';
      m.err = e.message;
    }
    this._save();
    this.node.emit('message-status', m);
  }

  _flush(addr) {
    for (const m of this.items) {
      if (m.to !== addr || m.status !== 'queued' || this.retrying.has(m.id)) continue;
      this.retrying.add(m.id);
      this._deliver(m).finally(() => this.retrying.delete(m.id));
    }
  }

  _receive(a, src) {
    if (typeof a.id !== 'string' || a.id.length > 40 || typeof a.text !== 'string' || !a.text || a.text.length > 4000) throw new Error('bad message');
    if (!this.ids.has(a.id)) {
      const m = { id: a.id, from: src, to: this.node.addr, text: a.text, ts: Number.isFinite(a.ts) ? a.ts : Date.now(), rx: Date.now(), read: false };
      this.items.push(m);
      this.ids.add(m.id);
      this._save();
      this.node.log(`message from ${this.node.nameOf(src)}: ${a.text.length > 60 ? a.text.slice(0, 60) + '…' : a.text}`);
      this.node.emit('message', m);
    }
    return { ok: true };
  }
}

module.exports = { Messages };
