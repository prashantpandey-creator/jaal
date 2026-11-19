'use strict';
// Jāla cryptography — all Node built-ins (OpenSSL), no packages.
//
//   identity   Ed25519 (signing) + X25519 (encryption) keypair, kept in <data>/identity.json
//   address    base32(sha256("jaal-addr-v1" | ed | x))[:20 bytes] → 32 letters. Self-certifying:
//              anyone can check that a public key really belongs to an address. Nobody issues it,
//              nobody can take it away.
//   sealed box what travels across relays: ephemeral + static X25519 → HKDF-SHA256 →
//              ChaCha20-Poly1305. Only the destination can open it; opening proves the sender.
const crypto = require('node:crypto');

const ADDR_RE = /^[a-z2-7]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

function base32(buf) {
  let out = '';
  let bits = 0;
  let val = 0;
  for (const byte of buf) {
    val = ((val << 8) | byte) & 0xfff; // at most 12 meaningful bits live here
    bits += 8;
    while (bits >= 5) {
      out += B32[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += B32[(val << (5 - bits)) & 31];
  return out;
}

function sha256(...parts) {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}
const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

const addrOf = (edRaw, xRaw) => base32(sha256(Buffer.from('jaal-addr-v1'), edRaw, xRaw).subarray(0, 20));
const short = (a) => (a ? String(a).slice(0, 8) : '?');

const rawPub = (key) => Buffer.from(key.export({ format: 'jwk' }).x, 'base64url');
const okp = (crv, raw) =>
  crypto.createPublicKey({ key: { kty: 'OKP', crv, x: Buffer.from(raw).toString('base64url') }, format: 'jwk' });

const keyCache = new Map();
function pubKey(crv, raw) {
  const id = crv + Buffer.from(raw).toString('base64');
  let k = keyCache.get(id);
  if (!k) {
    k = okp(crv, raw);
    if (keyCache.size >= 4096) keyCache.clear();
    keyCache.set(id, k);
  }
  return k;
}

function createIdentity() {
  const ed = crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  const x = crypto.generateKeyPairSync('x25519').privateKey.export({ format: 'jwk' });
  return loadIdentity({ v: 1, ed, x });
}

function loadIdentity(json) {
  const edPriv = crypto.createPrivateKey({ key: json.ed, format: 'jwk' });
  const xPriv = crypto.createPrivateKey({ key: json.x, format: 'jwk' });
  const edRaw = Buffer.from(json.ed.x, 'base64url');
  const xRaw = Buffer.from(json.x.x, 'base64url');
  return {
    edPriv, xPriv, edRaw, xRaw, json,
    ed: edRaw.toString('base64'),
    x: xRaw.toString('base64'),
    addr: addrOf(edRaw, xRaw),
  };
}

// Canonical JSON (sorted keys) so a signature survives any re-serialisation on the way.
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map((e) => (e === undefined ? 'null' : canon(e))).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

const sign = (id, data) => crypto.sign(null, Buffer.from(data), id.edPriv).toString('base64');

function verify(edB64, data, sigB64) {
  try {
    if (typeof edB64 !== 'string' || typeof sigB64 !== 'string') return false;
    return crypto.verify(null, Buffer.from(data), pubKey('Ed25519', Buffer.from(edB64, 'base64')), Buffer.from(sigB64, 'base64'));
  } catch {
    return false;
  }
}

// Do these public keys really hash to this address?
function checkKeys(addr, edB64, xB64) {
  if (typeof addr !== 'string' || typeof edB64 !== 'string' || typeof xB64 !== 'string') return false;
  const e = Buffer.from(edB64, 'base64');
  const x = Buffer.from(xB64, 'base64');
  return e.length === 32 && x.length === 32 && addrOf(e, x) === addr;
}

function dh(priv, pub) {
  const s = crypto.diffieHellman({ privateKey: priv, publicKey: pub });
  if (!s.some((b) => b !== 0)) throw new Error('weak key');
  return s;
}

const hkdf = (ikm, salt, info, len) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info), len));

function aeadSeal(key, nonce, pt) {
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}

function aeadOpen(key, nonce, data) {
  if (data.length < 16) throw new Error('short ciphertext');
  const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  d.setAuthTag(data.subarray(data.length - 16));
  return Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]);
}

// The static-static half of a sealed box is the same for every message between two nodes.
const staticCache = new Map();
function staticDH(id, peerXRaw) {
  const k = id.addr + Buffer.from(peerXRaw).toString('base64');
  let s = staticCache.get(k);
  if (!s) {
    s = dh(id.xPriv, pubKey('X25519', peerXRaw));
    if (staticCache.size >= 4096) staticCache.clear();
    staticCache.set(k, s);
  }
  return s;
}

function seal(id, dstXB64, plaintext) {
  const dstRaw = Buffer.from(dstXB64, 'base64');
  const eph = crypto.generateKeyPairSync('x25519');
  const ephRaw = rawPub(eph.publicKey);
  const ikm = Buffer.concat([dh(eph.privateKey, pubKey('X25519', dstRaw)), staticDH(id, dstRaw)]);
  const key = hkdf(ikm, Buffer.concat([ephRaw, id.xRaw, dstRaw]), 'jaal-seal-v1', 32);
  const n = crypto.randomBytes(12);
  return { e: ephRaw.toString('base64'), n: n.toString('base64'), c: aeadSeal(key, n, Buffer.from(plaintext)).toString('base64') };
}

function open(id, srcXB64, box) {
  if (!box || typeof box.e !== 'string' || typeof box.n !== 'string' || typeof box.c !== 'string') throw new Error('bad box');
  const ephRaw = Buffer.from(box.e, 'base64');
  const srcRaw = Buffer.from(srcXB64, 'base64');
  const n = Buffer.from(box.n, 'base64');
  if (ephRaw.length !== 32 || n.length !== 12) throw new Error('bad box');
  const ikm = Buffer.concat([dh(id.xPriv, okp('X25519', ephRaw)), staticDH(id, srcRaw)]);
  const key = hkdf(ikm, Buffer.concat([ephRaw, srcRaw, id.xRaw]), 'jaal-seal-v1', 32);
  return aeadOpen(key, n, Buffer.from(box.c, 'base64'));
}

module.exports = {
  ADDR_RE, HEX64, base32, sha256, sha256hex, addrOf, short, rawPub, okp, pubKey,
  createIdentity, loadIdentity, canon, sign, verify, checkKeys, dh, hkdf, aeadSeal, aeadOpen, seal, open,
};
