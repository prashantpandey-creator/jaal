'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../src/crypto');

test('base32 matches the RFC 4648 vectors', () => {
  const v = { '': '', f: 'my', fo: 'mzxq', foo: 'mzxw6', foob: 'mzxw6yq', fooba: 'mzxw6ytb', foobar: 'mzxw6ytboi' };
  for (const [k, want] of Object.entries(v)) assert.equal(C.base32(Buffer.from(k)), want);
});

test('addresses are 32 letters and self-certifying', () => {
  const a = C.createIdentity();
  const b = C.createIdentity();
  assert.match(a.addr, C.ADDR_RE);
  assert.ok(C.checkKeys(a.addr, a.ed, a.x));
  assert.ok(!C.checkKeys(a.addr, b.ed, a.x), "someone else's key does not fit my address");
  assert.equal(C.loadIdentity(JSON.parse(JSON.stringify(a.json))).addr, a.addr, 'identity survives a save/load');
});

test('sealed box: only the recipient opens it, and opening proves the sender', () => {
  const alice = C.createIdentity();
  const bob = C.createIdentity();
  const eve = C.createIdentity();
  const box = C.seal(alice, bob.x, 'meet at the banyan tree');
  assert.equal(C.open(bob, alice.x, box).toString(), 'meet at the banyan tree');
  assert.ok(!JSON.stringify(box).includes('banyan'));
  assert.throws(() => C.open(eve, alice.x, box), 'eve cannot open it');
  assert.throws(() => C.open(bob, eve.x, box), 'it cannot be passed off as coming from eve');
  const flipped = Buffer.from(box.c, 'base64');
  flipped[3] ^= 1;
  assert.throws(() => C.open(bob, alice.x, { ...box, c: flipped.toString('base64') }), 'one flipped bit is caught');
});

test('signatures survive re-serialisation (canonical JSON)', () => {
  const id = C.createIdentity();
  const sig = C.sign(id, C.canon({ b: 2, a: [1, { y: 'x', x: null }], c: 'ā' }));
  const reordered = JSON.parse(JSON.stringify({ c: 'ā', a: [1, { x: null, y: 'x' }], b: 2 }));
  assert.ok(C.verify(id.ed, C.canon(reordered), sig));
  assert.ok(!C.verify(id.ed, C.canon({ ...reordered, b: 3 }), sig));
});
