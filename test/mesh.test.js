'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeNode, waitFor, chain, stopAll, tmp, makeSite } = require('./helpers');

test('mesh: 4 nodes in a line find each other with the right hop counts', async (t) => {
  const ns = await chain(['a', 'b', 'c', 'd']);
  t.after(() => stopAll(ns));
  const [a, , , d] = ns;
  assert.equal(a.node.nodes.get(d.addr).hops, 3);
  assert.equal(d.node.nodes.get(a.addr).hops, 3);
  const r = await a.node.request(d.addr, 'ping');
  assert.equal(r.name, 'd');
});

test('message a → d crosses two relays that never see the words', async (t) => {
  const ns = await chain(['a', 'b', 'c', 'd']);
  t.after(() => stopAll(ns));
  const [a, b, c, d] = ns;
  const carried = [];
  for (const r of [b, c]) r.node.on('relay', (p) => carried.push(JSON.stringify(p)));
  const secret = 'the sacred word is हरि ॐ';
  const m = await a.msgs.send(d.addr, secret);
  assert.equal(m.status, 'delivered');
  const got = d.msgs.list().at(-1);
  assert.equal(got.text, secret);
  assert.equal(got.from, a.addr);
  assert.ok(carried.length >= 4, `relays carried the request and the reply (${carried.length} packets)`);
  assert.ok(carried.every((s) => !s.includes('sacred') && !s.includes('हरि')), 'relays saw only ciphertext');
});

test('site: d publishes, a reads it through b and c; forged copies and bad bytes are refused', async (t) => {
  const ns = await chain(['a', 'b', 'c', 'd']);
  t.after(() => stopAll(ns));
  const [a, , c, d] = ns;
  const big = Buffer.alloc(700_000, 7); // several chunks
  const dir = makeSite({
    'index.html': '<title>Banyan</title><h1>hello from d</h1>',
    'docs/index.html': 'docs',
    'img/big.bin': big,
    '.secret': 'never published',
  });
  const pub = d.sites.publish(dir);
  assert.equal(pub.files, 3, 'dotfiles are never published');
  assert.equal(pub.title, 'Banyan');
  await waitFor(() => a.node.nodes.get(d.addr)?.ann.site, 3000, 'site in announcement');

  const f = await a.sites.getFile(d.addr, '/');
  assert.match(f.buf.toString(), /hello from d/);
  assert.equal(f.source, 'origin');
  assert.ok((await a.sites.getFile(d.addr, '/img/big.bin')).buf.equals(big));
  assert.deepEqual(await a.sites.getFile(d.addr, '/docs'), { redirect: 'docs/' });
  await assert.rejects(a.sites.getFile(d.addr, '/.secret'), /not part of this site/);

  const real = d.sites._load(d.addr);
  const forged = JSON.parse(JSON.stringify(real));
  forged.m.title = 'Hacked';
  assert.equal(a.sites._valid(forged, d.addr), false, 'an edited manifest fails the signature');
  const sneaky = JSON.parse(JSON.stringify(real));
  sneaky.m.files['index.html'].h = '../identity.json';
  assert.equal(a.sites._valid(sneaky, d.addr), false, 'a hash that is really a path is refused');

  const docsHash = real.m.files['docs/index.html'].h;
  c.sites._serveBlob = () => ({ size: 5, d: Buffer.from('evil!').toString('base64') });
  await assert.rejects(a.sites.getBlob(docsHash, [c.addr]), /don't match the signed hash/);
});

test("mirror: c keeps d's site alive after d goes offline", async (t) => {
  const ns = await chain(['a', 'b', 'c', 'd']);
  t.after(() => stopAll(ns));
  const [a, , c, d] = ns;
  d.sites.publish(makeSite({ 'index.html': '<title>Resilient</title>still here', 'style.css': 'body{}' }));
  await waitFor(() => c.node.nodes.get(d.addr)?.ann.site, 3000, 'site in announcement');
  const r = await c.sites.mirror(d.addr);
  assert.equal(r.files, 2);
  await waitFor(() => a.node.nodes.get(c.addr)?.ann.mirrors.includes(d.addr), 3000, 'mirror in announcement');
  await d.node.stop();
  await waitFor(() => !a.node.routeTo(d.addr), 3000, 'd gone from the routes');
  const f = await a.sites.getFile(d.addr, '/');
  assert.match(f.buf.toString(), /still here/);
  assert.match(f.source, /mirror/);
});

test('a node with a different --net secret cannot link', async (t) => {
  const a = await makeNode('a', { netKey: 'om' });
  const b = await makeNode('b', { netKey: 'something else' });
  const c = await makeNode('c', { netKey: 'om' });
  t.after(() => stopAll([a, b, c]));
  await assert.rejects(b.node.connect('127.0.0.1', a.node.port), /handshake failed|connection closed/);
  await c.node.connect('127.0.0.1', a.node.port);
  await waitFor(() => a.node.byAddr.has(c.addr), 3000, "a's side of the link"); // c is up first; a a beat later
  assert.ok(!a.node.byAddr.has(b.addr));
});

test('a message to an offline node waits, then arrives when it comes back', async (t) => {
  const a = await makeNode('a');
  const dDir = tmp('d');
  let d = await makeNode('d', { dataDir: dDir });
  const dAddr = d.addr;
  d.node.addPeer(`127.0.0.1:${a.node.port}`);
  await waitFor(() => a.node.routeTo(dAddr), 3000, 'link');
  await d.node.stop();
  await waitFor(() => !a.node.routeTo(dAddr), 3000, 'd offline');
  const m = await a.msgs.send(dAddr, 'see you when you are back');
  assert.equal(m.status, 'queued');
  d = await makeNode('d', { dataDir: dDir });
  t.after(() => stopAll([a, d]));
  assert.equal(d.addr, dAddr, 'same identity after a restart');
  d.node.addPeer(`127.0.0.1:${a.node.port}`);
  await waitFor(() => d.msgs.list().some((x) => x.text === 'see you when you are back'), 5000, 'delivery');
  await waitFor(() => a.msgs.list().find((x) => x.id === m.id).status === 'delivered', 3000, 'delivered status');
});
