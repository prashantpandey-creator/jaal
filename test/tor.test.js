'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const { makeNode, chain, stopAll, waitFor, get } = require('./helpers');
const { Tor, socks5 } = require('../src/tor');
const { makeContentHandler, startGateway } = require('../src/web');

const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
const webServer = (text) => listen(http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(text);
}));

// A stand-in for Tor: a SOCKS5 server that only accepts host NAMES and plays the listed onion sites.
async function fakeTor(map = {}) {
  const seen = [];
  const server = net.createServer((c) => {
    let stage = 0;
    let buf = Buffer.alloc(0);
    c.on('error', () => {});
    c.on('data', function onData(d) {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2 || buf.length < 2 + buf[1]) return;
        c.write(Buffer.from([5, 0]));
        buf = buf.subarray(2 + buf[1]);
        stage = 1;
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        if (buf[3] !== 3) {
          seen.push({ atyp: buf[3] });
          return c.end(Buffer.from([5, 8, 0, 1, 0, 0, 0, 0, 0, 0]));
        }
        const len = buf[4];
        if (buf.length < 7 + len) return;
        const name = buf.subarray(5, 5 + len).toString();
        const port = buf.readUInt16BE(5 + len);
        seen.push({ name, port, atyp: 3 });
        c.off('data', onData);
        const rest = buf.subarray(7 + len);
        const target = map[name];
        if (!target) return c.end(Buffer.from([5, name.endsWith('.onion') ? 0xf0 : 4, 0, 1, 0, 0, 0, 0, 0, 0]));
        const up = net.connect(target, '127.0.0.1', () => {
          c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
          if (rest.length) up.write(rest);
          c.pipe(up);
          up.pipe(c);
        });
        up.on('error', () => c.destroy());
      }
    });
  });
  await listen(server);
  return { server, port: server.address().port, seen };
}

const onionOf = (ch) => ch.repeat(56) + '.onion';

async function torFor(n, ftor) {
  const tor = new Tor(n.node, { socks: `127.0.0.1:${ftor.port}` });
  n.bridge.useTor(tor);
  await tor.start();
  assert.equal(tor.state, 'ready');
  return tor;
}

test('Tor: SOCKS5 asks Tor by name — an .onion never touches local DNS; unknown onions get a plain error', async (t) => {
  const site = await webServer('hidden service');
  const onion = onionOf('a');
  const ftor = await fakeTor({ [onion]: site.address().port });
  t.after(() => {
    site.close();
    ftor.server.close();
  });
  const sock = await socks5(onion, 80, { socksPort: ftor.port });
  sock.resume();
  const body = await new Promise((resolve) => {
    let s = '';
    sock.on('data', (d) => (s += d));
    sock.on('end', () => resolve(s));
    sock.write(`GET / HTTP/1.1\r\nHost: ${onion}\r\nConnection: close\r\n\r\n`);
  });
  assert.match(body, /hidden service/);
  assert.deepEqual(ftor.seen, [{ name: onion, port: 80, atyp: 3 }]);
  await assert.rejects(socks5(onionOf('b'), 80, { socksPort: ftor.port }), /onion site not found/);
});

test('a node with no Tor opens an .onion site through a Jāla exit that has Tor', async (t) => {
  const site = await webServer('welcome to the onion');
  const onion = onionOf('c');
  const ftor = await fakeTor({ [onion]: site.address().port });
  const ns = await chain(['a', 'b', 'x'], { netKey: 'om' });
  const [a, , x] = ns;
  x.bridge.enableExit({ ports: [80, 443] });
  await torFor(x, ftor);
  await waitFor(() => a.node.exits().some((e) => e.tor), 3000, 'Tor exit in announcement');
  await a.bridge.startProxy({ port: 0 });
  t.after(async () => {
    a.bridge.proxy.close();
    await stopAll(ns);
    site.close();
    ftor.server.close();
  });
  const r = await get({ port: a.bridge.proxyPort, path: `http://${onion}/`, headers: { host: onion } });
  assert.equal(r.status, 200);
  assert.equal(r.body, 'welcome to the onion');
  assert.equal(ftor.seen.at(-1).name, onion, "the exit's Tor was asked for the onion by name");
  assert.equal(x.bridge.exitLog[0].host, 'cccccc….onion', 'exit logs keep onion addresses masked');
  assert.equal(x.bridge.exitLog[0].tor, true);
});

test('Tor-only mode fails closed: no Tor reachable, nothing is sent — and the same request works with the mode off', async (t) => {
  let hits = 0;
  const web = await listen(http.createServer((req, res) => {
    hits++;
    res.end('reached');
  }));
  const ns = await chain(['a', 'x'], { netKey: 'om' });
  const [a, x] = ns;
  x.bridge.enableExit({ ports: [web.address().port], lan: true }); // a plain exit, no Tor anywhere
  await waitFor(() => a.node.exits().length === 1, 3000, 'exit in announcement');
  await a.bridge.startProxy({ port: 0 });
  t.after(async () => {
    a.bridge.proxy.close();
    await stopAll(ns);
    web.close();
  });
  const req = { port: a.bridge.proxyPort, path: `http://127.0.0.1:${web.address().port}/`, headers: { host: '127.0.0.1' } };
  a.bridge.setTorAll(true);
  const refused = await get(req);
  assert.equal(refused.status, 502);
  assert.match(refused.body, /nothing was sent/);
  assert.equal(hits, 0, 'the server never saw the request');
  a.bridge.setTorAll(false);
  const ok = await get(req);
  assert.equal(ok.status, 200);
  assert.equal(hits, 1);
});

test('link to a peer by its .onion address (and not without Tor)', async (t) => {
  const b = await makeNode('b');
  const onion = onionOf('d');
  const ftor = await fakeTor({ [onion]: b.node.port });
  const a = await makeNode('a');
  const c = await makeNode('c');
  await torFor(a, ftor);
  t.after(async () => {
    await stopAll([a, b, c]);
    ftor.server.close();
  });
  await a.node.connect(onion, 4747);
  await waitFor(() => a.node.byAddr.has(b.addr) && b.node.byAddr.has(a.addr), 3000, 'both sides of the link');
  assert.equal(ftor.seen.at(-1).name, onion);
  assert.equal(a.node.status().links[0].host, onion);
  await assert.rejects(c.node.connect(onion, 4747), /needs Tor on this node/);
});

test('reader: no JavaScript, no cookies, links come back through it — and only with the secret, never on the gateway', async (t) => {
  const html = '<html><head><title>Hidden wiki</title><script>alert(1)</script></head><body>'
    + '<a href="/about">about</a> <a href="http://other.onion/x" target="_blank">x</a> <a href="javascript:steal()">j</a>'
    + '<img src="logo.png" srcset="logo-2x.png 2x, http://cdn.onion/big.png 800w" loading="lazy">'
    + '<picture><source srcset=http://cdn.onion/a.webp type="image/webp"><img src="pic.png"></picture>'
    + '<form action="/search"><input name=q></form><noscript><p>no js here</p></noscript></body></html>';
  const site = await listen(http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'set-cookie': 'track=1' });
    res.end(req.url === '/' ? html : 'ok');
  }));
  const onion = onionOf('e');
  const ftor = await fakeTor({ [onion]: site.address().port });
  const a = await makeNode('a');
  await torFor(a, ftor);
  const srv = await listen(http.createServer(makeContentHandler(a.node, a.sites, { reader: a.bridge, readerToken: 'secret123' })));
  const gw = await startGateway(a.node, a.sites, a.bridge, { port: 0, host: '127.0.0.1' });
  t.after(async () => {
    srv.close();
    gw.server.close();
    await stopAll([a]);
    site.close();
    ftor.server.close();
  });
  const pre = `/view/secret123/http://${onion}`;
  const r = await get({ port: srv.address().port, path: `${pre}/` });
  assert.equal(r.status, 200);
  assert.match(r.headers['content-security-policy'], /default-src 'none'/);
  assert.ok(!/script-src/.test(r.headers['content-security-policy']), 'no script source is allowed at all');
  assert.equal(r.headers['set-cookie'], undefined, 'no cookies kept');
  assert.ok(!/<script/i.test(r.body), 'scripts removed');
  assert.match(r.body, /<p>no js here<\/p>/, '<noscript> fallbacks are shown');
  assert.ok(r.body.includes(`<base href="${pre}/">`));
  assert.ok(r.body.includes(`href="${pre}/about"`), 'root-relative link');
  assert.ok(r.body.includes('href="/view/secret123/http://other.onion/x"'), 'absolute link');
  assert.ok(r.body.includes(`src="${pre}/logo.png"`), 'relative image');
  assert.ok(r.body.includes(`src="${pre}/pic.png"`), 'image inside <picture>');
  assert.ok(!/srcset/i.test(r.body), 'srcset dropped: browsers prefer it over src, and the reader rewrites src');
  assert.ok(r.body.includes(`action="${pre}/search"`), 'form');
  assert.ok(!/target=/i.test(r.body) && !/javascript:/i.test(r.body));
  const before = ftor.seen.length;
  const wrong = await get({ port: srv.address().port, path: `/view/guess/http://${onion}/` });
  assert.equal(wrong.status, 404, 'no secret, no reader');
  const viaGateway = await get({ port: gw.port, path: `${pre}/` });
  assert.equal(viaGateway.status, 404, 'the public gateway is never a reader');
  assert.equal(ftor.seen.length, before, 'neither request reached Tor');
});
