'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { makeNode, chain, stopAll, waitFor, get, tmp } = require('./helpers');
const { Tor, socks5 } = require('../src/tor');
const { makeContentHandler, startGateway, startPortal } = require('../src/web');

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

// ---------------------------------------------------------------- the portal's Tor control: no flag, no restart

// The portal's API the way the page calls it: the token header, and the Host check on the server.
function api(ui, route, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : '';
    const req = http.request({
      host: '127.0.0.1', port: ui.ui, method: body ? 'POST' : 'GET', path: `/api/${route}`,
      headers: { 'x-jaal-token': ui.token, 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) },
    }, (res) => {
      let s = '';
      res.on('data', (d) => (s += d));
      res.on('end', () => (res.statusCode === 200 ? resolve(JSON.parse(s)) : reject(new Error(`${res.statusCode} ${s}`))));
    });
    req.on('error', reject);
    req.end(data);
  });
}

// A stand-in for the tor binary: prints Tor's bootstrap lines, listens on the --SocksPort it is given, and
// exits when the node that started it is gone (as Tor does with --__OwningControllerProcess).
function fakeTorBinary() {
  const file = path.join(tmp('tor-bin'), 'tor');
  fs.writeFileSync(file, `#!${process.execPath}
'use strict';
const net = require('node:net');
const arg = (k) => { const i = process.argv.indexOf(k); return i > 1 ? process.argv[i + 1] : ''; };
const port = Number(/127\\.0\\.0\\.1:(\\d+)/.exec(arg('--SocksPort'))[1]);
const owner = Number(arg('--__OwningControllerProcess'));
const server = net.createServer((c) => { c.on('error', () => {}); c.once('data', () => c.end(Buffer.from([5, 0]))); });
server.listen(port, '127.0.0.1', () => {
  console.log('Mar 01 00:00:00.000 [notice] Bootstrapped 0% (starting): Starting');
  setTimeout(() => console.log('Mar 01 00:00:00.000 [notice] Bootstrapped 100% (done): Done'), 60);
});
setInterval(() => { try { process.kill(owner, 0); } catch { server.close(); process.exit(0); } }, 100).unref();
process.on('SIGTERM', () => { server.close(); process.exit(0); });
`, { mode: 0o755 });
  return file;
}

const closePortal = async (ui, ns) => {
  ui.portal.close();
  ui.contentServer.close();
  await stopAll(ns);
};

test('the portal turns Tor on for the running node — no flag, no restart — and off again', async (t) => {
  const n = await makeNode('p', { bridge: { torPath: fakeTorBinary(), torPorts: [] } });
  const ui = await startPortal(n.node, n.sites, n.msgs, n.bridge, { port: 0 });
  t.after(async () => {
    n.bridge.stopTor();
    await closePortal(ui, [n]);
  });
  assert.equal((await api(ui, 'status')).bridge.tor, null, 'Tor stays off until the owner turns it on');
  assert.ok(['starting', 'ready'].includes((await api(ui, 'tor', { on: true })).state));
  await waitFor(async () => (await api(ui, 'status')).bridge.tor?.state === 'ready', 10_000, 'Tor to reach ready');
  const { bridge } = await api(ui, 'status');
  assert.equal(bridge.tor.progress, 100);
  assert.equal(bridge.tor.source, 'jaal', 'its own tor binary, not a Tor already running');
  assert.equal(bridge.tor.onion, null, 'Tor on does not publish this node as an onion service');
  assert.equal(n.node.exit, null, 'Tor on does not make this node an exit');
  assert.equal(n.bridge.policy, null);
  const proc = n.bridge.tor.proc;
  assert.deepEqual(await api(ui, 'tor', { on: false }), { state: 'off', torAll: false });
  assert.equal(n.bridge.tor, null);
  await waitFor(() => proc.exitCode !== null || proc.signalCode !== null, 5000, 'our tor process to stop');
});

test('turning Tor on or off never changes Tor-only mode, and Tor-only mode stays fail-closed', async (t) => {
  const n = await makeNode('o', { bridge: { torPath: fakeTorBinary(), torPorts: [] } });
  const ui = await startPortal(n.node, n.sites, n.msgs, n.bridge, { port: 0 });
  t.after(async () => {
    n.bridge.stopTor();
    await closePortal(ui, [n]);
  });
  await api(ui, 'tor', { all: true });
  await api(ui, 'tor', { on: true });
  await waitFor(async () => (await api(ui, 'status')).bridge.tor?.state === 'ready', 10_000, 'Tor to reach ready');
  await api(ui, 'tor', { on: false });
  assert.equal((await api(ui, 'status')).bridge.torAll, true, 'Tor-only mode survives Tor going off');
  await assert.rejects(n.bridge.dial('example.com', 80), /nothing was sent/, 'and with Tor off nothing is sent');
  await api(ui, 'tor', { all: false });
  assert.equal((await api(ui, 'status')).bridge.torAll, false);
});

test('no Tor installed: the portal says so and gives the install lines', async (t) => {
  const n = await makeNode('m', { bridge: { torPath: '/nonexistent/tor', torPorts: [] } });
  const ui = await startPortal(n.node, n.sites, n.msgs, n.bridge, { port: 0 });
  t.after(() => closePortal(ui, [n]));
  assert.equal((await api(ui, 'status')).bridge.torInstalled, false);
  const r = await api(ui, 'tor', { on: true });
  assert.equal(r.state, 'missing');
  assert.match(r.error, /macOS: brew install tor/);
  assert.match(r.error, /Debian\/Ubuntu: sudo apt install tor/);
  assert.equal((await api(ui, 'status')).bridge.tor.state, 'missing');
});

test('an exit does not open .onion sites for others because its owner turned Tor on for themselves', async (t) => {
  const site = await webServer('should not be reached');
  const onion = onionOf('f');
  const ftor = await fakeTor({ [onion]: site.address().port });
  const ns = await chain(['a', 'x'], { netKey: 'om' });
  const [a, x] = ns;
  x.bridge.enableExit({ ports: [80, 443] });
  const own = new Tor(x.node, { socks: `127.0.0.1:${ftor.port}` });
  x.bridge.useTor(own, { forPeers: false });
  await own.start();
  assert.equal(own.state, 'ready');
  await waitFor(() => a.node.exits().length === 1, 3000, 'exit in announcement');
  assert.equal(a.node.exits()[0].tor, false, 'the exit is not announced as opening onion sites');
  await a.bridge.startProxy({ port: 0 });
  t.after(async () => {
    a.bridge.proxy.close();
    await stopAll(ns);
    site.closeAllConnections();
    site.close();
    ftor.server.close();
  });
  const r = await get({ port: a.bridge.proxyPort, path: `http://${onion}/`, headers: { host: onion } });
  assert.equal(r.status, 502);
  assert.match(r.body, /no Tor on this node or the net/);
  await x.bridge._exitStream(a.addr, { sid: 1, host: onion, port: 80, tor: true });
  assert.equal(x.bridge.exitLog.length, 0, 'the exit carried nothing for others');
  assert.equal(ftor.seen.filter((s) => s.name === onion).length, 0, 'Tor was never asked for the onion');
});

test("a failed site shows the reader's reason, never a blank page", async (t) => {
  const empty = await listen(http.createServer((req, res) => {
    res.writeHead(503);
    res.end();
  }));
  const onionEmpty = onionOf('g');
  const onionGone = onionOf('h');
  const ftor = await fakeTor({ [onionEmpty]: empty.address().port });
  const a = await makeNode('r');
  await torFor(a, ftor);
  const bare = await makeNode('bare');
  const srv = await listen(http.createServer(makeContentHandler(a.node, a.sites, { reader: a.bridge, readerToken: 'tok' })));
  const srvBare = await listen(http.createServer(makeContentHandler(bare.node, bare.sites, { reader: bare.bridge, readerToken: 'tok' })));
  t.after(async () => {
    srv.close();
    srvBare.close();
    empty.close();
    ftor.server.close();
    await stopAll([a, bare]);
  });
  const e = await get({ port: srv.address().port, path: `/view/tok/http://${onionEmpty}/` });
  assert.equal(e.status, 503);
  assert.match(e.body, /The site sent no page/);
  assert.match(e.body, /503 Service Unavailable/);
  const gone = await get({ port: srv.address().port, path: `/view/tok/http://${onionGone}/` });
  assert.equal(gone.status, 502);
  assert.match(gone.body, /onion site not found/);
  const off = await get({ port: srvBare.address().port, path: `/view/tok/http://${onionEmpty}/` });
  assert.equal(off.status, 502);
  assert.match(off.body, /turn Tor on/);
});

test('the portal Tor card lists the five checked .onion sites; the Tor Project address is written once', async (t) => {
  const n = await makeNode('l');
  const ui = await startPortal(n.node, n.sites, n.msgs, n.bridge, { port: 0 });
  t.after(() => closePortal(ui, [n]));
  const html = (await get({ port: ui.ui, path: '/' })).body;
  const torProject = '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion';
  for (const where of [
    torProject,
    'bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion/',
    'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/',
    'sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion/directory/',
    'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion/index.en.html',
  ]) assert.ok(html.includes(where), `listed: ${where}`);
  assert.equal(html.split(torProject).length - 1, 1, 'the Tor Project address is defined once and reused');
  assert.ok(html.includes('works without JavaScript'), 'each entry says it works without JavaScript');
  assert.ok(html.includes('id="torSites"') && html.includes('data-act="tortoggle"'));
});
