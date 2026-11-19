'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const crypto = require('node:crypto');
const { makeNode, chain, stopAll, waitFor, makeSite, get } = require('./helpers');
const { startGateway } = require('../src/web');

const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
const echoServer = () => listen(net.createServer((c) => c.pipe(c)));
const webServer = () => listen(http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(`hello from the internet: ${req.method} ${req.url}`);
}));

// a — b — c — x, x shares "internet" (local test servers stand in for the world: lan: true).
async function exitNet(t) {
  const echo = await echoServer();
  const web = await webServer();
  const ns = await chain(['a', 'b', 'c', 'x'], { netKey: 'om' });
  const [a, b, c, x] = ns;
  x.bridge.enableExit({ ports: [echo.address().port, web.address().port], lan: true });
  await waitFor(() => a.node.exits().length === 1, 3000, 'exit in announcement');
  t.after(async () => {
    await stopAll(ns);
    echo.close();
    web.close();
  });
  return { a, b, c, x, echo, web };
}

test('exit: 2 MB round trip through three hops, byte-exact (flow control + ordering)', async (t) => {
  const { a, x, echo } = await exitNet(t);
  const s = await a.bridge.dial('127.0.0.1', echo.address().port);
  assert.equal(s.exitAddr, x.addr);
  const data = crypto.randomBytes(2 * 1024 * 1024);
  const got = [];
  s.on('data', (d) => got.push(d));
  s.write(data);
  await waitFor(() => got.reduce((n, d) => n + d.length, 0) >= data.length, 20_000, 'echo');
  assert.ok(Buffer.concat(got).equals(data));
  s.end();
});

test('proxy: plain HTTP and a CONNECT tunnel both reach the world through the exit', async (t) => {
  const { a, echo, web } = await exitNet(t);
  await a.bridge.startProxy({ port: 0 });
  t.after(() => a.bridge.proxy.close());
  const pp = a.bridge.proxyPort;
  const wp = web.address().port;
  const plain = await get({ port: pp, path: `http://127.0.0.1:${wp}/hi?x=1`, headers: { host: `127.0.0.1:${wp}` } });
  assert.equal(plain.status, 200);
  assert.equal(plain.body, 'hello from the internet: GET /hi?x=1');

  const sock = net.connect(pp, '127.0.0.1');
  await new Promise((r) => sock.once('connect', r));
  sock.write(`CONNECT 127.0.0.1:${echo.address().port} HTTP/1.1\r\nHost: 127.0.0.1:${echo.address().port}\r\n\r\n`);
  const head = await new Promise((r) => sock.once('data', (d) => r(d.toString())));
  assert.match(head, /^HTTP\/1\.1 200/);
  sock.write('ping through the net');
  const echoed = await new Promise((r) => sock.once('data', (d) => r(d.toString())));
  assert.equal(echoed, 'ping through the net');
  sock.destroy();
});

test('exit refuses private addresses and closed ports by default', async (t) => {
  const ns = await chain(['a', 'x'], { netKey: 'om' });
  t.after(() => stopAll(ns));
  const [a, x] = ns;
  x.bridge.enableExit({ ports: [80, 443] });
  await waitFor(() => a.node.exits().length === 1, 3000, 'exit in announcement');
  await assert.rejects(a.bridge.dial('127.0.0.1', 80), /private\/local address/);
  await assert.rejects(a.bridge.dial('10.1.2.3', 443), /private\/local address/);
  await assert.rejects(a.bridge.dial('::ffff:7f00:1', 443), /private\/local address/);
  await assert.rejects(a.bridge.dial('example.com', 25), /no exit on the net opens port 25/);
  const s = a.node.openStream(x.addr, '93.184.215.14', 25);
  await assert.rejects(new Promise((res, rej) => {
    s.once('connect', res);
    s.once('error', rej);
  }), /port 25 is closed/);
});

test('no open exit on the public net unless asked for', async (t) => {
  const a = await makeNode('a');
  t.after(() => stopAll([a]));
  assert.throws(() => a.bridge.enableExit({}), /refusing to run an open internet exit/);
  a.bridge.enableExit({ open: true });
  assert.deepEqual(a.node.exit, { ports: [80, 443] });
});

test('jaal sites: http://<address>.jaal/ through the proxy, and the public gateway', async (t) => {
  const ns = await chain(['a', 'b', 'd']);
  t.after(() => stopAll(ns));
  const [a, , d] = ns;
  d.sites.publish(makeSite({ 'index.html': '<title>Gateway</title><a href="/about.html">about</a>', 'about.html': 'about page' }));
  await waitFor(() => a.node.nodes.get(d.addr)?.ann.site, 3000, 'site in announcement');
  await a.bridge.startProxy({ port: 0 });
  const gw = await startGateway(a.node, a.sites, a.bridge, { port: 0, host: '127.0.0.1' });
  t.after(() => {
    a.bridge.proxy.close();
    gw.server.close();
  });

  const viaProxy = await get({ port: a.bridge.proxyPort, path: `http://${d.addr}.jaal/`, headers: { host: `${d.addr}.jaal` } });
  assert.equal(viaProxy.status, 200);
  assert.match(viaProxy.body, /Gateway/);

  const page = await get({ port: gw.port, path: `/${d.addr}/` });
  assert.equal(page.status, 200);
  assert.equal(page.headers['x-jaal-site'], d.addr);
  assert.match(page.headers['content-security-policy'], /connect-src 'self'/);
  const about = await get({ port: gw.port, path: '/about.html', headers: { referer: `http://127.0.0.1:${gw.port}/${d.addr}/` } });
  assert.equal(about.status, 302);
  assert.equal(about.headers.location, `/${d.addr}/about.html`);
  const dir = await get({ port: gw.port, path: '/' });
  assert.match(dir.body, /Gateway/);
});
