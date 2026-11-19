#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { JaalNode, Sites, Messages, Bridge, startPortal, startGateway } = require('../src');
const { Tor } = require('../src/tor');

const HELP = `
  ◈ jāla — your own internet, that also reaches the regular one

  jaal start [options]           run a node
    --name <name>                how you appear on the net (default: this computer's name)
    --data <dir>                 your identity, sites and messages (default ~/.jaal)
    --port <n>                   link port other nodes dial (default 4747)
    --peer <host:port>           link to a node — repeat for more. On the same Wi-Fi you need none.
    --net <secret>               private net: only nodes started with the same secret can link
    --no-lan                     don't look for nodes on the local network
    --site <folder>              publish this folder as your site (needs an index.html)
    --title <text>               site title (default: the page's <title>)
    --exit                       share this node's internet with the net (needs --net, or --exit-open)
    --exit-open                  allow --exit on the public net: anyone can then use your connection
    --exit-ports <list>          ports the exit opens (default 80,443)
    --proxy <port>               local HTTP/HTTPS proxy into the net (default 8118, 0 = off)
    --proxy-host <ip>            default 127.0.0.1 — 0.0.0.0 shares it with phones on your Wi-Fi
    --via <address>              always leave through this exit
    --ui <port>                  portal at http://127.0.0.1:<port> (default 7777; sites on port+1)
    --gateway <port>             public, read-only web gateway to Jāla sites (off by default)
    --tor                        use Tor: .onion sites open, and .onion peers link. Uses a Tor already running
                                 (port 9050/9150), or starts its own that stops with the node.
    --tor-all                    send ALL internet traffic through Tor (fails closed: no Tor, nothing sent)
    --onion                      run Tor and make this node an onion service: reachable from anywhere as
                                 <name>.onion:4747, no public IP or open port needed
    --tor-socks <host:port>      use the Tor at this SOCKS port
    --exit --tor                 an exit that also opens .onion sites for the rest of the net
    --quiet                      no log lines

  jaal id   [--data <dir>]                    print your address
  jaal send <address> <text> [--data <dir>]   send a message through your running node
  jaal get  <jaal://address/path | .onion | https://…> [--data <dir>]  print a page through your running node
`;

const FLAGS = new Set(['exit', 'exit-open', 'exit-lan', 'lan', 'pex', 'quiet', 'help', 'tor', 'tor-all', 'onion']);

function parse(argv) {
  const o = { _: [], peer: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      o._.push(a);
      continue;
    }
    let [k, v] = a.slice(2).split(/=(.*)/s);
    if (k.startsWith('no-')) {
      o[k.slice(3)] = false;
      continue;
    }
    if (v === undefined && !FLAGS.has(k)) v = argv[++i];
    if (v === undefined) v = true;
    if (k === 'peer') o.peer.push(v);
    else o[k] = v;
  }
  return o;
}

const dataDir = (o) => path.resolve(String(o.data || path.join(os.homedir(), '.jaal')).replace(/^~(?=$|\/)/, os.homedir()));
const kb = (n) => (n > 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.ceil(n / 1024)} KB`);
const num = (v, d) => (v === undefined || v === true ? d : Number(v));
const die = (msg) => {
  console.error(`jaal: ${msg}`);
  process.exit(1);
};

async function start(o) {
  const stamp = () => new Date().toTimeString().slice(0, 8);
  const node = new JaalNode({
    dataDir: dataDir(o),
    name: o.name,
    port: num(o.port, 4747),
    host: o.host,
    peers: o.peer,
    netKey: o.net ? String(o.net) : null,
    lan: o.lan !== false,
    pex: o.pex !== false,
    log: o.quiet ? () => {} : (...a) => console.log(`\x1b[2m${stamp()}\x1b[0m`, ...a),
  });
  const sites = new Sites(node);
  const msgs = new Messages(node);
  const bridge = new Bridge(node, sites, { via: o.via || null, torAll: !!o['tor-all'] });
  const wantTor = o.tor || o.onion || o['tor-all'] || o['tor-socks'];
  const tor = wantTor ? new Tor(node, { socks: o['tor-socks'] && o['tor-socks'] !== true ? String(o['tor-socks']) : null, onion: !!o.onion, torPath: o['tor-path'] }) : null;
  if (tor) bridge.useTor(tor);
  if (o.site) {
    const r = sites.publish(String(o.site), o.title ? String(o.title) : undefined);
    node.log(`site published: "${r.title}" — ${r.files} files, ${kb(r.bytes)}`);
  }
  if (o.exit) {
    const ports = String(o['exit-ports'] || '80,443').split(',').map(Number).filter(Boolean);
    bridge.enableExit({ ports, open: !!o['exit-open'], lan: !!o['exit-lan'] });
  }
  await node.start();
  if (tor) await tor.start(); // a Tor already running answers at once; our own bootstraps in the background
  const proxyPort = num(o.proxy, 8118);
  if (proxyPort) {
    try {
      await bridge.startProxy({ port: proxyPort, host: String(o['proxy-host'] || '127.0.0.1') });
    } catch (e) {
      node.log(`proxy not started (${e.code || e.message}) — try --proxy <other port>`);
    }
  }
  const ui = await startPortal(node, sites, msgs, bridge, { port: num(o.ui, 7777) });
  let gw = null;
  if (o.gateway) gw = await startGateway(node, sites, bridge, { port: num(o.gateway, 8080), host: String(o['gateway-host'] || '0.0.0.0') });

  const b = (s) => `\x1b[1m${s}\x1b[0m`;
  const g = (s) => `\x1b[38;5;214m${s}\x1b[0m`;
  const lines = [
    '',
    `  ${g('◈ JĀLA')}  ${b(node.opts.name)}  ·  ${node.privateNet ? 'private net' : 'public net'}`,
    `  address   ${g('jaal://' + node.addr)}`,
    `  links     :${node.port}${node.opts.lan ? '  ·  LAN discovery on' : ''}${o.peer.length ? '  ·  peers ' + o.peer.join(', ') : ''}`,
    `  portal    http://127.0.0.1:${ui.ui}`,
    `  sites     http://127.0.0.1:${ui.content}/<address>/${node.site ? `   ·   yours: "${node.site.title}"` : ''}`,
  ];
  if (bridge.proxyPort) lines.push(`  internet  proxy ${bridge.proxyHost}:${bridge.proxyPort} — set it as HTTP+HTTPS proxy; http://<address>.jaal/ works there too`);
  if (bridge.policy) lines.push(`  exit      sharing this machine's internet · ports ${bridge.policy.ports.join(',')}${bridge.policy.open ? ' · OPEN to anyone' : ' · your net only'}`);
  if (gw) lines.push(`  gateway   http://0.0.0.0:${gw.port}/ — anyone can read Jāla sites here`);
  if (tor) {
    const t = tor.info();
    lines.push(`  tor       ${t.state === 'ready' ? `ready (Tor already running here, ${t.socks})` : t.state === 'starting' ? `starting our own Tor… .onion sites open when it's ready${o.onion ? '; the onion address is logged then' : ''}` : t.error}${bridge.opts.torAll ? '  ·  ALL traffic through Tor' : ''}`);
  }
  console.log(lines.join('\n') + '\n');

  let stopping = false;
  const bye = async () => {
    if (stopping) process.exit(0);
    stopping = true;
    if (tor) tor.stop();
    await node.stop();
    process.exit(0);
  };
  process.on('SIGINT', bye);
  process.on('SIGTERM', bye);
}

function localApi(o, method, route, body) {
  let info;
  try {
    info = JSON.parse(fs.readFileSync(path.join(dataDir(o), 'ui.json'), 'utf8'));
  } catch {
    die('no running node found (start one with `jaal start`)');
  }
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request({ host: '127.0.0.1', port: info.ui, method, path: '/api/' + route, headers: { 'x-jaal-token': info.token, 'content-type': 'application/json' } }, (res) => {
      let s = '';
      res.on('data', (d) => (s += d));
      res.on('end', () => {
        const j = JSON.parse(s || '{}');
        res.statusCode === 200 ? resolve(j) : reject(new Error(j.error || res.statusCode));
      });
    });
    req.on('error', () => reject(new Error('no running node answered (start one with `jaal start`)')));
    req.end(data);
  });
}

async function main() {
  const o = parse(process.argv.slice(2));
  const cmd = o._[0];
  if (!cmd || o.help || cmd === 'help') return console.log(HELP);
  if (cmd === 'start') return start(o);
  if (cmd === 'id') {
    const node = new JaalNode({ dataDir: dataDir(o), log: () => {} });
    return console.log(node.addr);
  }
  if (cmd === 'send') {
    const [, to, ...words] = o._;
    if (!to || !words.length) die('usage: jaal send <address> <text>');
    const m = await localApi(o, 'POST', 'send', { to: to.replace(/^jaal:\/\//, ''), text: words.join(' ') });
    return console.log(`${m.status}${m.err ? ` (${m.err})` : ''}`);
  }
  if (cmd === 'get') {
    const arg = String(o._[1] || '');
    const u = /^(?:jaal:\/\/)?([a-z2-7]{32})(\/.*)?$/.exec(arg);
    const web = !u && (/^https?:\/\//i.test(arg) || /^[a-z0-9.-]+\.onion(?::\d+)?(\/|$)/i.test(arg));
    if (!u && !web) die('usage: jaal get <jaal://address/path | something.onion/path | https://…>');
    let info;
    try {
      info = JSON.parse(fs.readFileSync(path.join(dataDir(o), 'ui.json'), 'utf8'));
    } catch {
      die('no running node found (start one with `jaal start`)');
    }
    const reqPath = u ? `/${u[1]}${u[2] || '/'}` : info.reader + (/^https?:\/\//i.test(arg) ? arg : 'http://' + arg);
    http.get({ host: '127.0.0.1', port: info.content, path: reqPath }, (res) => {
      if (res.statusCode >= 400) process.exitCode = 1;
      res.pipe(process.stdout);
    }).on('error', () => die('no running node answered'));
    return;
  }
  die(`unknown command "${cmd}" — try: jaal help`);
}

main().catch((e) => die(e.message));
