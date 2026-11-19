'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { JaalNode, Sites, Messages, Bridge } = require('../src');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), `jaal-${name}-`));

async function makeNode(name, opts = {}) {
  const { bridge: bopts, ...rest } = opts;
  const node = new JaalNode({ dataDir: tmp(name), name, port: 0, host: '127.0.0.1', lan: false, pex: false, log: () => {}, ...rest });
  const sites = new Sites(node);
  const msgs = new Messages(node);
  const bridge = new Bridge(node, sites, bopts || {});
  await node.start();
  return { node, sites, msgs, bridge, name, addr: node.addr };
}

async function waitFor(fn, ms = 5000, what = 'condition') {
  const t0 = Date.now();
  for (;;) {
    if (await fn()) return;
    if (Date.now() - t0 > ms) throw new Error('timed out waiting for ' + what);
    await sleep(20);
  }
}

// a — b — c — … in a line, each dialling the one before it, so traffic between the ends must relay.
async function chain(names, common = {}, per = {}) {
  const ns = [];
  for (const n of names) ns.push(await makeNode(n, { ...common, ...(per[n] || {}) }));
  for (let i = 1; i < ns.length; i++) ns[i].node.addPeer(`127.0.0.1:${ns[i - 1].node.port}`);
  await waitFor(() => ns.every((a) => ns.every((b) => a === b || a.node.routeTo(b.addr))), 5000, 'routes between every pair');
  return ns;
}

const stopAll = (ns) => Promise.all(ns.map((n) => n.node.stop()));

function makeSite(files) {
  const dir = path.join(tmp('site'), 'www');
  for (const [p, c] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, p)), { recursive: true });
    fs.writeFileSync(path.join(dir, p), c);
  }
  return dir;
}

function get({ port, path: p, headers = {} }) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: p, headers }, (res) => {
      const parts = [];
      res.on('data', (d) => parts.push(d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts).toString() }));
    }).on('error', reject);
  });
}

module.exports = { sleep, tmp, makeNode, waitFor, chain, stopAll, makeSite, get };
