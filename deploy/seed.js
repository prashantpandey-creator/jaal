#!/usr/bin/env node
'use strict';
// A Jāla seed: a node on a machine with a public IP, so your devices on different networks (home
// Wi-Fi, mobile data, another city) can join one private net. It relays sealed packets and does
// nothing else: no exit, no proxy, no gateway, no site, no LAN discovery.
//
// The --net secret comes from a file (JAAL_NET_FILE, default /run/jaal-net), never the command line,
// because `ps` and `docker ps --no-trunc` show a process's arguments to everyone on the box.
//
//   JAAL_NET_FILE=~/.config/jaal/net-secret node deploy/seed.js [--name seed] [--port 4747] [--data dir]
//
// Also allowed: --host, --peer (link to another seed), --no-pex, --ui, --quiet. Anything else is refused.
const fs = require('node:fs');
const path = require('node:path');

const ALLOWED = new Set(['name', 'data', 'port', 'host', 'peer', 'pex', 'no-pex', 'no-lan', 'ui', 'quiet']);
const die = (msg) => {
  console.error(`seed: ${msg}`);
  process.exit(2);
};

const args = process.argv.slice(2);
const bad = args.filter((a) => a.startsWith('--') && !ALLOWED.has(a.slice(2).split('=')[0]));
if (bad.length) die(`refusing ${bad.join(' ')}: a seed only relays (the secret comes from JAAL_NET_FILE)`);

const file = process.env.JAAL_NET_FILE || '/run/jaal-net';
let secret;
try {
  secret = fs.readFileSync(file, 'utf8').trim();
} catch (e) {
  die(`can't read the net secret from ${file} (${e.code || e.message})`);
}
// Anyone who can reach the port can test guesses offline against a handshake, so no words.
if (secret.length < 32) die(`the net secret in ${file} is too short: use 32+ random bytes (openssl rand -hex 32)`);

process.argv = [process.argv[0], path.join(__dirname, '..', 'bin', 'jaal.js'), 'start', '--net', secret, '--no-lan', '--proxy', '0', ...args];
require('../bin/jaal.js');
