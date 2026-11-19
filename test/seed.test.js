'use strict';
// deploy/seed.js is what a public seed runs. It must keep the --net secret off the command line
// (`ps` and `docker ps --no-trunc` show argv to everyone on the box) and refuse to become anything
// but a relay: a seed's public IP must never carry anyone's internet traffic.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { makeNode, waitFor, tmp } = require('./helpers');

const SEED = path.join(__dirname, '..', 'deploy', 'seed.js');

function run(args, env) {
  const child = spawn(process.execPath, [SEED, ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (out += d));
  const code = new Promise((r) => child.on('exit', r));
  return { child, code, out: () => out };
}

function secretFile(s) {
  const f = path.join(tmp('secret'), 'net');
  fs.writeFileSync(f, s, { mode: 0o600 });
  return f;
}

test('seed refuses to be an exit, a proxy, a gateway or a site', async () => {
  const env = { JAAL_NET_FILE: secretFile(crypto.randomBytes(32).toString('hex')) };
  for (const bad of [['--exit'], ['--exit-open'], ['--exit-ports=80'], ['--proxy', '8118'], ['--proxy-host', '0.0.0.0'], ['--gateway', '8080'], ['--via', 'x'], ['--site', '.'], ['--lan'], ['--net', 'x']]) {
    const r = run([...bad, '--data', tmp('seed')], env);
    assert.equal(await r.code, 2, `${bad[0]} must be refused`);
    assert.match(r.out(), /refus/);
  }
});

test('seed refuses a missing or guessable secret', async () => {
  const missing = run(['--data', tmp('seed')], { JAAL_NET_FILE: path.join(tmp('none'), 'net') });
  assert.equal(await missing.code, 2);
  assert.match(missing.out(), /can't read the net secret/);
  const weak = run(['--data', tmp('seed')], { JAAL_NET_FILE: secretFile('hunter2\n') });
  assert.equal(await weak.code, 2);
  assert.match(weak.out(), /too short/);
});

test('seed links a node holding the same secret, and the secret never reaches its command line', async (t) => {
  const secret = crypto.randomBytes(32).toString('hex');
  const seed = run(['--name', 'seed', '--host', '127.0.0.1', '--port', '0', '--ui', '0', '--data', tmp('seed')], { JAAL_NET_FILE: secretFile(secret + '\n') });
  t.after(() => seed.child.kill());
  await waitFor(() => /links\s+:(\d+)/.test(seed.out()), 10_000, 'seed banner');
  const port = Number(/links\s+:(\d+)/.exec(seed.out())[1]);
  assert.match(seed.out(), /private net/);
  assert.doesNotMatch(seed.out(), /internet\s+proxy|exit\s+sharing|gateway\s+http/, 'no proxy, exit or gateway');

  const a = await makeNode('a', { netKey: secret });
  t.after(() => a.node.stop());
  a.node.addPeer(`127.0.0.1:${port}`);
  await waitFor(() => [...a.node.links].some((l) => l.peer.name === 'seed'), 10_000, 'link to the seed');

  const cmdline = execFileSync('ps', ['-o', 'command=', '-p', String(seed.child.pid)]).toString();
  assert.match(cmdline, /seed\.js/, 'ps sees the seed process');
  assert.ok(!cmdline.includes(secret), 'the secret is not on the command line');
});
