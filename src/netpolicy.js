'use strict';
// What an exit node will and won't dial on behalf of the net.
// Private / loopback / link-local / metadata ranges are refused, so nobody on the net can use your
// exit to reach your router, your LAN, or 127.0.0.1. We connect to the exact IP we checked, so a
// DNS answer can't be swapped underneath us (rebinding).
const net = require('node:net');
const dns = require('node:dns');

// Two lists on purpose: a BlockList also tests IPv4 addresses against its IPv6 rules (as
// ::ffff:a.b.c.d), so one shared list with ::ffff:0:0/96 in it would block the entire IPv4 internet.
const block4 = new net.BlockList();
for (const [a, p] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) block4.addSubnet(a, p, 'ipv4');
const block6 = new net.BlockList();
for (const [a, p] of [
  ['::', 96], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32],
  ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8],
]) block6.addSubnet(a, p, 'ipv6');

function isPrivateIp(ip) {
  if (typeof ip !== 'string') return true;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) ip = mapped[1];
  const fam = net.isIP(ip);
  if (fam === 4) return block4.check(ip, 'ipv4');
  if (fam === 6) return block6.check(ip, 'ipv6'); // hex-form mapped (::ffff:7f00:1) lands in ::ffff:0:0/96
  return true;
}

async function resolveTarget(host, allowLan) {
  host = String(host).replace(/^\[|\]$/g, '');
  let ips;
  if (net.isIP(host)) ips = [host];
  else {
    if (!/^[a-z0-9_.-]{1,253}$/i.test(host)) throw new Error('bad hostname');
    const found = await dns.promises.lookup(host, { all: true });
    ips = found.sort((a, b) => a.family - b.family).map((r) => r.address); // IPv4 first: works on more exits
  }
  for (const ip of ips) if (allowLan || !isPrivateIp(ip)) return ip;
  throw new Error(`${host} is a private/local address — blocked by this exit`);
}

async function dialOut(host, port, policy = {}) {
  const ip = await resolveTarget(host, policy.lan);
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: ip, port });
    const t = setTimeout(() => {
      sock.destroy();
      reject(new Error(`connecting to ${host}:${port} timed out`));
    }, 15_000);
    const onErr = (e) => {
      clearTimeout(t);
      reject(e);
    };
    sock.once('error', onErr);
    sock.once('connect', () => {
      clearTimeout(t);
      sock.off('error', onErr);
      resolve(sock);
    });
  });
}

module.exports = { isPrivateIp, resolveTarget, dialOut };
