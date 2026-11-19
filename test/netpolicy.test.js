'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { isPrivateIp } = require('../src/netpolicy');

// Both directions on purpose: the first version blocked private ranges AND the whole public internet,
// and a blocking-only test passed on it.
test('exit policy: public addresses pass', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '172.66.147.243', '104.20.23.154', '34.223.124.45', '172.32.0.1', '::ffff:8.8.8.8', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isPrivateIp(ip), false, `${ip} is public`);
  }
});

test('exit policy: private, local and special addresses are blocked', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '198.18.0.5', '224.0.0.1', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', 'not-an-ip']) {
    assert.equal(isPrivateIp(ip), true, `${ip} is private`);
  }
});
