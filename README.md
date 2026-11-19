# ◈ Jāla — your own internet, that also reaches the regular one

**Jāla** (जाल, *net* — after Indra's net, where every jewel reflects every other) is a small
peer-to-peer internet you run yourself, on your own machines. It has its own addresses, its own
sites and its own messages, and it works with **no internet at all**. When some node does have
internet, it **bridges into the regular internet** in both directions.

| | |
|---|---|
| **Own addresses** | `jaal://<32 letters>`: a hash of your key. No registrar, no IP, nobody can revoke it. |
| **Own sites** | Publish a folder. Every file is signed, any node can keep a mirror, and it stays up when you're offline. |
| **Own messages** | Sealed end to end. Relays carry ciphertext only. Offline? It waits and goes when they're back. |
| **No internet needed** | Machines on the same Wi-Fi find each other on their own. Zero config. |
| **Over the internet** | Link to any node by `host:port`. A cheap VPS makes a seed that joins people anywhere. |
| **Into the internet** | A node with internet becomes an **exit**. Point your browser's proxy at your own node and the whole web travels the net. HTTPS stays end-to-end, so the exit sees only ciphertext. |
| **Out of the internet** | A **gateway** lets ordinary browsers read Jāla sites. |

Zero dependencies: Node 20+ and nothing else. MIT.

## Try it

```bash
node bin/jaal.js start --site examples/site
```

Open **http://127.0.0.1:7777** to get the live map of the net, sites, messages and the internet bridge.

**A second machine on the same Wi-Fi.** Run `node bin/jaal.js start` there. The two find each other in about 5 seconds.

**Share one machine's internet with the whole net:**

```bash
jaal start --exit --net <secret>      # the machine that has internet
jaal start --net <secret>             # everyone else (same secret = private net)
curl -x http://127.0.0.1:8118 https://example.com     # or set 127.0.0.1:8118 as the browser's HTTP+HTTPS proxy
```

With the proxy set, `http://<address>.jaal/` opens Jāla sites right in the browser too.

**Join people across the internet.** Run a node on any machine with a public IP, with port 4747 open, and everyone adds `--peer that-host:4747`. Peer exchange then links nodes to each other directly where it can.

**Phones on your Wi-Fi.** Use `--proxy-host 0.0.0.0` to share the proxy and `--gateway 8080` to share a read-only site gateway.

## How it works

| Layer | What happens |
|---|---|
| **Identity** | Ed25519 (signing) + X25519 (encryption). The address is `base32(sha256(keys))[:20 bytes]`, so it's self-certifying. Kept in `~/.jaal/identity.json`. |
| **Links** | TCP. Both sides swap ephemeral X25519 keys, derive one ChaCha20-Poly1305 key per direction (salted with the `--net` secret), then each proves its identity by signing both ephemerals. Frames use counter nonces. A different `--net` secret gives different keys, and the link dies at the handshake. |
| **Discovery** | UDP multicast/broadcast beacons on the LAN, configured `--peer`s with back-off redial, and peer exchange. |
| **Routing** | Every node floods a signed announcement (name, site version, exit ports, mirrors) every 30 s. Each node keeps the freshest / shortest next hop per address. Sequence numbers prevent loops (DSDV-style). Breaks are withdrawn at once, and a `want` flood heals a route in one round trip. |
| **Packets** | Payloads are sealed boxes: ephemeral + static X25519 → HKDF → ChaCha20-Poly1305. Only the destination opens one, and opening it proves the sender. Relays see `from → to` and nothing else. |
| **Streams** | Reliable byte streams over the mesh with a 512 KiB credit window (back-pressure end to end) and sequence numbers (reordering). This is what carries real TCP for the internet bridge. |
| **Sites** | A signed manifest of sha256 hashes. Files are fetched in 192 KiB chunks from the owner or, failing that, from mirrors, and every byte is checked against the signed hash. Nodes serve only their own site and sites they chose to mirror, never what they merely visited. |
| **Exit** | Off by default. It refuses to run open on the public net unless you pass `--exit-open`. Default ports are 80 and 443. It never dials private, loopback, link-local or metadata addresses, and it connects to the exact IP it checked, so DNS rebinding can't swap the target. |
| **Portal** | Bound to `127.0.0.1`. Every API call needs a per-run token embedded in the page, with a Host-header check against DNS rebinding and a nonce CSP. Jāla sites are served from a **different origin** (port + 1) with `connect-src 'self'`. A hostile site can't call your portal, and it can't phone home to the regular internet either. |

## What it is not (yet)

Here's what it doesn't do. Read this before trusting it with anything that matters:

- **Not anonymous.** Relays see who talks to whom (never what), and an exit sees which hosts you visit. Think VPN, not Tor.
- **Routing trusts hop counts.** A malicious node can claim short paths to attract traffic and then drop it. It can't read or forge that traffic, though.
- **Flood routing** suits tens to hundreds of nodes, not millions.
- **No NAT traversal.** A node behind a home router can dial out but can't be dialled. Link through a node with a public IP.
- **Message-layer replay protection** is a 1-hour clock window plus request-id memory, so device clocks must be within an hour.
- **No phone app yet.** Phones use a laptop's proxy and gateway over Wi-Fi.

## Proof

`npm test` runs 17 tests, about 3.5 s, no network. They cover RFC 4648 base32 vectors, sealed-box tamper and impersonation cases, 4-node routing hop counts, a message across two relays that never see the words, signed sites (forged manifests, path-as-hash, bad bytes all refused), a mirror serving after the owner dies, a wrong `--net` secret refused, an offline message delivered on return, a 2 MB stream byte-exact over three hops, proxy HTTP and CONNECT, exit policy in **both** directions, and the gateway.

**Live run, 2026-11-19.** Three separate processes, wired `mathura → prayag → kashi`, with the route checked before any traffic: mathura's only link was prayag, and kashi was 2 hops away. Through mathura's proxy:

- `https://example.com` returned 200.
- `https://en.wikipedia.org/wiki/Indra's_net` returned 200, 345 KB in 0.69 s.
- `http://neverssl.com` returned 200.
- `192.168.1.1` was refused by the exit.
- prayag relayed +126 sealed packets.
- kashi's log showed every connection it made on mathura's behalf.

Killing kashi didn't take its site down: it was then served as `x-jaal-source: mirror prayag`. Two zero-config nodes found each other over Wi-Fi on the first beacon.

## Commands

```
jaal start [--name n] [--data dir] [--port 4747] [--peer host:port]… [--net secret] [--no-lan] [--no-pex]
           [--site folder] [--title text] [--exit] [--exit-open] [--exit-ports 80,443]
           [--proxy 8118] [--proxy-host ip] [--via address] [--ui 7777] [--gateway port] [--quiet]
jaal id
jaal send <address> <text>
jaal get  jaal://<address>/<path>
```

`node bin/jaal.js help` explains each flag.

## Layout

```
bin/jaal.js        CLI
src/crypto.js      identities, addresses, sealed boxes
src/link.js        one encrypted, authenticated hop
src/node.js        links, discovery, routing, packets, requests, streams
src/stream.js      reliable byte streams across the mesh
src/sites.js       signed sites, mirrors
src/messages.js    sealed messages, offline queue
src/bridge.js      exit, local proxy, internet probe
src/netpolicy.js   what an exit will dial
src/web.js         portal, site server, public gateway
src/portal.html    the portal UI
test/              node:test suites
```
