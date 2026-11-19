# Run a seed

A **seed** is a Jāla node on a machine with a public IP. A node behind a home router or on mobile data
can dial out but can't be dialled (Jāla has no NAT traversal yet), so your devices on different networks
meet through a seed. It relays sealed packets: it sees *from → to*, sizes and the IPs that link to it,
never what's inside. It never carries internet traffic. `deploy/seed.js` refuses `--exit`, `--proxy`,
`--gateway`, `--site` and every other flag except `--name --data --port --host --peer --no-pex --ui --quiet`.

## 1. A secret

```bash
openssl rand -hex 32 > net-secret && chmod 600 net-secret
```

Every node of your net starts with this same secret. Never use a word you picked: anyone who can reach
port 4747 can record one handshake and test guesses against it offline. `seed.js` refuses anything
shorter than 32 characters. Move it with `scp`, never on a command line. `seed.js` reads it from a file
so it never shows in `ps` or `docker ps --no-trunc`.

## 2. The seed (Docker, no npm install)

```bash
mkdir -p /srv/jaal-seed/data && cd /srv/jaal-seed
git clone https://github.com/prashantpandey-creator/jaal app
# put the secret at /srv/jaal-seed/net-secret
chown 1000:1000 net-secret data && chmod 600 net-secret && chmod 700 data
docker run -d --name jaal-seed --restart unless-stopped \
  --memory 128m --cpus 0.5 --pids-limit 64 --read-only --tmpfs /tmp:size=8m \
  --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 4747:4747 \
  -v /srv/jaal-seed/app:/app:ro -v /srv/jaal-seed/data:/data -v /srv/jaal-seed/net-secret:/run/jaal-net:ro \
  node:22-bookworm-slim node /app/deploy/seed.js --name seed --data /data --port 4747
```

- **The firewall.** Docker publishes `-p 4747:4747` through its own iptables rules, and those skip ufw:
  the publish *is* the opening. To try it first without opening anything, publish
  `-p 127.0.0.1:4747:4747` and link through `ssh -L 4747:127.0.0.1:4747 <seed-host>`.
- **Without Docker:** `JAAL_NET_FILE=net-secret node deploy/seed.js --data ~/.jaal-seed`, then open
  TCP 4747 (`ufw allow 4747/tcp`).
- **Check:** `docker logs jaal-seed` prints the banner with `private net` and the seed's address. Its own
  memory is about 10 MiB. `docker stats` shows ~110 MiB because it also counts the page cache holding
  the node binary, and the kernel takes that back before it would hit the cap.
- `data/` holds the seed's identity, so its address stays the same across restarts. Keep it.

## 3. Join from any machine (Node 20+)

```bash
git clone https://github.com/prashantpandey-creator/jaal && cd jaal
mkdir -p ~/.config/jaal && chmod 700 ~/.config/jaal    # put the secret at ~/.config/jaal/net-secret
node bin/jaal.js start --net "$(cat ~/.config/jaal/net-secret)" --peer <seed-host>:4747
```

The log shows `link up → seed`, and the portal at http://127.0.0.1:7777 shows every node on the net.
From a script, ask a running node with its portal token:

```bash
node -e 'const u=require(process.argv[1]);fetch(`http://127.0.0.1:${u.ui}/api/status`,{headers:{"x-jaal-token":u.token}}).then(r=>r.json()).then(s=>console.log(s.links.map(l=>l.name)))' ~/.jaal/ui.json
```

A node with the wrong secret dies at the handshake: no link, and nothing in the seed's log.
