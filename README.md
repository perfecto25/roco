# ROCO (Route Coordinator)

Roco is a network proxy agent that can proxy all packets bound to unreachable endpoint via a reachable relay. ROCO is short for route coordinator.

Its inspired by sshuttle but does not rely on SSH transport or SSH encryption.

Roco is designed for simplicity and sole task of proxying TCP and UDP packets to an unreachable target. Its essentially a lightweight router that can proxy an entire network over a hop.

## How ROCO works

Roco routes packets via intermediate hops (servers). A Roco relay process listens on a port and adds firewall rules to redirect a packet bound for a target to the next node in the "chain".

For every server in the packet's path, there needs to be a Roco process running, since the process is the one managing firewall in-memory rules for routing.

Lets say you have 3 servers, nodeA, nodeB, nodeC

A cannot reach C directly, but A can reach B, and B can reach C

the config on nodeA will look like this

    relays:
      - targets: ['nodeC']
        chain: ['nodeB']

this translates to, "on nodeA, any packet bound for nodeC, send it to nodeB"

on nodeB, a Roco process is running without any config, ie a pure relay

it recieves a packet from nodeA, sees the destination as 'nodeC' and forwards it to nodeC

This works the same way for multi-hop chain, ie A > B > C > D > E > etc

Roco can route TCP packets only

### Encryption

by default, Roco does not encrypt the traffic, for simplicty of setup and performance

to encrypt Roco traffic, see TLS section below.


## Quickstart

Download the roco binary

use the example configs as an example to setup a relay chain



## Relay and originator on the same node

A node can have its own `relays:` list and act as a relay for other nodes at the
same time. Every roco node listens on its `port` (12190 by default), whether or
not it has `relays:`. Each connection is one of two kinds:

- **Local traffic redirected by the firewall.** An app on this node (or a host
  that routes through it) connects to one of the `targets:`. roco sends it down
  that relay's `chain:`.
- **A connection from another roco node.** It starts with a roco handshake that
  carries the full route. roco follows that route and ignores its own `relays:`.

For example, this node sends its own traffic for qbtch2 via qbtch7, and can still
appear in other nodes' `chain:`:

    relays:
      - targets: ["qbtch2"]
        chain: ['qbtch7']

### How roco keeps its own connections out of its redirect rules

The firewall rules redirect all TCP to a target's IP into the listener. Without
an exception, that would include connections roco itself makes. Suppose another
node asks this one to relay to qbtch2 (for example, `chain: [thisnode]` with
target qbtch2). roco's own connection to qbtch2 would then be caught and sent
back into its own listener, and from there via qbtch7 instead of directly. That
breaks when qbtch2 is itself a roco hop in the route, and can loop.

To prevent this, roco sets a firewall mark (`SO_MARK`, value `0x524f`) on every
outbound connection it makes: to the next hop and to the final target. The
first rule in the `ROCO` chain skips marked packets:

    # iptables -t nat -S ROCO
    -A ROCO -m mark --mark 0x524f -j RETURN
    -A ROCO -d <first chain hop> -j RETURN
    -A ROCO -d <target> -p tcp -j REDIRECT --to-ports 12190

    # nft list table ip ROCO   (OUTPUT chain)
    meta mark 0x0000524f return

So traffic that other nodes relay through this one always leaves directly to
the destination they asked for. Only this node's local apps and forwarded
traffic follow its `relays:`.

Setting the mark needs `CAP_NET_ADMIN`. Running as root, or under the provided
systemd unit (which grants it), is enough. Without it, roco still works but logs
this once:

    Cannot set firewall mark on outbound sockets (...); relayed connections to this node's own targets will loop back into roco

If other software on the host uses firewall mark `0x524f` for something else,
its traffic will also skip roco's redirect rules.


## TLS

By default, traffic between roco nodes is unencrypted. With TLS enabled, every
roco-to-roco link runs mutual TLS (TLS 1.3): each side proves its identity with a
certificate signed by your own private CA, and connections from anything
without such a certificate are refused.

What gets encrypted, for a chain `qbtch7 -> atlas -> mrxmac3 -> 192.168.30.135`:

    app on qbtch7 --plain--> roco(qbtch7) ==TLS==> roco(atlas) ==TLS==> roco(mrxmac3) --plain--> 192.168.30.135:22
      (loopback)                                                                              (target doesn't speak roco)

Each hop decrypts and re-encrypts, so intermediate roco nodes can see the
traffic. The final hop to the target stays plain TCP. Use an encrypted
protocol (SSH, HTTPS, ...) on top if that last segment matters.

All certificate work is built into the roco binary (`roco tls ...`). No
`openssl` commands are needed.

### Files

| File | Where | Secret | Purpose |
|---|---|---|---|
| `ca.key` | admin machine only | **yes** | Signs node certificates. Anyone holding it can create certificates every node trusts. Never copy it to a relay. |
| `ca.crt` | admin machine + every node | no | Lets a node check that a peer's certificate was signed by your CA |
| `node.key` | each node, `/etc/roco/tls/` | **yes** (mode 600) | The node's private key |
| `node.crt` | each node, `/etc/roco/tls/` | no | The node's certificate, presented to peers |

Every roco node needs its own `node.key` and `node.crt`, including the
originating node (qbtch7 above). The target host needs nothing.

The "admin machine" can be any machine you control (your laptop, a bastion).
It only runs `roco tls` commands, not the roco daemon.

### Step 1: create the CA (once, on the admin machine)

    mkdir ~/roco-ca && cd ~/roco-ca
    roco tls init-ca

This writes `ca.key` and `ca.crt` to the current directory (or `--dir DIR`). The
CA is valid for 10 years (`--days N` to change). Back up this directory, since
it's needed whenever you add or renew a node.

### Step 2: create a certificate for each node

A node's certificate must contain every name other nodes use for it in their
`chain:` config. If qbtch7's config says `chain: ["atlas", "mrxmac3"]`, then
atlas's certificate needs `atlas` and mrxmac3's needs `mrxmac3`. The node name
you pass is always included. Add any other hostname or IP it's reached by with
`--dns` / `--ip`; both can be repeated or given as comma-separated lists.

Pick either option below for each node.

**Option A: generate everything on the admin machine (simplest)**

    cd ~/roco-ca
    roco tls issue qbtch7
    roco tls issue atlas   --ip 192.168.40.21
    roco tls issue mrxmac3 --ip 192.168.30.109

Each command writes a ready-to-copy bundle to `nodes/<name>/` (`node.key`,
`node.crt`, `ca.crt`). Copy it to the node:

    ssh atlas mkdir -p /etc/roco/tls
    scp nodes/atlas/* atlas:/etc/roco/tls/
    ssh atlas chmod 600 /etc/roco/tls/node.key

**Option B: private key never leaves the node**

On the node:

    roco tls request atlas          # writes /etc/roco/tls/node.key and /etc/roco/tls/atlas.csr

Copy `atlas.csr` to the admin machine, then sign it:

    cd ~/roco-ca
    roco tls sign atlas.csr --ip 192.168.40.21

This writes `nodes/atlas/node.crt` and `nodes/atlas/ca.crt`. Copy both back
next to the node's key:

    scp nodes/atlas/node.crt nodes/atlas/ca.crt atlas:/etc/roco/tls/

Node certificates are valid for 825 days (`--days N` to change). To check what
a certificate contains (names, expiry), run `roco tls show /etc/roco/tls/node.crt`.

### Step 3: enable TLS in each node's config

    tls:
      mode: required          # off | optional | required
      # These are the defaults; only set them if your files live elsewhere.
      ca:   /etc/roco/tls/ca.crt
      cert: /etc/roco/tls/node.crt
      key:  /etc/roco/tls/node.key
      # Optional: only accept connections from these nodes (certificate names).
      # allowed_peers: [qbtch7, atlas]

| mode | Connects to next roco hop | Accepts from roco peers |
|---|---|---|
| `off` (default) | plain | plain only |
| `optional` | TLS | TLS or plain |
| `required` | TLS | TLS only |

### Step 4: restart roco and check the logs

    systemctl restart roco

On startup:

    roco: TLS required, node certificate atlas (/etc/roco/tls/node.crt), accepting any node signed by the CA

Per connection, on the sending and receiving node:

    proxy: Connected to atlas:12190 (192.168.40.21, TLS)
    proxy: Peer handshake (TLS peer qbtch7), route mrxmac3:12190 -> 192.168.30.135:22

If a TLS file is missing or the key doesn't match the certificate, roco exits at
startup with `TLS setup failed: ...`.

### Turning TLS on for a running chain

Every node must be able to accept TLS before the node in front of it starts
sending TLS. `required` also refuses plaintext peers, so switch in two
passes:

1. Install the certificates on all nodes (steps 1 and 2).
2. Set `mode: optional` and restart, starting at the **end** of each chain and
   working back. For `qbtch7 -> atlas -> mrxmac3`, that's mrxmac3, then
   atlas, then qbtch7. Connections keep working throughout, because each node
   still accepts plaintext.
3. Once every node is on `optional`, set `mode: required` everywhere, in any
   order.

During step 2, nodes log `Plaintext peer connection accepted (tls mode: optional)`
for each connection that is still unencrypted. When those messages stop, it's
safe to switch to `required`.

Every node must run a roco version with TLS support (0.1.2+) before you begin.

### Adding a node later

You don't change the CA or the existing nodes. Anything signed by the CA is
trusted automatically.

    cd ~/roco-ca
    roco tls issue nyc5 --ip 10.1.2.3          # or: request on the node + sign
    scp nodes/nyc5/* nyc5:/etc/roco/tls/

Then add `tls:` to nyc5's config and reference it in other nodes' `chain:`
as usual. If you use `allowed_peers`, add `nyc5` to it on the nodes it will
connect to.

### Renewing a node certificate

Before it expires (see `roco tls show`), issue a new one and restart roco on
that node:

    roco tls issue atlas --ip 192.168.40.21 --force     # new key + cert
    # or, keeping the node's key: roco tls sign atlas.csr --ip 192.168.40.21 --force

### Removing (revoking) a node

roco has no certificate revocation list. To lock a node out while its
certificate is still valid, list the nodes you do trust with
`allowed_peers` on the nodes it used to connect to, and leave the removed one
out. Also delete its bundle from `nodes/` on the admin machine.

If `ca.key` itself leaks, create a new CA and reissue every node (next section).

### Replacing the CA

Needed when the CA nears expiry or `ca.key` is compromised. To avoid downtime:

1. Create the new CA in a separate directory:
   `roco tls init-ca --dir ~/roco-ca-2027 --name "roco CA 2027"`.
2. On every node, make `ca.crt` contain both CAs, then restart:
   `cat old-ca.crt new-ca.crt > /etc/roco/tls/ca.crt`.
3. Reissue each node's certificate from the new CA
   (`roco tls issue <node> --dir ~/roco-ca-2027 ...`), install `node.key` and
   `node.crt` (keep the combined `ca.crt`), and restart. Do this one node at a time.
4. When all nodes are moved over, replace `ca.crt` on every node with the new
   CA only, and restart.

### `roco tls` command reference

    roco tls init-ca [--dir DIR] [--name NAME] [--days N] [--force]
    roco tls issue   <node> [--ip IP] [--dns NAME] [--dir DIR] [--days N] [--force]
    roco tls request <node> [--dir DIR] [--force]                  # default DIR: /etc/roco/tls
    roco tls sign    <node.csr> [--ip IP] [--dns NAME] [--dir DIR] [--days N] [--force]
    roco tls show    <file.crt>

For `init-ca`, `issue` and `sign`, `--dir` is the CA directory (default: the
current directory). Keys are Ed25519. Existing files are never overwritten
without `--force`.

### Troubleshooting

| Log message | Meaning |
|---|---|
| `Plaintext peer connection rejected (tls mode: required)` | The upstream node isn't using TLS: it has `mode: off`, or it runs a roco version without TLS |
| `TLS handshake with atlas failed: ... certificate verify failed` (on the sending node) | atlas's certificate doesn't contain the name `atlas`, is expired, or is from a different CA. Check with `roco tls show` on atlas |
| `TLS handshake failed: ... certificate verify failed` (on the receiving node) | The connecting node's certificate is from a different CA or expired |
| `TLS peer 'x' is not in allowed_peers` | The certificate is valid, but the node isn't listed in `allowed_peers` |
| `Route down: TLS handshake with ... failed` (on the originating node) | A hop further down the chain failed its TLS handshake. See that hop's log |

Nodes' clocks must be roughly correct: certificates aren't valid before their
creation time (minus 5 minutes).


## Building

single binary for all linux versions (musl-linked binary)


    docker run --rm -v $PWD:/w -w /w crystallang/crystal:1.18.0-alpine \
    crystal build src/roco.cr -o bin/roco --release --static

## Publishing builds

    git tag v0.1.2 && git push origin v0.1.2


## Changelog

0.1.2 - added encryption option
0.1.2 - relayed connections skip the node's own redirect rules (firewall mark 0x524f), so a node can be a relay and have its own targets