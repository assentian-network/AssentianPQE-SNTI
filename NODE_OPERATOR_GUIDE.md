# SNTI Independent Node Operator Guide

## Why this matters

Assentian-PQE (SNTI) mainnet currently runs on a small number of nodes
operated by the founding team. A blockchain is only as decentralized as
the set of independent parties validating it — the more independent
full nodes on the network, the harder it is for any single party
(including the founder) to censor transactions, rewrite history, or
take the network offline. If you run a full node, you are directly
strengthening SNTI's decentralization and censorship resistance.

Running a node does **not** require mining. A full node validates
blocks and relays transactions/blocks to peers — that alone is a
meaningful contribution.

## What you need

| Resource | Minimum | Notes |
|---|---|---|
| OS | Linux (Ubuntu 20.04+ recommended) | Same as build requirements in DEVDOCS.md |
| RAM | 4 GB | 8 GB if you also plan to mine |
| Disk | 20 GB, growing over time | Chain is XMSS-signature-heavy — see WHITEPAPER.md §12 for growth projections |
| Bandwidth | Modest — a few GB/month at current chain size | Grows with adoption |
| Uptime | As high as you can manage | More uptime = more useful to the network |
| Public IP / port-forwarding | Recommended, not required | Needed only if you want to accept *inbound* peer connections |

## 1. Get the software

Either build from source (see `DEVDOCS.md` → Build Guide) or download
the prebuilt binary:

```bash
# Build from source (recommended if you want to verify the code yourself)
git clone https://github.com/assentian-network/snti.git
cd snti
./autogen.sh
./configure --disable-bench --disable-gui --without-miniupnpc --disable-zmq --without-natpmp
make -j$(nproc)

# OR download the prebuilt binary
curl -O https://assentian.network/bin/bitcoind
chmod +x bitcoind
```

If you download the prebuilt binary, verify its hash against the one
announced in the project's release notes/GitHub before running it.

## 2. Run the node

```bash
./bitcoind \
  -datadir=/root/.bitcoin \
  -rpcuser=<choose-your-own-user> -rpcpassword=<choose-a-strong-password> \
  -rpcport=9332 -rpcallowip=127.0.0.1 \
  -port=9333 \
  -daemon
```

DNS seeds (`seed.assentian.network`, `seed2.assentian.network`,
`seed3.assentian.network`) are embedded in the binary, so your node
will discover peers automatically on first start. Initial sync speed
depends on chain height at the time you join.

## 3. Firewall guidance

- **Open** inbound TCP **9333** (P2P) if you want to accept connections
  from other peers — this is what makes you useful as a relay/seed,
  not just a passive follower.
- **Never** expose RPC port **9332** to the public internet. Keep
  `-rpcallowip=127.0.0.1` (or your private network only) and use a
  strong, unique `rpcpassword`.

## 4. Run it as a persistent service (systemd example)

```ini
[Unit]
Description=SNTI Full Node
After=network.target

[Service]
Type=simple
User=<a-dedicated-non-root-user>
ExecStart=/path/to/bitcoind \
  -datadir=/path/to/datadir \
  -rpcuser=<user> -rpcpassword=<password> \
  -rpcport=9332 -rpcallowip=127.0.0.1 \
  -port=9333
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 5. (Optional) Get listed as a public seed node

If you're willing to run a stable, always-on node with good bandwidth
and want to help new nodes discover the network faster, you can be
added as an additional DNS seed entry alongside the existing ones.
Contact **admin@assentian.network** with your node's public IP and
uptime commitment.

## 6. Mining pools

If you'd rather run a mining pool (against the real SNTI network, not
a fork) than a plain relay node, that's explicitly permitted under the
project LICENSE — see the "What you CAN do" section there.

## Incentives

There is currently no formal reward program for running a relay-only
node beyond the value of a more decentralized, resilient network. If
you're interested in operating long-term, reach out to
**admin@assentian.network** — incentive/partnership options for early
independent operators may be discussed on a case-by-case basis.

## Questions

- Technical: see `DEVDOCS.md` and `MINING_GUIDE.md`
- Licensing: see `LICENSE`
- Contact: admin@assentian.network
