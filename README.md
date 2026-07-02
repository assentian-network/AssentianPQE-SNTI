# SNTI — Assentian-PQE Quantum-Resistant Blockchain

The world's first mineable post-quantum cryptocurrency. A Bitcoin Core v27 fork using **XMSS-SHA2_10_256** post-quantum signatures and **PoUW v2** (Proof-of-Useful-Work) mining.

> **Mainnet is live** — Genesis block mined 26 Jun 2026. Block explorer at [assentian.network/explorer](https://assentian.network/explorer/)

---

## Overview

| Feature | Specification |
|---|---|
| Ticker | **SNTI** |
| Signature Scheme | XMSS-SHA2_10_256 (NIST SP 800-208) |
| Proof of Work | PoUW v2 — XMSS tree building (no SHA-256 nonce grinding) |
| Block Time | 60 seconds |
| Max Supply | 210,000,000 SNTI |
| Initial Block Reward | 50 SNTI |
| Halving Interval | 2,100,000 blocks (~4 years) |
| P2P Port | 9333 (mainnet), 19333 (testnet) |
| RPC Port | 9332 (mainnet), 18332 (testnet) |
| Address Prefix | `snti1` (mainnet), `tsnti1` (testnet) |
| Script Types | P2XMSS, P2XMSSHASH |

---

## Why SNTI?

Classical blockchains (Bitcoin, Ethereum) rely on ECDSA/secp256k1 signatures — vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. SNTI uses **XMSS**, a hash-based post-quantum signature scheme standardized by NIST (SP 800-208), as the signature scheme for every wallet, address, and mining reward. (Note: legacy ECDSA opcodes are inherited from the Bitcoin Core codebase and are not rejected at the consensus level — see WHITEPAPER.md §13.1 — but no wallet or tooling generates them and none has ever been used on-chain.)

Mining also changes: instead of wasting energy on SHA-256 nonce grinding, **PoUW v2** requires miners to build XMSS cryptographic trees — work that directly produces post-quantum security material.

---

## Mainnet

| Item | Detail |
|---|---|
| Genesis Block | `b4a26aef52f6f5038815f26917cb0ea1fd3b3b13fbc7cfb5c541088a6943a5ba` |
| Genesis Time | 26 Jun 2026 (Unix: 1782474812) |
| Genesis nBits | `0x2001a41a` |
| Network | `mainnet` |
| Explorer | https://assentian.network/explorer/ |
| Web Wallet | https://assentian.network/wallet/ |
| DNS Seeds | `seed.assentian.network`, `seed2.assentian.network`, `seed3.assentian.network` |

### Connect to Mainnet

```bash
./src/bitcoind \
  -datadir=~/.bitcoin \
  -rpcuser=<user> -rpcpassword=<pass> \
  -rpcport=9332 -port=9333 \
  -rpcallowip=127.0.0.1 \
  -walletcrosschain \
  -daemon

# Check sync status
./src/bitcoin-cli -rpcport=9332 -rpcuser=<user> -rpcpassword=<pass> getblockchaininfo
```

DNS seeds are embedded in the binary — your node will automatically discover peers on first start.

---

## Building from Source

### Dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libtool autotools-dev automake pkg-config \
  bsdmainutils python3 libevent-dev libboost-dev libsqlite3-dev libssl-dev git
```

### Build

```bash
git clone https://github.com/assentian-network/snti.git
cd snti
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j$(nproc)
```

Build time: 15–30 minutes depending on hardware.

### Pre-built Binaries

Stripped Linux x86-64 binaries available at:
```
https://assentian.network/bin/bitcoind
https://assentian.network/bin/bitcoin-cli
```

SHA-256: `c3070e74998f0234bc856ec712e7b40fea540fb40f62a3c844ba96ef3689a7f0` (bitcoind)

---

## Quick Start (Regtest)

```bash
./src/bitcoind -regtest -rpcport=18443 -daemon
./src/bitcoin-cli -regtest -rpcport=18443 createwallet "test_wallet"

# Generate XMSS address
ADDR=$(./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=test_wallet getnewxmssaddress | python3 -c "import sys,json; print(json.load(sys.stdin)['address'])")

# Mine a block
./src/bitcoin-cli -regtest -rpcport=18443 generatetoaddress 1 "$ADDR"

# Check balance
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=test_wallet getbalances
```

---

## PoUW v2 Algorithm

PoUW v2 fully replaces SHA-256 nonce grinding. XMSS tree building **is** the proof of work.

1. Miner selects a random SK_SEED (96 bytes: SK_SEED | SK_PRF | PUB_SEED)
2. Builds an XMSS-SHA2_10_256 tree of height 10 (~2–6 seconds depending on hardware)
3. Extracts the `xmssRoot` (32-byte Merkle root)
4. Checks: `xmssRoot < target` — if not, repeat from step 1
5. If valid: signs the block hash with leaf index 0
6. Embeds auth_path + WOTS+ signature in coinbase OP_RETURN (~2,660 bytes)
7. Broadcasts the block

`nNonce` is always 0. EMA difficulty adjusts per block (alpha=0.1, target=60s).

---

## XMSS Address Model

- Each XMSS address is used **at most once** for spending
- After signing, the key is retired — wallet refuses to sign again with the same address
- Change is automatically sent to a new XMSS address
- Two script types:
  - **P2XMSS** — `<64-byte-pubkey> OP_XMSS_CHECKSIG` (pubkey known to sender)
  - **P2XMSSHASH** — `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_XMSS_CHECKSIG` (like P2PKH)

> ⚠️ **CRITICAL: never run the same `wallet.dat` on two machines at once.**
> The "retired after signing" protection above is tracked per-key on disk in `wallet.dat` itself (and, for mining-derived addresses, also in a shared on-disk ledger — see [WHITEPAPER.md §13.1](WHITEPAPER.md)) — but neither mechanism survives a **stale backup**. If you restore or copy a `wallet.dat` snapshot taken *before* a signature was made, and both the original and the restored copy later sign with the same XMSS address (same `leaf_index`), you produce two signatures from the same one-time key. XMSS's security collapses under key reuse: an attacker who observes both signatures can mathematically reconstruct the private key and steal all funds on that address.
>
> **This is not caught by the blockchain.** SNTI's consensus-level leaf-reuse check only protects the mining proof embedded in each block (so two miners can't reuse the same mining tree's leaf) — it does **not** inspect ordinary spending transactions. Two independent nodes signing regular sends from the same restored address will both succeed and both be accepted on-chain; nothing on the network will warn you.
>
> Treat `wallet.dat` restores like a hardware wallet seed — restore to exactly one live node, never run backups "just in case" in parallel, and if you must migrate to a new machine, shut down the old node first and confirm it stays offline.

---

## Architecture

```
src/
├── pouw_v2.h               # PoUW v2: proof struct, CheckPoUWv2(), CalcNextTargetEMA()
├── primitives/block.h      # CBlockHeader — xmssRoot, nLeafIndex, commitmentsRoot
├── pow.cpp                 # EMA difficulty adjustment + stuck-chain recovery
├── validation.cpp          # Block validation for PoUW v2
├── rpc/mining.cpp          # GenerateBlock() — mining loop
├── wallet/
│   ├── xmss_signer.h/cpp   # CXMSSSigner — signing, state, key retirement
│   └── rpc/xmss.h/cpp      # RPC: getnewxmssaddress, getxmssaddressinfo, etc.
└── script/
    ├── interpreter.cpp     # OP_XMSS_CHECKSIG — signature verification
    └── sign.cpp            # SignStep() — XMSS transaction signing
explorer/
├── server.py               # Flask API + web wallet backend
├── index.html              # Block explorer UI
└── snti-coin.svg           # SNTI coin icon
```

---

## XMSS Parameters

| Parameter | Value |
|---|---|
| Algorithm | XMSS-SHA2_10_256 |
| Tree Height | 10 (1024 leaves) |
| Security Level | 256-bit post-quantum |
| Public Key | 64 bytes |
| Signature Size | ~2,500 bytes |
| Standard | NIST SP 800-208 |

---

## Status (30 Jun 2026)

| Item | Status |
|---|---|
| Mainnet | ✅ Live — block 1170+ |
| PoUW v2 mining | ✅ Operational |
| P2XMSS + P2XMSSHASH spending | ✅ Operational |
| XMSS key retirement | ✅ Operational |
| DNS seeds (3 nodes) | ✅ Operational |
| Web wallet (custodial) | ✅ Operational |
| Non-custodial wallet | ✅ Operational |
| Block explorer | ✅ Operational |
| Pool mining | 🔄 In development (Phase 3) |
| External security audit | 🔄 Planned |

---

## References

- [NIST SP 800-208](https://doi.org/10.6028/NIST.SP.800-208) — Recommendation for Stateful Hash-Based Signature Schemes
- [RFC 8391](https://tools.ietf.org/html/rfc8391) — XMSS: eXtended Merkle Signature Scheme
- [Bitcoin Core](https://github.com/bitcoin/bitcoin) — Base codebase (v27)

---

## License

BSL-1.1, converting to GPL-2.0 on 15 Jun 2030.
