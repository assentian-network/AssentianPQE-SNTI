# Contributing to SNTI

Thank you for your interest in contributing to Assentian-PQE (SNTI) — the first mineable post-quantum blockchain. This document covers the practical process for contributing code, tests, and documentation.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Building from Source](#building-from-source)
- [Running a Local Test Node](#running-a-local-test-node)
- [Finding Something to Work On](#finding-something-to-work-on)
- [Contributor Workflow](#contributor-workflow)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Critical Areas](#critical-areas)
- [Code Style](#code-style)
- [Communication](#communication)

---

## Getting Started

SNTI is a Bitcoin Core v27 fork with two major subsystems added:

- **XMSS-SHA2_10_256** post-quantum signatures replacing ECDSA/secp256k1
- **PoUW v2** (Proof-of-Useful-Work) replacing SHA-256 nonce grinding with XMSS tree construction

Before contributing, read:
- [`doc/pouw-v2.md`](doc/pouw-v2.md) — PoUW v2 algorithm design
- [`src/pouw_v2.h`](src/pouw_v2.h) — proof structure, `CheckPoUWv2()`, `CalcNextTargetEMA()`
- [`src/wallet/xmss_signer.h`](src/wallet/xmss_signer.h) — XMSS key lifecycle and state

---

## Building from Source

### Dependencies (Ubuntu 22.04 / Debian 12)

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

Build time: 15–30 minutes. The relevant binaries are `src/bitcoind` and `src/bitcoin-cli`.

To also build tests:
```bash
./configure --without-gui
make -j$(nproc)
make check
```

---

## Running a Local Test Node

Use **regtest** mode for local development — it allows instant block generation without real mining.

```bash
# Start a regtest node
./src/bitcoind -regtest -rpcport=18443 -rpcuser=test -rpcpassword=test -daemon

# Create a wallet and generate an XMSS address
./src/bitcoin-cli -regtest -rpcport=18443 -rpcuser=test -rpcpassword=test \
  createwallet "dev_wallet"

ADDR=$(./src/bitcoin-cli -regtest -rpcport=18443 -rpcuser=test -rpcpassword=test \
  -rpcwallet=dev_wallet getnewxmssaddress | python3 -c "import sys,json; print(json.load(sys.stdin)['address'])")

# Mine blocks (each runs a real XMSS tree build — takes 2–6 seconds each)
./src/bitcoin-cli -regtest -rpcport=18443 -rpcuser=test -rpcpassword=test \
  generatetoaddress 10 "$ADDR"

# Check balance
./src/bitcoin-cli -regtest -rpcport=18443 -rpcuser=test -rpcpassword=test \
  -rpcwallet=dev_wallet getbalances

# Stop node
./src/bitcoin-cli -regtest -rpcport=18443 -rpcuser=test -rpcpassword=test stop
```

> **Note:** XMSS keys are stateful — each `generatetoaddress` call consumes one leaf from the wallet's XMSS tree. The wallet tracks leaf index automatically and refuses to reuse a key.

---

## Finding Something to Work On

- Check [open issues](https://github.com/assentian-network/snti/issues) for bugs and feature requests
- Issues labeled `good first issue` are suitable for new contributors
- Issues labeled `consensus-critical` require extra care (see [Critical Areas](#critical-areas))

If you plan to work on an issue, leave a comment so others know it is being addressed.

---

## Contributor Workflow

1. Fork the repository
2. Create a topic branch from `main`:
   ```bash
   git checkout -b your-branch-name
   ```
3. Make your changes (keep commits focused — one logical change per commit)
4. Test locally in regtest mode
5. Push your branch and open a Pull Request against `assentian-network/snti:main`

---

## Commit Guidelines

- **One logical change per commit.** Do not mix refactoring, formatting, and feature changes in a single commit.
- **Subject line:** 50 characters max. Use the area prefix format:

  ```
  pouw: fix EMA difficulty underflow at genesis
  xmss: enforce leaf index bound on coinbase signing
  wallet: retire key before broadcasting, not after
  rpc: add getxmssleafstatus command
  validation: reject blocks with pouw-sig-too-large
  explorer: fix balance display for dust UTXOs
  doc: update PoUW v2 algorithm description
  build: add libssl dependency to configure.ac
  ```

- **Body:** Explain *why*, not *what*. Include references to related issues (`fixes #42`).
- Do not include `@` mentions in commit messages.

---

## Pull Request Guidelines

- Keep PRs focused. A PR should do one thing: fix a bug, add a feature, or refactor — not all three.
- The PR description must explain what the change does and why.
- For bug fixes, describe how to reproduce the bug and verify the fix.
- For consensus changes, open an issue for discussion **before** writing code.
- All PRs must pass CI before merge.

### PR Title Format

Use the same area prefix as commits:

```
pouw: clamp min_target to 1 to prevent difficulty underflow
wallet: fix key retirement race on parallel signing
```

---

## Critical Areas

Changes to these areas require extra review and a clear rationale:

### PoUW v2 Consensus Code
Files: `src/pouw_v2.h`, `src/mining.cpp` (GenerateBlock), `src/validation.cpp` (CheckPoUWv2), `src/pow.cpp` (CalcNextTargetEMA)

- Any change here affects block validity across all nodes on the network.
- Must include regtest reproduction steps demonstrating the old and new behavior.
- Breaking changes require a hard fork height (`nPoUWv3StartHeight` pattern).

### XMSS Key State
Files: `src/wallet/xmss_signer.h/cpp`, `src/xmss_keystore.h`, `src/wallet/xmss_bridge.cpp`

- XMSS is a **stateful** signature scheme. Reusing a leaf index breaks security permanently.
- The wallet enforces that `leaf_index < 1024` before signing and marks the leaf consumed immediately.
- Changes to key state management must be conservative — err on the side of refusing to sign rather than allowing a potentially reused key.

### Consensus Parameters
File: `src/chainparams.cpp`

- `nXMSSChainId` must be unique per network (mainnet=1, testnet=2, signet=3, regtest=4).
- Genesis block hash and nBits are fixed — changes here produce a different chain entirely.

---

## Code Style

SNTI follows the Bitcoin Core C++ style as described in [`doc/developer-notes.md`](doc/developer-notes.md), with these additions:

- XMSS-specific structs and functions use the `XMSS` prefix (`CXMSSSigner`, `XMSSKeyStore`, etc.)
- PoUW v2 structs use `PoUW` prefix (`CPoUWProof`, `CheckPoUWv2`, etc.)
- Avoid allocating large buffers on the stack — XMSS signatures are ~2,500 bytes; use `std::vector`

---

## Communication

- **Bug reports and feature requests:** [GitHub Issues](https://github.com/assentian-network/snti/issues)
- **Pull request discussion:** comments on the PR itself
- **General discussion:** [GitHub Discussions](https://github.com/assentian-network/snti/discussions)

Please be respectful and constructive. This is a small project — every contributor matters.

---

## License

By contributing to this repository, you agree to license your work under the same license as the project (BSL-1.1, converting to GPL-2.0 on 15 Jun 2030).
