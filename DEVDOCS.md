# Assentian-PQE (SNTI) Developer Documentation

> **Ticker**: SNTI · **Copyright**: Asep Mulya · **GitHub**: https://github.com/assentian-network/snti

## Table of Contents

1. [Build Guide](#build-guide)
2. [RPC API Reference](#rpc-api-reference)
3. [XMSS Wallet Guide](#xmss-wallet-guide)
4. [Mining Guide](#mining-guide)
5. [Testnet Guide](#testnet-guide)
6. [Architecture](#architecture)

---

## Build Guide

### System Requirements

- Linux (Ubuntu 20.04+ recommended)
- 4GB RAM minimum
- 20GB disk space
- GCC 9+ or Clang 10+

### Dependencies

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential libtool autotools-dev automake pkg-config \
  libssl-dev libevent-dev bsdmainutils python3 \
  libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
  libboost-test-dev libboost-thread-dev \
  libdb-dev libdb++-dev
```

### Build Steps

```bash
# Clone repository
git clone https://github.com/assentian-network/snti.git
cd snti

# Generate configure script
./autogen.sh

# Configure (disable GUI and benchmarks for faster build)
./configure --disable-bench --disable-gui --without-miniupnpc \
  --disable-zmq --without-natpmp

# Build
make -j$(nproc)
```

### Build Output

| Binary | Path | Description |
|--------|------|-------------|
| bitcoind | src/bitcoind | Main daemon |
| bitcoin-cli | src/bitcoin-cli | RPC client |
| bitcoin-wallet | src/bitcoin-wallet | Wallet management |
| bitcoin-tx | src/bitcoin-tx | Transaction builder |

### Running the Node (Mainnet)

```bash
./src/bitcoind \
  -datadir=/root/.bitcoin \
  -rpcuser=<user> -rpcpassword=<pass> \
  -rpcport=9332 -port=9333 \
  -rpcallowip=127.0.0.1 \
  -walletcrosschain \
  -daemon
```

DNS seeds are embedded in the binary — your node will automatically discover peers on first start.

For a local development environment, use **regtest** mode instead (see [Running a Local Test Node](#running-a-local-test-node) in CONTRIBUTING.md).

---

## RPC API Reference

### Standard Bitcoin RPC

SNTI supports all standard Bitcoin Core RPC commands. See [Bitcoin RPC documentation](https://developer.bitcoin.org/reference/rpc/).

### SNTI-Specific RPC Commands

#### `getnewxmssaddress (label)`

Generate a new XMSS key pair and return the corresponding address.

**Parameters:**
- `label` (string, optional): Human-readable label for the key

**Returns:**
```json
{
  "address": "snti1...",
  "pubkey": "hex...",
  "leaf_index": 0,
  "remaining": 1024
}
```

**Example:**
```bash
./src/bitcoin-cli -datadir=/root/.bitcoin \
  -rpcuser=<user> -rpcpassword=<pass> -rpcport=9332 \
  -rpcwallet=<wallet> getnewxmssaddress "my_first_key"
```

---

#### `listxmsskeys`

List all XMSS keys in the wallet.

**Returns:**
```json
[
  {
    "label": "my_first_key",
    "address": "snti1...",
    "pubkey": "hex...",
    "leaf_index": 0,
    "remaining": 1024,
    "valid": true
  }
]
```

---

#### `getxmssaddressinfo (address)`

Get information about an XMSS address.

**Parameters:**
- `address` (string, required): XMSS address to query

**Returns:**
```json
{
  "address": "snti1...",
  "pubkey": "hex...",
  "is_mine": true,
  "leaf_index": 0,
  "remaining": 1024
}
```

---

#### `importxmsskey (seckey, pubkey, label)`

Import an existing XMSS key pair into the wallet.

**Parameters:**
- `seckey` (string, required): Serialized XMSS secret key, hex-encoded
- `pubkey` (string, required): 64-byte XMSS public key, hex-encoded
- `label` (string, optional): Human-readable label for the key

---

#### `exportxmsskey (address)`

Export an XMSS private key from the wallet for backup.

**WARNING**: anyone with the secret key can spend funds from this address.

**Parameters:**
- `address` (string, required): The XMSS address to export the key for

**Returns:**
```json
{
  "pubkey": "hex...",
  "seckey": "hex...",
  "address": "snti1...",
  "leaf_index": 0,
  "remaining": 1024
}
```

---

#### `sendfromxmssaddress (address, amount, ...)`

Send SNTI from an XMSS address. The sending address is swept fully and retired after signing (one-time-address model — see Key Lifecycle below).

**Parameters:**
- `address` (string, required): Destination address
- `amount` (number, required): Amount in SNTI

---

#### `getmininginfo`

Returns mining information including PoUW status.

**Returns:**
```json
{
  "blocks": 2,
  "currentblockweight": 4000,
  "currentblocktx": 0,
  "difficulty": 4.656542373906925e-10,
  "networkhashps": 3.29e-05,
  "pooledtx": 0,
  "chain": "test",
  "warnings": "",
  "pouw_enabled": true
}
```

---

## XMSS Wallet Guide

### Understanding XMSS

XMSS (eXtended Merkle Signature Scheme) is a **stateful** post-quantum signature scheme. Key properties:

- **One-time signatures**: Each key pair can produce exactly 1,024 signatures (indices 0–1022 safe; index 1023 has a known reference library bug — see Architecture §Known Bugs)
- **Index tracking**: Each signature advances an internal counter
- **Anti-reuse**: Reusing a key index leaks the private key
- **Large signatures**: ~2,500 bytes per signature

### Address Lifecycle (Swept One-Time Model)

SNTI uses a **swept one-time-address** model for XMSS spending addresses:

```
Generate Key → Index 0 (only index ever used for spending)
  ↓
Receive funds
  ↓
sendfromxmssaddress → signs at index 0, sweeps ALL UTXOs at address
  ↓
Key retired (persisted before broadcast, wallet refuses second use)
  ↓
Generate new key for next use
```

This design:
- Avoids any HD-derivation/CPubKey incompatibility
- Structurally prevents ever reaching the index-1023 library bug
- Eliminates crash-safe index-persistence complexity

> **Note**: This is separate from PoUW mining keys. Mining generates a fresh XMSS key per block (search phase — see Mining Guide) and discards it.

### XMSS in PoUW Mining vs. Transaction Signing

XMSS is used in **two distinct, unrelated contexts**:

| Context | What XMSS does | Key lifecycle |
|---------|----------------|---------------|
| **PoUW Mining** | Tree root hash = proof of work | Fresh key per block, discarded |
| **TX Signing** | Signs SNTI spending transactions | One-time address, swept and retired |

### Wallet Backup

```bash
# Backup wallet
./src/bitcoin-cli -testnet [...] backupwallet "/path/to/backup.dat"
```

---

## Mining Guide

### How PoUW v2 Works

SNTI uses **Proof-of-Useful-Work v2** (PoUW v2): building an XMSS Merkle tree is the proof of work. There is no SHA-256 nonce grinding.

**Mining loop:**
1. Miner picks a random 96-byte SK_SEED (= SK_SEED | SK_PRF | PUB_SEED)
2. Builds full XMSS-SHA2_10_256 tree (height 10, 1024 leaves) → ~6 seconds on 4 CPU cores
3. Extracts `xmssRoot` (32-byte Merkle root)
4. Checks: `xmssRoot < target` — if not, pick new SK_SEED and repeat
5. When valid: sign the block hash with the XMSS key at leaf index 0
6. Embed auth_path + WOTS+ signature in coinbase via `PoUWv2Proof::Serialize()` (2660 bytes)
7. Broadcast block

**Key point**: `nNonce` in the block header is **always 0** in PoUW v2. The "nonce" is the SK_SEED stored in the PoUW proof.

**Difficulty**: EMA per-block adjustment (alpha=0.1), target ~60 second blocks.
**powLimit (testnet)**: `7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` (max — easy mining)
**powLimit (mainnet)**: `01a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a4` (1-of-156 trees valid)

### Solo Mining (RPC — mainnet)

```bash
CLI="./src/bitcoin-cli -datadir=/root/.bitcoin \
  -rpcuser=<user> -rpcpassword=<pass> -rpcport=9332"

# Load wallet
$CLI loadwallet <wallet_name>

# Get a new XMSS address
ADDR=$($CLI -rpcwallet=<wallet_name> getnewxmssaddress | python3 -c "import sys,json; print(json.load(sys.stdin)['address'])")

# Mine 1 block (timeout long — XMSS tree build takes ~2–6s/attempt)
$CLI -rpcclienttimeout=300 generatetoaddress 1 "$ADDR"
```

### Pool Mining (Stratum — Phase 3, not yet available)

> **Status**: Pool mining via stratum is planned for Phase 3 of the roadmap. It is not yet deployed on mainnet.
>
> The planned approach is a hybrid stratum server that accepts standard SHA-256 share submissions from cpuminer-compatible clients and internally triggers `generatetoaddress` on the node after a qualifying share. Miners do not need to understand XMSS directly.
>
> Track progress: [GitHub Issues — pool mining](https://github.com/assentian-network/snti/issues)

### Key Design Decision: One-Shot Mining Keys

Each mined block generates a fresh XMSS key and uses only index 0 of its 1024-signature capacity. This is deliberate:

- No durable crash-safe index-state persistence needed
- No risk of index reuse across restarts
- Tradeoff: ~6s keygen overhead per block attempt, 1023 signatures wasted per key

This will be revisited if block time needs to drop below ~5 seconds.

---

## Testnet Guide

### Mainnet Parameters

| Parameter | Value |
|-----------|-------|
| P2P Port | 9333 |
| RPC Port | 9332 |
| Address Prefix | `snti1` (bech32m) |
| Block Time Target | 60 seconds |
| powLimit | `01a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a4` |
| Block Reward | 50 SNTI |
| Halving Interval | 2,100,000 blocks (~4 years) |
| Max Supply | 210,000,000 SNTI |

### Testnet Parameters

| Parameter | Value |
|-----------|-------|
| P2P Port | 19333 |
| RPC Port | 18332 |
| Address Prefix | `tsnti1` (bech32m) |
| Block Time Target | 60 seconds |
| powLimit | `7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` (max) |
| Block Reward | 50 SNTI |

### Mainnet Genesis Block

| Field | Value |
|-------|-------|
| nTime | 1750931612 (26 Jun 2026 11:53:32 UTC) |
| nBits | 0x01a41a41 |
| nNonce | 0 (PoUW v2 — always 0) |
| Hash | `b4a26aef52f6f5038815f26917cb0ea1fd3b3b13fbc7cfb5c541088a6943a5ba` |

### Live Infrastructure (Mainnet — 30 Jun 2026)

| Service | Host | Port |
|---------|------|------|
| assentian-seed.service | Main VPS (Indonesia) | P2P:9333, RPC:9332 |
| assentian-seed.service | Seed KC (USA) | P2P:9333, RPC:9332 |
| assentian-seed.service | Seed SG (Singapore) | P2P:9333, RPC:9332 |
| Explorer + Web Wallet | https://assentian.network | HTTPS:443 |
| DNS Seeds | seed.assentian.network, seed2.assentian.network, seed3.assentian.network | — |

---

## Architecture

### Block Header Structure (PoUW v2)

```
CBlockHeader
├── nVersion       (int32)   — block version
├── hashPrevBlock  (uint256) — previous block hash
├── hashMerkleRoot (uint256) — Merkle root of transactions
├── nTime          (uint32)  — Unix timestamp
├── nBits          (uint32)  — compact difficulty target
├── nNonce         (uint32)  — ALWAYS 0 in PoUW v2 (legacy field retained for serialization)
├── xmssRoot       (uint256) — XMSS tree Merkle root — THIS IS THE PROOF OF WORK
├── nLeafIndex     (uint32)  — which leaf signed this block (consensus: sequential, no reuse)
└── commitmentsRoot(uint256) — Merkle root of failed-SK_SEED commitments
```

### PoUW v2 Proof Structure (in coinbase)

Serialized `PoUWv2Proof` (2660 bytes total), identified by magic `PW2\x02`:

```
[4 bytes magic: 'P','W','2',0x02]
[96 bytes seed: SK_SEED | SK_PRF | PUB_SEED]
[64 bytes xmss_pk: root(32) | PUB_SEED(32)]
[320 bytes auth_path: 10 × 32-byte node hashes]
[2144 bytes wots_sig: WOTS+ signature]
[32 bytes r: signature randomness]
```

### Block Layout

```
Block
├── Block Header (PoUW v2 — see above)
└── Block Data
    ├── Coinbase Transaction
    │   ├── Input: height + extra_nonce
    │   ├── Output 1: block reward (50 SNTI)
    │   └── Output 2: OP_RETURN <PoUWv2Proof 2660 bytes>
    └── Transactions [...]
```

### Transaction Flow (XMSS spending)

P2XMSS and P2XMSSHASH are the two XMSS-native output types:

```
P2XMSS:     <64-byte-pubkey> OP_XMSS_CHECKSIG
P2XMSSHASH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_XMSS_CHECKSIG
```

Signature is split into 5 × 500-byte chunks (each < 520-byte consensus push limit):

```
scriptSig (P2XMSS, 2515 bytes):
  <chunk1-500> <chunk2-500> <chunk3-500> <chunk4-500> <chunk5-500>

scriptSig (P2XMSSHASH, 2580 bytes):
  <chunk1-500> <chunk2-500> <chunk3-500> <chunk4-500> <chunk5-500> <pubkey-64>
```

Policy exception: `MAX_STANDARD_SCRIPTSIG_SIZE_XMSS = 3000` (type-gated, only for P2XMSS/P2XMSSHASH prevouts; all other inputs keep the 1650-byte cap).

### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| PoUWv2Proof | src/pouw_v2.h | PoUW v2 data structure, CheckPoUWv2(), CalcNextTargetEMA() |
| CBlockHeader | src/primitives/block.h | Block header with xmssRoot, nLeafIndex, commitmentsRoot |
| CheckPoUWv2 | src/validation.cpp | Block PoUW v2 verification |
| GenerateBlock / XMSS search | src/rpc/mining.cpp | PoUW v2 mining loop (SK_SEED search) |
| CalcNextTargetEMA | src/pow.cpp | EMA per-block difficulty adjustment |
| CXMSSSigner | wallet/xmss_signer.cpp | XMSS signing provider (TX signing) |
| CXMSSKeyStore | wallet/xmss_keystore.cpp | Key persistence |
| OP_XMSS_CHECKSIG | script/interpreter.cpp | Script verification (5-chunk reassembly) |
| sendfromxmssaddress | wallet/rpc/xmss.cpp | XMSS sweep-spend RPC |
| stratum_server.py | stratum_server.py | PoUW v2 hybrid stratum server |

### XMSS Library Parameters

- OID: `0x00000001` (XMSS-SHA2_10_256)
- Tree height: 10
- Leaves: 1024
- n (hash bytes): 32
- WOTS+ sig bytes: 2144
- Auth path bytes: 320 (10 × 32)
- PK bytes: 64 (root || PUB_SEED)
- SK_SEED bytes: 96 (SK_SEED || SK_PRF || PUB_SEED)
- Signature bytes: 2500 (index_bytes:4 + R:32 + WOTS_sig:2144 + auth_path:320)

### EMA Difficulty Adjustment

Per-block EMA with alpha=0.1:

```
new_target = old_target × (900×T + 100×A) / (1000×T)

where T = 60s (target spacing), A = actual spacing (clamped to [T/4, T×4])
```

---

## Active Issues (Jun 25 2026)

### ✅ RESOLVED — WOTS+ verification in CheckPoUWv2() (Jun 25 2026)

WOTS+ verification is fully active. `CheckPoUWv2()` calls `xmss_sign_open()` on every block and all blocks are confirmed passing (`CheckPoUWv2 result=1` in node logs). `auth_path` is non-zero (populated correctly by `xmss_sign()` after `xmssmt_core_seed_keypair()`).

The BDS state issue documented in the Jun 24 handoff note was resolved by commit `5409c3f` (use `xmss_keypair()` flow to ensure BDS state is initialized before signing).

### 🔴 Stratum: no native PoUW v2 protocol

Stratum uses a hybrid approach (SHA-256 share-counting triggers `generatetoaddress`). A full getwork/submitblock flow exposing XMSS signing at RPC level is planned for a future wave.

---

## Historical Engineering Record

The sections below preserve the detailed investigation and resolution history from earlier development phases. This is valuable context for auditors and future contributors.

---

## ✅ RESOLVED — XMSS Wallet Spending (sweep working end-to-end) (20/Jun/2026)

**Status: `sendfromxmssaddress` now produces a transaction that passes full
consensus validation, is accepted to mempool, and confirms on-chain.**

### Root cause (the size-limit decision, finally made)

Chose option (a)-and-(b) hybrid: instead of raising `MAX_SCRIPT_ELEMENT_SIZE` (520-byte consensus push limit) or redesigning P2XMSS as a witness program, the ~2500-byte XMSS-SHA2_10_256 signature is split into **5 chunks of exactly 500 bytes** pushed as separate scriptSig elements. Each chunk is comfortably under the 520-byte consensus limit, so **no consensus-level change was needed at all** — only a narrow, type-gated relay-policy exception (`MAX_STANDARD_SCRIPTSIG_SIZE_XMSS = 3000`, only applied to inputs spending a confirmed `TxoutType::P2XMSS` prevout).

### All fixes required, in the order discovered

1. **`script/interpreter.cpp`** — `OP_XMSS_CHECKSIG`/`OP_XMSS_CHECKSIGVERIFY` handler rewritten to pop `chunk1..chunk5 pubkey` (6 stack items instead of 2), reassemble the signature by concatenating chunks in push order, and validate the reassembled length is exactly 2500 bytes before calling `CheckXMSSSignature`.

2. **`policy/policy.h` / `policy/policy.cpp`** — `IsStandardTx()`'s type-blind `MAX_STANDARD_SCRIPTSIG_SIZE` check raised to `MAX_STANDARD_SCRIPTSIG_SIZE_XMSS` (necessarily coarse, since that function has no `CCoinsViewCache` to check prevout type); `AreInputsStandard()` (which does have prevout access) re-enforces the original tight 1650-byte cap for every input *except* confirmed P2XMSS spends.

3. **`script/sign.cpp`**, two separate bugs in `SignStep()`:
   - The XMSS-detection block's guard condition only checked `whichTypeRet == NONSTANDARD || PUBKEY || PUBKEYHASH`, but `Solver()` already classifies P2XMSS as its own distinct `TxoutType::P2XMSS` (not `NONSTANDARD`) — so the guard never matched, the entire XMSS signing block was unreachable, and execution fell through to the generic `switch (whichTypeRet)`'s unhandled-default `assert(false)`, crashing `bitcoind` with `SIGABRT` on every real signing attempt. Fixed by adding `|| whichTypeRet == TxoutType::P2XMSS` to the guard.
   - Once reachable, the code pushed `<sig><pubkey>` (2 items) into the scriptSig — but for bare P2XMSS the pubkey is already embedded in scriptPubKey and must NOT be pushed again. Fixed to push only the 5 signature chunks.

4. **`wallet/rpc/xmss.cpp`** — UTXO discovery used `AvailableCoinsListUnspent()`, which filters through `IsMine()`. Descriptor wallets have no working `IsMine()` path for P2XMSS, so it never found the funds. Replaced with a manual scan over `pwallet->mapWallet`.

5. **`wallet/spend.cpp`** — `CalculateMaximumSignedInputSize()` and `GetSignedTxinWeight()` both special-cased to return the deterministic XMSS input size/weight directly instead of going through descriptor inference (no XMSS support there).

6. **`wallet/wallet.cpp`** — `CWallet::SignTransaction()` looped over all `ScriptPubKeyMan`s (none know about XMSS) then fell through to a comment promising a `SignTransactionXMSS()` fallback that **was never actually called** (dead code). Fixed by calling the corrected generic `::SignTransaction()` free function with `m_xmss_signer.get()` as the `SigningProvider`.

### Verified end-to-end

`sendfromxmssaddress` from a manually-funded P2XMSS UTXO (regtest) produced a transaction with a 2515-byte scriptSig (5 × (3-byte OP_PUSHDATA2 + 500 bytes)), confirmed via `getmempoolentry` that the node's actual mempool accepted it, and confirmed on-chain after mining one block.

---

## ✅ RESOLVED — P2XMSSHASH (hash-committed XMSS funding) (20/Jun/2026)

**Status: generic `sendtoaddress` to an XMSS address now produces a correct, spendable output.**

### The bug

`sendtoaddress` resolved XMSS addresses to a P2XMSS scriptPubKey with an all-zero 64-byte pubkey placeholder — a provably unspendable output. Root cause: an XMSS address only encodes a 20-byte `HASH160(pubkey)`; `DecodeDestination()` had a stub that discarded the decoded hash and zero-filled the pubkey field instead.

### The fix

Added a proper hash-committed script type — `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_XMSS_CHECKSIG` — so a sender who only has the address (hash) can pay it correctly; the real pubkey is revealed only when spending, exactly like ordinary P2PKH.

Files changed: `script/solver.h`, `script/solver.cpp`, `addresstype.h`, `addresstype.cpp`, `key_io.cpp` (two bugs), `script/sign.cpp`, `wallet/rpc/xmss.cpp`, `wallet/spend.cpp`, `policy/policy.cpp`.

### Verified end-to-end

`sendtoaddress` to an XMSS address now produces a `type: p2xmsshash` output whose `address` field correctly round-trips. `sendfromxmssaddress` correctly spends it: scriptSig is exactly 2580 bytes (chunks + pubkey), accepted to mempool, confirmed on-chain.

---

## ✅ RESOLVED — cleanup pass: P2XMSSHASH gaps (20/Jun/2026)

1. **`sendtoxmssaddress` fallback fixed** — when the wallet doesn't know the recipient's full pubkey, now builds a real `XMSSHash(hash)` → P2XMSSHASH output instead of a fake-P2PKH placeholder.
2. **`CWallet::IsMine()` now recognizes P2XMSSHASH** — previously only checked `TxoutType::P2XMSS`.
3. **`CWallet::SignTransactionXMSS()` removed entirely** — confirmed 100% dead code across two sessions; real XMSS signing goes through the generic `::SignTransaction()` free function.
4. **`-Wswitch` warnings silenced** in four switches (`rpc/rawtransaction.cpp`, `wallet/scriptpubkeyman.cpp`, `script/sign.cpp`) for `P2XMSS`/`P2XMSSHASH` cases.

---

## ✅ RESOLVED — Gap #4: XMSS state reload flakiness (20 Jun 2026) — CLOSED, NOT REPRODUCIBLE

After controlled reproduction testing, `PersistXMSSState()` → `WalletBatch::WriteXmssState()` → `CXMSSSigner::LoadState()` is durable across all tested scenarios including `kill -9`.

The "flakiness" reports were methodology issues:
1. Calling `bitcoin-cli` without full path connected to a stale `bitcoind` process
2. `getnewxmssaddress` returns a JSON object, not a bare address string — capturing without `jq .address` sent the whole JSON blob as a parameter to subsequent RPCs, producing false `ismine: false`

If similar symptoms reappear: check these two causes first before suspecting `xmss_signer.cpp`/`walletdb.cpp`.

---

## ✅ RESOLVED — Gap #3: Key retirement / one-time address enforcement (20 Jun 2026)

Added `retired` field to `XMSSKeyEntry` (`xmss_signer.h`). `SignXMSS()` checks this flag before signing, rejects if `true`; sets `true` after successful sign, inside the same lock as `leaf_index` increment. State format bumped to v2 (`QNT2` magic prefix + 1 byte retired per key entry); `LoadState()` falls back to v1 parsing automatically — old wallet DBs remain readable without wipe.

Verified: generate address → fund → first sign succeeds → second sign to same address rejected (`SignXMSS refused -- key is retired` in debug.log).

---

## Known Bugs

### Reference Library Bug — Final Signature (index 1023) Fails Verification

Discovered 17/Jun/2026. Confirmed empirically:
- Index 0–1022: sign() succeeds, verify() succeeds
- Index 1023: sign() succeeds, verify() **FAILS**
- Index 1024: sign() correctly refuses (code -2)

**Root cause**: in `xmss_core_fast.c`, when the SK reaches max index, the implementation zeroes the SK's index bytes as a "key exhausted" sentinel *before* copying those bytes into the produced signature's index field. The final signature is serialized with a corrupted index, which `xmss_sign_open()` cannot reconcile against the PK's Merkle root.

**Why this doesn't affect SNTI today**: one-shot mining keys never reach index 1023; spending keys use only index 0 and are immediately retired.

**If one-shot design is ever revisited**: fix this in the XMSS library layer first — either reorder the zero-out to happen after the signature index bytes are committed to output, or treat 1023 effective signatures per key as the safe practical maximum.
