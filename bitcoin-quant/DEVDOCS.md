# QNT Developer Documentation

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
git clone https://github.com/asepganzu-svg/bitcoin-quant.git
cd bitcoin-quant/bitcoin-quant

# Generate configure script
./autogen.sh

# Configure (disable GUI and benchmarks for faster build)
./configure --disable-bench --disable-gui --without-miniupnpc \
  --disable-zmq --without-natpmp

# Build
make -j$(nproc)

# Run tests (optional)
make check
```

### Build Output

| Binary | Path | Description |
|--------|------|-------------|
| bitcoind | src/bitcoind | Main daemon |
| bitcoin-cli | src/bitcoin-cli | RPC client |
| bitcoin-wallet | src/bitcoin-wallet | Wallet management |
| bitcoin-tx | src/bitcoin-tx | Transaction builder |

---

## RPC API Reference

### Standard Bitcoin RPC

QNT supports all standard Bitcoin Core RPC commands. See [Bitcoin RPC documentation](https://developer.bitcoin.org/reference/rpc/).

### QNT-Specific RPC Commands

#### `getnewxmssaddress (label)`

Generate a new XMSS key pair and return the corresponding address.

**Parameters:**
- `label` (string, optional): Human-readable label for the key

**Returns:**
```json
{
  "address": "q...",
  "pubkey": "hex...",
  "leaf_index": 0,
  "remaining": 1024
}
```

**Example:**
```bash
bitcoin-cli -regtest getnewxmssaddress "my_first_key"
```

---

#### `listxmsskeys`

List all XMSS keys in the wallet.

**Returns:**
```json
[
  {
    "label": "my_first_key",
    "address": "q...",
    "pubkey": "hex...",
    "leaf_index": 3,
    "remaining": 1021,
    "valid": true
  }
]
```

**Example:**
```bash
bitcoin-cli -regtest listxmsskeys
```

---

#### `getxmssaddressinfo (address)`

Get information about an XMSS address.

**Parameters:**
- `address` (string, required): XMSS address to query

**Returns:**
```json
{
  "address": "q...",
  "pubkey": "hex...",
  "is_mine": true,
  "leaf_index": 3,
  "remaining": 1021
}
```

---


#### `importxmsskey (seckey, pubkey, label)`

Import an existing XMSS key pair into the wallet.

**Parameters:**
- `seckey` (string, required): Serialized XMSS secret key, hex-encoded
- `pubkey` (string, required): 64-byte XMSS public key, hex-encoded
- `label` (string, optional): Human-readable label for the key

**Example:**
```bash
bitcoin-cli -testnet importxmsskey "<seckey-hex>" "<64-byte-pubkey-hex>" "restored_key"
```

---

#### `exportxmsskey (address)`

Export an XMSS private key from the wallet for backup. Fixed 16/Jun/2026 —
this command previously returned "Method not found" because it was
implemented but never registered in the RPC command table, and depended
on `CXMSSSigner::GetSecKeyForPubkey()`, which did not exist. Both issues
are resolved as of this build (see CHANGELOG Phase 6.6).

**WARNING**: anyone with the secret key can spend funds from this address.
Handle the output with the same care as a Bitcoin private key.

**Parameters:**
- `address` (string, required): The XMSS address to export the key for

**Returns:**
```json
{
  "pubkey": "hex...",
  "seckey": "hex...",
  "address": "q...",
  "leaf_index": 0,
  "remaining": 1024
}
```

**Example:**
```bash
bitcoin-cli -testnet exportxmsskey "fmZyeGjBp4Yt4hSEfXi4byNhpfnE7UkMhv"
```

#### `sendtoxmssaddress (address, amount, ...)`

Send QNT to an XMSS address.

**Parameters:**
- `address` (string, required): Destination XMSS address
- `amount` (number, required): Amount in QNT
- `comment` (string, optional): Transaction comment
- `subtractfeefromamount` (boolean, optional): Subtract fee from amount

**Returns:**
```json
{
  "txid": "hex...",
  "fee": 0.00001
}
```

---

#### `getmininginfo`

Returns mining information including PoUW status.

**Returns:**
```json
{
  "blocks": 100,
  "difficulty": 0.00024414,
  "networkhashps": 1234.56,
  "pouw_enabled": true,
  "chain": "regtest"
}
```

---

## XMSS Wallet Guide

### Understanding XMSS

XMSS (eXtended Merkle Signature Scheme) is a **stateful** post-quantum signature scheme. Key properties:

- **One-time signatures**: Each key pair can produce exactly 1,024 signatures
- **Index tracking**: Each signature advances an internal counter
- **Anti-reuse**: Reusing a key index leaks the private key
- **Large signatures**: ~2,500 bytes per signature

### Address Lifecycle

```
Generate Key → Index 0
  ↓
Send TX → Index 1 (old address still receives)
  ↓
Send TX → Index 2
  ↓
... (1024 total)
  ↓
Key Exhausted → Generate new key
```

### Best Practices

1. **Never reuse a sending address** — always generate new change addresses
2. **Monitor remaining signatures** — use `listxmsskeys` to check
3. **Backup wallet regularly** — XMSS state is stored in wallet.dat
4. **Don't share private keys** — each key is unique to your wallet

### Wallet Backup

```bash
# Backup wallet
bitcoin-cli -regtest backupwallet "/path/to/backup.dat"

# Restore wallet
bitcoin-wallet -regtest -wallet=/path/to/backup.dat
```

---

## Mining Guide

### Solo Mining (Regtest)

```bash
# Start regtest node
bitcoind -regtest -daemon

# Create wallet and get address
bitcoin-cli -regtest createwallet "miner"
ADDR=$(bitcoin-cli -regtest getnewaddress)

# Mine 10 blocks
bitcoin-cli -regtest generatetoaddress 10 $ADDR

# Check balance
bitcoin-cli -regtest getbalance
```

### PoUW Mining Process

Each mined block:
1. Generates fresh XMSS key pair (~2-3 seconds, measured)
2. Embeds pubkey in coinbase OP_RETURN
3. Grinds SHA-256 nonce
4. Signs block hash with XMSS
5. Inserts signature into coinbase witness (not scriptSig — avoids the 100-byte push limit)
6. Re-verifies PoW


> **Important — actual key lifecycle differs from the ideal XMSS model.**
> The XMSS-Wallet-Guide section above describes the ideal case: one key signing
> up to 1024 times before rotation. In the current PoUW mining implementation
> (`GenerateBlock()` in `rpc/mining.cpp`), this is NOT what happens. A fresh
> XMSS key is generated and discarded for every single block — only index 0
> of each key's 1024-signature capacity is ever used. This is a deliberate
> simplification: it avoids any risk of state persistence bugs or accidental
> index reuse across node restarts, at the cost of generating a brand-new key
> every ~2-3 seconds (most of a block's mining time) and wasting 1023 of 1024
> available signatures per key. This tradeoff has not yet been revisited as
> of the 16/Jun/2026 testnet validation session — see CHANGELOG Phase 6.5.

### Mining RPC

```bash
# Get mining info
bitcoin-cli -regtest getmininginfo

# Generate blocks (regtest only)
bitcoin-cli -regtest generatetoaddress 100 $ADDR
```

---

## Testnet Guide

### Connecting to Testnet

```bash
# Start testnet node
bitcoind -testnet -daemon

# Check connection
bitcoin-cli -testnet getnetworkinfo

# Get testnet coins from faucet (when available)
# POST /faucet { "address": "your_testnet_address" }
```

### Testnet Parameters

| Parameter | Value |
|-----------|-------|
| Port | 19333 |
| RPC Port | 29332 |
| Address Prefix | m or n |
| Magic Bytes | 0x71545354 ("qTST") |
| Difficulty | Low (easy mining) |

---

## Architecture

### Block Structure

```
Block Header
├── Version
├── Previous Block Hash
├── Merkle Root (includes signed coinbase)
├── Timestamp
├── Bits (difficulty)
└── Nonce

Block Data
├── Coinbase Transaction
│   ├── Input: height + extra_nonce + XMSS_signature
│   ├── Output 1: block reward (P2PKH)
│   └── Output 2: OP_RETURN <64-byte XMSS pubkey>
└── Transactions [...]
```

### Transaction Flow (XMSS)

```
1. CreateTransaction()
   ↓
2. SignTransaction() (ECDSA inputs)
   ↓
3. SignTransactionXMSS() (XMSS inputs)
   ├── Detect 64-byte pubkey + OP_XMSS_CHECKSIG
   ├── Compute sighash
   ├── Sign via CXMSSSigner::SignXMSS()
   └── Build scriptSig: <sig> <pubkey>
   ↓
4. CommitTransaction()
   └── Save XMSS state to wallet DB
```


### Design Decision Record — Key lifecycle (16/Jun/2026)

**Decision**: Keep the one-shot key model (fresh XMSS key generated and
discarded per block) for the testnet/pre-mainnet phase. Key reuse across
the full 1024-signature capacity was considered and explicitly deferred.

**Reasoning**: Reusing an XMSS key across multiple blocks requires durable,
crash-safe persistence of the signing index. If a node crashes after
signing but before flushing the updated index to disk, a restart could
sign again at the same index — which leaks the private key under XMSS's
security model. Building that persistence correctly (atomic writes, fsync
ordering, recovery on corrupt state) is real work with real risk of
getting subtly wrong. The one-shot model has no such failure mode by
construction. The tradeoff (1023 of 1024 signature capacity wasted per
key, ~2-3s of keygen overhead per block) is accepted for now in exchange
for that safety margin.

**Revisit when**: mainnet launch planning begins in earnest, or if block
time needs to drop below ~5 seconds and keygen overhead becomes the
binding constraint.


### Known Reference Library Bug — Final Signature (index 1023) Fails Verification

Discovered 17/Jun/2026 during key-exhaustion audit testing. Confirmed empirically
with a standalone test harness linked directly against the project's compiled
XMSS library (bypassing the bitcoind wrapper entirely):
Index 0–1022:  sign() succeeds, verify() succeeds   — 1023 of 1024 signatures OK

Index 1023:    sign() succeeds, verify() FAILS      — the final signature is broken

Index 1024:    sign() correctly refuses (code -2)   — key properly exhausted

**Root cause**: in the core sign function (`xmss_core_fast.c` / `xmss_commons.c`),
when the secret key's index reaches the maximum valid value, the implementation
zeroes/marks the secret key's index bytes as a "key exhausted" sentinel *before*
copying those same index bytes into the produced signature's index field. The
final, otherwise-legitimate signature is therefore serialized with a corrupted
index, which `xmss_sign_open()` cannot reconcile against the public key's Merkle
root — verification fails even though the signature was produced from a valid,
unused leaf.

**Why this hasn't affected QNT mining**: under the current one-shot key design
(see Design Decision Record above), every block generates a fresh key and signs
exactly once at index 0 — index 1023 is never reached in practice, so this bug
has zero observable effect on PoUW today.

**Why it matters anyway**: if the one-shot key design is ever revisited in favor
of reusing a key across its full 1024-signature capacity, this bug would cause
the 1024th use of every key to silently produce an unverifiable, rejected block.
Any future work in that direction must fix this in the XMSS library layer first
— either by reordering the zero-out to happen after the signature's index bytes
are committed to the output, or by reserving index 1023 as unusable (i.e.,
treating 1023 effective signatures per key as the safe practical maximum).

### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| CXMSSSigner | wallet/xmss_signer.cpp | XMSS signing provider |
| CXMSSKeyStore | wallet/xmss_keystore.cpp | Key persistence |
| CXMSSKey | xmss_bridge.cpp | C XMSS wrapper |
| CheckPoUW | validation.cpp | Block PoUW verification |
| GenerateBlock | rpc/mining.cpp | PoUW mining loop |
| OP_XMSS_CHECKSIG | script/interpreter.cpp | Script verification |

## ⚠️ ACTIVE BLOCKER — XMSS Wallet Spending (as of 18/Jun/2026)

**Status: investigation complete, root cause confirmed, fix NOT yet implemented.**
**This is the single most important section in this document for resuming work.**

### The goal
Make `sendfromxmssaddress` actually work end-to-end: spend funds that were
received at an XMSS address, broadcast successfully, confirm on-chain.

### What was tried and ruled out, in order

**1. Quick fix: bridge CXMSSSigner to LegacyScriptPubKeyMan**
`AddXMSSKeyToKeystore()` was a no-op stub; `getnewxmssaddress` never called
it. Implemented the bridge so generated keys register with
`LegacyScriptPubKeyMan::AddXMSSKey()`. **Result: inert.** The active wallet
is a descriptor wallet (`"descriptors": true`), and `GetLegacyScriptPubKeyMan()`
returns nullptr for descriptor wallets — there is no Legacy SPKM instance to
register anything with. Confirmed by trying to create an explicit legacy
wallet: fails outright, `Compiled without bdb support (required for legacy
wallets)`. **The current binary cannot create a legacy wallet at all.**

**2. Real fix: proper descriptor integration (`xmss(pubkey)` descriptor type)**
Investigated what this would require: a new `DescriptorImpl` subclass,
parser support, wiring into `DescriptorScriptPubKeyMan`. Hit a hard type
incompatibility: the entire `PubkeyProvider → DescriptorImpl → SigningProvider`
pipeline is built around `CPubKey`, which is hard-capped at `SIZE = 65` bytes
and whose `IsValid()`/`IsFullyValid()` checks call into libsecp256k1 to
confirm the bytes are a valid EC point. XMSS's 64-byte raw pubkey (root ||
PUB_SEED) is not EC data and cannot pass through `CPubKey` without either
modifying `CPubKey` itself (used everywhere, very high blast radius) or
building an entirely parallel non-`CPubKey` provider/descriptor/signing
stack. Genuine multi-day-to-multi-week engineering effort, not a patch.

**3. Pivoted to a different design philosophy: "swept one-time address"**
Decision made (see new Design Decision Record below) to lean into XMSS's
stateful nature rather than fight it: each XMSS address is used at most
ONCE for spending (always index 0, never reused), matching the same
philosophy already adopted for PoUW mining keys. This sidesteps the
`CPubKey`/HD-derivation incompatibility entirely (no derivation needed —
just individually tracked one-shot keys) and avoids the broken-last-signature
reference library bug (index 1023) by construction, since index never
advances past 0.

**4. While implementing the manual transaction-builder approach for this
design, found and fixed an unrelated but critical bug:** `CXMSSSigner::SaveState()`
was only called from `CommitTransaction()` — a key generated via
`getnewxmssaddress` lived in memory only until the wallet's first outgoing
transaction. A crash/restart before that point would permanently lose the
private key (and any funds already received at that address), silently.
**Fixed**: extracted `CWallet::PersistXMSSState()`, now called both from
`CommitTransaction()` and immediately after key generation in
`getnewxmssaddress`. **Verified via actual crash test**: generated a key,
sent zero transactions, `SIGKILL`'d the node, restarted, confirmed the key
and `ismine:true` survived. This fix is committed and pushed
(`d61ae76`) — it stands regardless of how the spending design below
ultimately gets resolved.

**5. Investigated exactly what consensus requires to spend a P2XMSS output**,
to design the manual transaction builder correctly:
- `OP_XMSS_CHECKSIG`'s `CheckXMSSSignature()` (interpreter.cpp ~line 1735)
  computes a completely standard `SignatureHash(scriptCode, *txTo, nIn,
  SIGHASH_ALL, amount, sigversion, nullptr)` — i.e. the ordinary
  legacy/BIP143 sighash, nothing custom. Good news: no novel sighash scheme
  needed.
- `CScript::IsWitnessProgram()` is **completely unmodified** from upstream.
  The P2XMSS script (`<64-byte-pubkey-push> OP_XMSS_CHECKSIG`, 66 bytes) is
  far larger than the 42-byte max for witness programs and doesn't start
  with `OP_0`/`OP_1`-`OP_16`. **A P2XMSS output is therefore never treated
  as a witness program by consensus — it can only be spent via legacy
  scriptSig (`SigVersion::BASE`)**, pushing just the signature (the pubkey
  is already embedded in the locking script, so scriptSig only needs `<sig>`,
  similar to bare P2PK).

### THE ACTUAL BLOCKER (found last, and the reason nothing can move forward
### without a deliberate decision)

XMSS signatures are ~2500 bytes. Checked the standardness/relay policy
limits in `policy/policy.h` (confirmed **unmodified** from upstream):
```
MAX_STANDARD_SCRIPTSIG_SIZE        = 1650   bytes  (policy.cpp line ~121)
MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80     bytes  (policy.h line 43)
MAX_STANDARD_P2WSH_SCRIPT_SIZE     = 3600   bytes  (policy.h line 47, fine on its own)
```
**A 2500-byte signature does not fit through either path.** Neither bare
scriptSig (consensus-mandated path per the IsWitnessProgram finding above,
1650-byte policy cap) nor a hypothetical P2WSH-wrapped redesign (80-byte
policy cap on witness stack items, nowhere close) can carry it under
default relay policy. `AcceptToMemoryPool` would reject any transaction
attempting to spend a P2XMSS output before it could ever reach a block —
this would block it from our own node's mempool too, not just P2P relay.

**This is why PoUW mining signatures never hit this wall**: they're carried
in a coinbase `OP_RETURN` output (Phase 6.9's preimage redesign), which is
not subject to scriptSig/witness-stack size policy at all. Spending-side
signatures, going through actual script execution via `OP_XMSS_CHECKSIG`,
have no equivalent escape hatch today.

### What fixing this actually requires (not started — this is the next session's first task)

A deliberate policy decision, most likely one of:
- (a) Raise `MAX_STANDARD_SCRIPTSIG_SIZE` specifically for transactions
  whose input's previous output is a recognized P2XMSS script (narrow,
  type-gated exception rather than a blanket policy change — safer, smaller
  DoS surface), **or**
- (b) Redesign P2XMSS spending to use a witness-based scheme and raise
  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE` (or design a bespoke witness
  program type for XMSS, recognized by a modified `IsWitnessProgram()`,
  so it gets `SigVersion::WITNESS_V0` treatment) — this is more invasive
  (touches consensus-level witness-program recognition) but is more
  consistent with how the project already solved the identical problem
  for mining (move large data out of size-constrained legacy paths into
  a purpose-built carve-out).

Either path has real DoS-surface tradeoffs (larger standard transaction
sizes = more relay bandwidth and validation cost network-wide) that
deserve careful, undistracted thought — explicitly NOT a decision to make
at the tail end of an exhausting session, which is why this was stopped
here rather than pushed through.

### Design Decision Record — Swept One-Time XMSS Address Model (18/Jun/2026)

Decided, not yet implemented:
- Each XMSS address is swept and retired in a single spend — one signature
  (always index 0) authorizes spending the address's *entire* balance
  (all UTXOs at that address) in one transaction. Partial spends from an
  address are not allowed; the wallet must always sweep fully.
- After a sweep, the key is marked permanently retired (persisted
  synchronously, before broadcast) and the wallet must refuse to ever sign
  with it again, regardless of future deposits to that address.
- Change goes to a freshly generated XMSS address automatically (chosen by
  the user this session, for consistency with the project's "everything
  post-quantum" positioning).
- If a single payment exceeds any one address's balance, the wallet may
  automatically combine multiple one-time XMSS addresses' UTXOs into a
  single transaction (chosen by the user this session, for usability) —
  each input still signed independently by its own key, each of those keys
  then independently retired.
- This sidesteps needing any HD-derivation scheme for XMSS (no `CPubKey`
  compatibility needed for key derivation) and structurally avoids ever
  reaching the broken index-1023 reference-library bug (Phase 6.8 finding),
  since no key's index ever advances past 0.
- UTXO discovery approach settled on for the eventual manual transaction
  builder (since `IsMine()`/`listunspent` don't recognize P2XMSS under the
  current descriptor-only wallet backend): scan `pwallet->mapWallet` for
  outputs matching the P2XMSS script pattern with the target pubkey,
  filtered by `GetTxDepthInMainChain() >= 1` (confirmed) and
  `!pwallet->IsSpent(outpoint)`. Final broadcast should reuse
  `pwallet->CommitTransaction()` for recording + relay (already verified
  safe and now correctly persists XMSS state per the Phase 6.11 fix),
  bypassing only `CreateTransaction`'s coin selection and the standard
  ECDSA-oriented signing path — NOT yet implemented, blocked on the policy
  size-limit decision above.

### Concrete next-session starting point
1. Make the policy decision (scriptSig exception vs. witness redesign) —
   read this whole section first, then decide.
2. Implement the chosen policy change in `policy/policy.cpp`/`policy.h`
   (and `script/interpreter.cpp`'s witness-program detection if option (b)).
3. Implement the manual transaction builder for `sendfromxmssaddress`
   per the Design Decision Record above (UTXO discovery via mapWallet scan
   already designed, just needs writing + testing).
4. Test: full round trip — generate address, receive funds, sweep-spend,
   confirm key retired, confirm wallet refuses second use.

## ✅ RESOLVED — XMSS Wallet Spending (sweep working end-to-end) (20/Jun/2026)

**Status: `sendfromxmssaddress` now produces a transaction that passes full
consensus validation, is accepted to mempool, and confirms on-chain.**
**This resolves the blocker documented in the section above.**

### Root cause (the size-limit decision, finally made)

Chose option (a)-and-(b) hybrid from the blocker section above, but neither
literally: instead of raising `MAX_SCRIPT_ELEMENT_SIZE` (520-byte consensus
push limit) or redesigning P2XMSS as a witness program, the ~2500-byte
XMSS-SHA2_10_256 signature is split into **5 chunks of exactly 500 bytes**
(2500 = 5 × 500, divides evenly — no padding/remainder logic needed) pushed
as separate scriptSig elements. Each chunk is comfortably under the 520-byte
consensus limit, so **no consensus-level change was needed at all** — only
a narrow, type-gated relay-policy exception (`MAX_STANDARD_SCRIPTSIG_SIZE_XMSS
= 3000`, only applied to inputs spending a confirmed `TxoutType::P2XMSS`
prevout; the original 1650-byte cap is explicitly re-enforced for every
other input type).

### All fixes required, in the order discovered (each was a separate,
### independent blocker — fixing one only revealed the next)

1. **`script/interpreter.cpp`** — `OP_XMSS_CHECKSIG`/`OP_XMSS_CHECKSIGVERIFY`
   handler rewritten to pop `chunk1..chunk5 pubkey` (6 stack items instead
   of 2), reassemble the signature by concatenating chunks in push order,
   and validate the reassembled length is exactly 2500 bytes before calling
   `CheckXMSSSignature`.

2. **`policy/policy.h` / `policy/policy.cpp`** — `IsStandardTx()`'s
   type-blind `MAX_STANDARD_SCRIPTSIG_SIZE` check raised to
   `MAX_STANDARD_SCRIPTSIG_SIZE_XMSS` (necessarily coarse, since that
   function has no `CCoinsViewCache` to check prevout type); `AreInputsStandard()`
   (which does have prevout access) re-enforces the original tight 1650-byte
   cap for every input *except* confirmed P2XMSS spends.

3. **`script/sign.cpp`**, two separate bugs in `SignStep()`:
   - The XMSS-detection block's guard condition only checked
     `whichTypeRet == NONSTANDARD || PUBKEY || PUBKEYHASH`, but `Solver()`
     already classifies P2XMSS as its own distinct `TxoutType::P2XMSS` (not
     `NONSTANDARD`) — so the guard never matched, the entire XMSS signing
     block was unreachable, and execution fell through to the generic
     `switch (whichTypeRet)`'s unhandled-default `assert(false)`, crashing
     `bitcoind` with `SIGABRT` on every real signing attempt. Fixed by
     adding `|| whichTypeRet == TxoutType::P2XMSS` to the guard.
   - Once reachable, the code pushed `<sig><pubkey>` (2 items) into the
     scriptSig — but for bare P2XMSS the pubkey is already embedded in
     scriptPubKey and must NOT be pushed again (it produces an extra stray
     stack item and corrupts the sig/pubkey positions `OP_XMSS_CHECKSIG`
     reads). Fixed to push only the 5 signature chunks.

4. **`wallet/rpc/xmss.cpp`** — UTXO discovery used
   `AvailableCoinsListUnspent()`, which filters through `IsMine()`. Descriptor
   wallets have no working `IsMine()` path for P2XMSS (the `LegacyScriptPubKeyMan`
   bridge documented as "inert" in the blocker section above), so it never
   found the funds. Replaced with a manual scan over `pwallet->mapWallet`,
   exactly as already designed in the Design Decision Record below the
   original blocker writeup.

5. **`wallet/spend.cpp`**, two separate fee/size-estimation functions that
   both depend on `InferDescriptor()` (no XMSS support, same root cause as
   `IsMine()` above — XMSS has no `CPubKey`-based descriptor representation):
   `CalculateMaximumSignedInputSize()` and `GetSignedTxinWeight()` both
   special-cased to return the deterministic XMSS input size/weight directly
   instead of going through descriptor inference.

6. **`wallet/wallet.cpp`** — `CWallet::SignTransaction()` looped over all
   `ScriptPubKeyMan`s (none know about XMSS) then fell through to a comment
   promising a `SignTransactionXMSS()` fallback that **was never actually
   called** (dead code, zero call sites, confirmed via grep). That dead
   function also independently had both of the `sign.cpp` bugs from #3
   above (un-chunked single push + redundant pubkey push) — if it had been
   wired up as-is it would have produced consensus-invalid transactions.
   Fixed by calling the corrected generic `::SignTransaction()` free
   function (the one fixed in #3) with `m_xmss_signer.get()` as the
   `SigningProvider`, instead of the broken dead function.

### Verified end-to-end

`sendfromxmssaddress` from a manually-funded P2XMSS UTXO (regtest) produced
a transaction with a 2515-byte scriptSig (5 × (3-byte OP_PUSHDATA2 + 500
bytes)), confirmed via `getmempoolentry` that the *node's actual mempool*
accepted it (full consensus + policy validation passed), and confirmed
on-chain after mining one block.

### Known gaps, explicitly NOT fixed this session — next session's starting points

1. **Generic funding bug**: `sendtoaddress` to an XMSS address (decoded via
   the generic `DecodeDestination()`/`GetScriptForDestination()` path, not
   the XMSS-aware logic inside `sendfromxmssaddress` itself) produces a
   scriptPubKey with an all-zero 64-byte pubkey placeholder — the address
   format only encodes a 20-byte hash, and the generic path has no way to
   recover the real pubkey from just that hash. The resulting output is
   provably unspendable. Likely needs the existing-but-unused
   `GetXMSSHashScriptForPubkey()` (P2XMSSHASH, hash-committed form) wired
   into `GetScriptForDestination()` for this case instead of the bare
   pubkey form. Worked around this session via a hand-built raw transaction
   (`build_p2xmss_tx.py`) to isolate-test the spending-side fix.
2. **Swept one-time-address key retirement**: the Design Decision Record's
   "each XMSS address spent exactly once, key retired after" is still
   unimplemented — nothing currently prevents signing with the same key
   twice.
3. **XMSS state reload-on-`loadwallet` flakiness**: observed `ismine: false`
   for a known-good XMSS key immediately after a clean `bitcoind` restart +
   `loadwallet`, despite `CWallet::Create()`'s `LoadState()` call being
   correctly wired into that exact code path. Root cause not yet found —
   suspect either a `WriteXmssState`/`ReadXmssState` DB-key mismatch or the
   state being silently overwritten empty by some other `PersistXMSSState()`
   call. Not blocking (this session's funding/spending used a freshly
   generated key each time to route around it), but needs investigation
   before this is safe for any real, persistent-across-restarts use.
4. **`CWallet::SignTransactionXMSS()` is now confirmed 100% dead code** —
   zero call sites anywhere in the codebase. Safe to delete entirely in a
   cleanup pass; keeping it around risks a future contributor wiring it
   back in by mistake (as happened mid-session here) and reintroducing the
   un-chunked/redundant-pubkey bugs it contains.
5. Compiler warnings `enumeration value 'P2XMSS' not handled in switch`
   (multiple sites: `rpc/rawtransaction.cpp`, `script/sign.cpp`'s main
   switch) and `SigningProvider::GetXMSSPubKey/HaveXMSSKey was hidden`
   (virtual function shadowing) are pre-existing, harmless for current
   functionality, but worth a cleanup pass.

## ✅ RESOLVED — XMSS Wallet Spending (sweep working end-to-end) (20/Jun/2026)

**Status: `sendfromxmssaddress` now produces a transaction that passes full
consensus validation, is accepted to mempool, and confirms on-chain.**
**This resolves the blocker documented in the section above.**

### Root cause (the size-limit decision, finally made)

Chose option (a)-and-(b) hybrid from the blocker section above, but neither
literally: instead of raising `MAX_SCRIPT_ELEMENT_SIZE` (520-byte consensus
push limit) or redesigning P2XMSS as a witness program, the ~2500-byte
XMSS-SHA2_10_256 signature is split into **5 chunks of exactly 500 bytes**
(2500 = 5 × 500, divides evenly — no padding/remainder logic needed) pushed
as separate scriptSig elements. Each chunk is comfortably under the 520-byte
consensus limit, so **no consensus-level change was needed at all** — only
a narrow, type-gated relay-policy exception (`MAX_STANDARD_SCRIPTSIG_SIZE_XMSS
= 3000`, only applied to inputs spending a confirmed `TxoutType::P2XMSS`
prevout; the original 1650-byte cap is explicitly re-enforced for every
other input type).

### All fixes required, in the order discovered (each was a separate,
### independent blocker — fixing one only revealed the next)

1. **`script/interpreter.cpp`** — `OP_XMSS_CHECKSIG`/`OP_XMSS_CHECKSIGVERIFY`
   handler rewritten to pop `chunk1..chunk5 pubkey` (6 stack items instead
   of 2), reassemble the signature by concatenating chunks in push order,
   and validate the reassembled length is exactly 2500 bytes before calling
   `CheckXMSSSignature`.

2. **`policy/policy.h` / `policy/policy.cpp`** — `IsStandardTx()`'s
   type-blind `MAX_STANDARD_SCRIPTSIG_SIZE` check raised to
   `MAX_STANDARD_SCRIPTSIG_SIZE_XMSS` (necessarily coarse, since that
   function has no `CCoinsViewCache` to check prevout type); `AreInputsStandard()`
   (which does have prevout access) re-enforces the original tight 1650-byte
   cap for every input *except* confirmed P2XMSS spends.

3. **`script/sign.cpp`**, two separate bugs in `SignStep()`:
   - The XMSS-detection block's guard condition only checked
     `whichTypeRet == NONSTANDARD || PUBKEY || PUBKEYHASH`, but `Solver()`
     already classifies P2XMSS as its own distinct `TxoutType::P2XMSS` (not
     `NONSTANDARD`) — so the guard never matched, the entire XMSS signing
     block was unreachable, and execution fell through to the generic
     `switch (whichTypeRet)`'s unhandled-default `assert(false)`, crashing
     `bitcoind` with `SIGABRT` on every real signing attempt. Fixed by
     adding `|| whichTypeRet == TxoutType::P2XMSS` to the guard.
   - Once reachable, the code pushed `<sig><pubkey>` (2 items) into the
     scriptSig — but for bare P2XMSS the pubkey is already embedded in
     scriptPubKey and must NOT be pushed again (it produces an extra stray
     stack item and corrupts the sig/pubkey positions `OP_XMSS_CHECKSIG`
     reads). Fixed to push only the 5 signature chunks.

4. **`wallet/rpc/xmss.cpp`** — UTXO discovery used
   `AvailableCoinsListUnspent()`, which filters through `IsMine()`. Descriptor
   wallets have no working `IsMine()` path for P2XMSS (the `LegacyScriptPubKeyMan`
   bridge documented as "inert" in the blocker section above), so it never
   found the funds. Replaced with a manual scan over `pwallet->mapWallet`,
   exactly as already designed in the Design Decision Record below the
   original blocker writeup.

5. **`wallet/spend.cpp`**, two separate fee/size-estimation functions that
   both depend on `InferDescriptor()` (no XMSS support, same root cause as
   `IsMine()` above — XMSS has no `CPubKey`-based descriptor representation):
   `CalculateMaximumSignedInputSize()` and `GetSignedTxinWeight()` both
   special-cased to return the deterministic XMSS input size/weight directly
   instead of going through descriptor inference.

6. **`wallet/wallet.cpp`** — `CWallet::SignTransaction()` looped over all
   `ScriptPubKeyMan`s (none know about XMSS) then fell through to a comment
   promising a `SignTransactionXMSS()` fallback that **was never actually
   called** (dead code, zero call sites, confirmed via grep). That dead
   function also independently had both of the `sign.cpp` bugs from #3
   above (un-chunked single push + redundant pubkey push) — if it had been
   wired up as-is it would have produced consensus-invalid transactions.
   Fixed by calling the corrected generic `::SignTransaction()` free
   function (the one fixed in #3) with `m_xmss_signer.get()` as the
   `SigningProvider`, instead of the broken dead function.

### Verified end-to-end

`sendfromxmssaddress` from a manually-funded P2XMSS UTXO (regtest) produced
a transaction with a 2515-byte scriptSig (5 × (3-byte OP_PUSHDATA2 + 500
bytes)), confirmed via `getmempoolentry` that the *node's actual mempool*
accepted it (full consensus + policy validation passed), and confirmed
on-chain after mining one block.

### Known gaps, explicitly NOT fixed this session — next session's starting points

1. **Generic funding bug**: `sendtoaddress` to an XMSS address (decoded via
   the generic `DecodeDestination()`/`GetScriptForDestination()` path, not
   the XMSS-aware logic inside `sendfromxmssaddress` itself) produces a
   scriptPubKey with an all-zero 64-byte pubkey placeholder — the address
   format only encodes a 20-byte hash, and the generic path has no way to
   recover the real pubkey from just that hash. The resulting output is
   provably unspendable. Likely needs the existing-but-unused
   `GetXMSSHashScriptForPubkey()` (P2XMSSHASH, hash-committed form) wired
   into `GetScriptForDestination()` for this case instead of the bare
   pubkey form. Worked around this session via a hand-built raw transaction
   (`build_p2xmss_tx.py`) to isolate-test the spending-side fix.
2. **Swept one-time-address key retirement**: the Design Decision Record's
   "each XMSS address spent exactly once, key retired after" is still
   unimplemented — nothing currently prevents signing with the same key
   twice.
3. **XMSS state reload-on-`loadwallet` flakiness**: observed `ismine: false`
   for a known-good XMSS key immediately after a clean `bitcoind` restart +
   `loadwallet`, despite `CWallet::Create()`'s `LoadState()` call being
   correctly wired into that exact code path. Root cause not yet found —
   suspect either a `WriteXmssState`/`ReadXmssState` DB-key mismatch or the
   state being silently overwritten empty by some other `PersistXMSSState()`
   call. Not blocking (this session's funding/spending used a freshly
   generated key each time to route around it), but needs investigation
   before this is safe for any real, persistent-across-restarts use.
4. **`CWallet::SignTransactionXMSS()` is now confirmed 100% dead code** —
   zero call sites anywhere in the codebase. Safe to delete entirely in a
   cleanup pass; keeping it around risks a future contributor wiring it
   back in by mistake (as happened mid-session here) and reintroducing the
   un-chunked/redundant-pubkey bugs it contains.
5. Compiler warnings `enumeration value 'P2XMSS' not handled in switch`
   (multiple sites: `rpc/rawtransaction.cpp`, `script/sign.cpp`'s main
   switch) and `SigningProvider::GetXMSSPubKey/HaveXMSSKey was hidden`
   (virtual function shadowing) are pre-existing, harmless for current
   functionality, but worth a cleanup pass.

## ✅ RESOLVED — P2XMSSHASH (hash-committed XMSS funding) (20/Jun/2026)

**Status: generic `sendtoaddress` to an XMSS address now produces a correct,
spendable output. Full round trip (fund via generic RPC, spend via
`sendfromxmssaddress`) verified end-to-end on regtest.**

### The bug

`sendtoaddress` (and any other generic RPC building an output from an
address string) resolved XMSS addresses to a P2XMSS scriptPubKey with an
all-zero 64-byte pubkey placeholder -- a provably unspendable output. Root
cause: an XMSS address only ever encodes a 20-byte `HASH160(pubkey)` (the
sender of an arbitrary payment can't know the recipient's real pubkey up
front -- this is architecturally unavoidable, same situation as P2PKH).
`DecodeDestination()` had a stub `XMSSHash(const uint160&)` constructor
that literally discarded the decoded hash and zero-filled the pubkey field
instead (comment: "from address hash - store zeros, full pubkey needed").
`GetScriptForDestination()` then always built the bare P2XMSS form
(`<pubkey> OP_XMSS_CHECKSIG`) from that zeroed pubkey.

### The fix: real P2XMSSHASH support (the XMSS analogue of P2PKH)

Added a proper hash-committed script type --
`OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_XMSS_CHECKSIG` -- so a sender
who only has the address (hash) can pay it correctly; the real pubkey is
revealed only when spending, exactly like ordinary P2PKH/P2WPKH.

1. **`script/solver.h`** -- new `TxoutType::P2XMSSHASH`.
2. **`script/solver.cpp`** -- pattern-match the new script form; **also**
   add the missing `case` to `GetTxnOutputType()` (forgotten on the first
   pass -- caused an `assert(false)`/SIGABRT crash on any verbose RPC call
   that decoded a P2XMSSHASH scriptPubKey, e.g. `gettransaction true true`).
3. **`addresstype.h`** -- `XMSSHash` redesigned to hold *either* a known
   full pubkey *or* just a hash (`HasFullPubKey()` flag), instead of always
   forcing a (possibly zeroed) pubkey.
4. **`addresstype.cpp`** -- `ExtractDestination()` gets a `P2XMSSHASH` case;
   `CScriptVisitor`'s XMSS handler branches on `HasFullPubKey()` to build
   bare P2XMSS (pubkey known) or P2XMSSHASH (hash only).
5. **`key_io.cpp`**, two separate bugs:
   - `DecodeDestination()`: fixed to actually store the decoded hash
     (`XMSSHash(xmss_hash)`) instead of discarding it.
   - `DestinationEncoder` (the *other* direction, hash/destination back to
     a display string): was unconditionally calling
     `XMSSAddr::Encode(xmss.GetPubKeyVec(), ...)`, which re-derives
     `HASH160` from `GetPubKeyVec()` -- all-zeros in hash-only mode --
     silently producing the *wrong* address in any RPC output that displays
     an `"address"` field for a P2XMSSHASH script (e.g.
     `gettransaction`/`decoderawtransaction`). Fixed to encode directly
     from `xmss.GetHash()` when no full pubkey is known, bypassing
     `XMSSAddr::Encode()`'s pubkey-hashing path entirely for that case.
6. **`script/sign.cpp`** -- `SignStep`'s XMSS block extended to handle
   P2XMSSHASH: look up the real pubkey via `provider.GetXMSSPubKey()`
   (confirmed this uses the *same* `HASH160(pubkey)` scheme as
   `XMSSAddr::Hash()` -- both go through `CHash160`, so the lookup keys
   line up), then push the pubkey *in addition to* the 5 signature chunks
   (unlike bare P2XMSS, where the pubkey is already embedded in
   scriptPubKey and must NOT be pushed again).
7. **`wallet/rpc/xmss.cpp`** -- UTXO discovery's manual `mapWallet` scan
   extended to also match `TxoutType::P2XMSSHASH` outputs.
8. **`wallet/spend.cpp`** -- both fee/size-estimation special-cases
   (`CalculateMaximumSignedInputSize`, `GetSignedTxinWeight`) extended:
   P2XMSSHASH scriptSig is 2580 bytes (2515 chunked-signature bytes + 65
   bytes for the extra pubkey push), vs 2515 for bare P2XMSS.
9. **`policy/policy.cpp`** -- `AreInputsStandard`'s type-gated scriptSig
   size exception extended to cover P2XMSSHASH too (same
   `MAX_STANDARD_SCRIPTSIG_SIZE_XMSS` cap; 2580 bytes still comfortably
   fits under the 3000-byte allowance).

One more compile-time-only fix along the way: `CKeyID keyid(uint160(...))`
in `sign.cpp` is a classic C++ "most vexing parse" -- parsed as a function
declaration, not a variable. Fixed with brace-init:
`CKeyID keyid{uint160(...)};`.

### Verified end-to-end

`sendtoaddress` to an XMSS address now produces a `type: p2xmsshash` output
whose `address` field correctly round-trips back to the original address
string. `sendfromxmssaddress` correctly spends it: scriptSig is exactly
2580 bytes (chunks + pubkey), accepted to mempool, confirmed on-chain.

### Known gaps / cleanup for next session

1. **`sendtoxmssaddress` (the custom RPC, distinct from generic
   `sendtoaddress`) is now obsolete and arguably actively misleading**: per
   its own header comment, it's a "v1" stopgap that creates a **plain
   P2PKH** output to the XMSS address hash (not a real XMSS-spendable
   output at all) "until `CTxDestination` is extended to support XMSS
   destinations natively" -- which is exactly what this session did. This
   RPC should probably be removed (or rewritten as a thin wrapper around
   the now-correct generic `sendtoaddress` path) so users don't
   accidentally use the fake-P2PKH stopgap instead of real XMSS funding.
2. **`CWallet::IsMine(const CScript&)`'s QNT special-case only checks
   `TxoutType::P2XMSS`, not `P2XMSSHASH`.** This means `getxmssaddressinfo`
   and other `IsMine()`-dependent paths may not recognize P2XMSSHASH funds
   as belonging to the wallet, even though `sendfromxmssaddress`'s
   independent manual `mapWallet` scan (which doesn't use `IsMine()`) can
   still find and spend them correctly, as verified this session. Worth
   auditing whether any *other* `IsMine()`-dependent feature (balance
   totals, `listunspent`, etc.) needs the same P2XMSSHASH awareness.
3. Carried over from the previous session, still open: swept
   one-time-address key retirement not implemented; XMSS state
   reload-on-`loadwallet` flakiness; `CWallet::SignTransactionXMSS()` still
   100% dead code (now confirmed dead across *two* sessions -- safe to
   delete); cosmetic `-Wswitch` warnings for unhandled `P2XMSS`/`P2XMSSHASH`
   in switches that are provably unreachable for those types (e.g. the
   lower generic switch in `sign.cpp`'s `SignStep`, `IsMineInner` in
   `scriptpubkeyman.cpp`, `rpc/rawtransaction.cpp`).
