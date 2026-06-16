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

### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| CXMSSSigner | wallet/xmss_signer.cpp | XMSS signing provider |
| CXMSSKeyStore | wallet/xmss_keystore.cpp | Key persistence |
| CXMSSKey | xmss_bridge.cpp | C XMSS wrapper |
| CheckPoUW | validation.cpp | Block PoUW verification |
| GenerateBlock | rpc/mining.cpp | PoUW mining loop |
| OP_XMSS_CHECKSIG | script/interpreter.cpp | Script verification |
