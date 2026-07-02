# Assentian-PQE (SNTI)
## The First Mineable Post-Quantum Cryptocurrency
### Whitepaper v1.1 | June 2026

---

> *"The question is not whether quantum computers will break existing cryptography. The question is whether the world will be ready when they do."*
> — NIST Post-Quantum Cryptography Team, 2024

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Investment Thesis](#2-investment-thesis)
3. [The Quantum Threat](#3-the-quantum-threat)
4. [Why XMSS](#4-why-xmss)
5. [Competitive Landscape](#5-competitive-landscape)
6. [Architecture](#6-architecture)
7. [Proof-of-Useful-Work](#7-proof-of-useful-work)
8. [Security Model](#8-security-model)
9. [Tokenomics](#9-tokenomics)
10. [Roadmap](#10-roadmap)
11. [Technical Specifications](#11-technical-specifications)
12. [Blockchain Scalability & The XMSS Size Trade-off](#12-blockchain-scalability--the-xmss-size-trade-off)
13. [Risk Analysis](#13-risk-analysis)
14. [Team & Governance](#14-team--governance)
15. [Conclusion](#15-conclusion)

---

## 1. Executive Summary

Assentian-PQE (SNTI) is the **world's first mineable post-quantum cryptocurrency** — a fully operational blockchain that replaces classical ECDSA signatures with XMSS (eXtended Merkle Signature Scheme), the signature standard mandated by NIST SP 800-208.

Unlike theoretical proposals or migration promises, Assentian-PQE is **already running**:

- ✅ Mainnet genesis block mined — June 26, 2026 (hash: `b4a26aef...`)
- ✅ Mainnet live — 1170+ blocks, 3-node network (Indonesia + USA + Singapore)
- ✅ DNS seed live — seed/seed2/seed3.assentian.network
- ✅ CPU mining operational, solo mining via RPC
- ✅ Block explorer live at assentian.network/explorer/
- ✅ Web wallet live at assentian.network/wallet/
- ✅ Send/receive SNTI verified end-to-end
- ✅ NIST SP 800-208 compliant from genesis

**The quantum era is not coming. For Assentian-PQE, it has already begun.**

| Property | Detail |
|---|---|
| **Ticker** | SNTI |
| **Consensus** | Proof-of-Useful-Work (PoUW) via XMSS |
| **Signature Scheme** | XMSS-SHA2_10_256 (NIST SP 800-208) |
| **Block Time** | 60 seconds |
| **Max Supply** | 210,000,000 SNTI |
| **Halving Interval** | Every 2,100,000 blocks (~4 years) |
| **Genesis Date** | June 26, 2026 |
| **Codebase** | Bitcoin Core fork (C++) |
| **License** | BSL-1.1 → GPL-2.0 (2030) |
| **Magic Bytes** | SNTI (0x53, 0x4E, 0x54, 0x49) |
| **Contact** | assentianpqe@gmail.com |

---

## 2. Investment Thesis

### 2.1 The Core Proposition

Assentian-PQE is positioned at the intersection of three converging forces:

**Force 1: The Quantum Threat is Real**
NIST has finalized post-quantum cryptography standards (FIPS 203, 204, 205, SP 800-208). The US federal government mandates PQC migration by 2030. This is not speculation — it is policy.

**Force 2: Existing Blockchains Are Vulnerable**
Bitcoin, Ethereum, Solana — every major blockchain uses ECDSA or Ed25519. Both are broken by Shor's algorithm on a sufficiently powerful quantum computer. Migration is technically complex, politically contentious, and economically disruptive.

**Force 3: First-Mover Advantage is Claimed**
Assentian-PQE is the world's first working, mineable, NIST-compliant post-quantum blockchain — live since June 26, 2026.

### 2.2 Why Now
2024: NIST finalizes PQC standards

2025: Enterprise PQC migration begins

2026: SNTI mainnet launched June 26 ◄── WE ARE HERE

2027: "Harvest now, decrypt later" attacks surface publicly

2028: First cryptographically relevant quantum computer (IBM/Google estimates)

2029: NIST mandates PQC for all federal systems

2030: Mass migration begins — SNTI is already there
### 2.3 Total Addressable Market

| Market | Size (2026) | SNTI Relevance |
|---|---|---|
| Cryptocurrency market cap | ~$3.5 trillion | Direct — quantum-safe store of value |
| PQC security market | ~$400M → $7B by 2030 | Direct — XMSS mining as useful work |
| Enterprise blockchain | ~$12B | Indirect — PQC infrastructure |
| Government IT security | ~$80B | Indirect — regulatory tailwind |

**Conservative scenario:** If SNTI captures 0.1% of crypto market cap at quantum inflection point → $3.5B market cap.

---

## 3. The Quantum Threat

### 3.1 What Breaks

Current blockchain cryptography relies on two mathematical problems:

**ECDSA / Ed25519 (used by Bitcoin, Ethereum, Solana):**
- Security assumption: Discrete logarithm problem is hard
- Broken by: Shor's algorithm on quantum computer
- Timeline to break 256-bit ECDSA: ~4,000 logical qubits

**SHA-256 (used in Bitcoin PoW):**
- Security assumption: Preimage resistance
- Weakened by: Grover's algorithm (reduces to 128-bit effective security)
- Timeline to meaningfully weaken: ~10,000+ logical qubits

### 3.2 The Timeline

| Year | Event | Implication |
|---|---|---|
| 2019 | Google achieves quantum supremacy (53 qubits) | Proof of concept |
| 2023 | IBM reaches 1,000+ qubit processor | Engineering milestone |
| 2024 | NIST finalizes PQC standards | Policy signal |
| 2025 | Microsoft, Google, IBM racing to error correction | Commercial viability |
| 2026–2028 | Cryptographically relevant QC estimated | ECDSA at risk |
| 2029 | NIST PQC mandate for US federal systems | Regulatory force |
| 2030+ | Mass PQC migration | SNTI first-mover advantage |

### 3.3 "Harvest Now, Decrypt Later"

The most immediate threat is not breaking encryption in real-time — it is **retroactive decryption**. Nation-state actors are harvesting encrypted blockchain transactions today, storing them for future decryption when quantum computers become powerful enough.

For Bitcoin holders: **every transaction you have ever made is permanently recorded on a public ledger, and every signature will eventually be forgeable.**

Assentian-PQE addresses this by making XMSS the exclusive signature scheme used by every wallet, address, and mining reward from block zero — no transaction on the network has ever used a classical signature.

### 3.4 The $2.8 Trillion Problem

Bitcoin alone holds approximately $2.8 trillion in value (peak 2024). All of it is protected by ECDSA. When quantum computers break ECDSA:

- Addresses with exposed public keys become drainable
- P2PK outputs (Satoshi's coins) are immediately vulnerable
- Exchange hot wallets become high-value targets
- The entire trust model of "not your keys, not your coins" collapses

**Assentian-PQE is immune to this attack from genesis.**

---

## 4. Why XMSS

### 4.1 The NIST Selection

NIST spent 8 years (2016–2024) evaluating post-quantum cryptographic algorithms. The result:

- **FIPS 203**: CRYSTALS-Kyber (key encapsulation)
- **FIPS 204**: CRYSTALS-Dilithium (signatures)
- **FIPS 205**: SPHINCS+ (signatures)
- **SP 800-208**: XMSS and LMS (stateful hash-based signatures)

Assentian-PQE chose **XMSS from SP 800-208** — the only standard specifically designed for high-security, long-term applications where key state can be managed.

### 4.2 XMSS vs Other PQC Schemes

| Scheme | Standard | Quantum-Safe | Key Size | Sig Size | Security Assumption | SNTI Choice |
|---|---|---|---|---|---|---|
| **XMSS** | NIST SP 800-208 | ✅ Yes | 64 B | 2,500 B | Hash only | **✅ Selected** |
| SPHINCS+ | NIST FIPS 205 | ✅ Yes | 32 B | 8,000 B | Hash only | Too large |
| FALCON | NIST FIPS 206 | ✅ Yes | 897 B | 666 B | Lattice | Lattice risk |
| CRYSTALS-Dilithium | NIST FIPS 204 | ✅ Yes | 1,312 B | 2,420 B | Lattice | Lattice risk |
| LMS | NIST SP 800-208 | ✅ Yes | 64 B | ~4,000 B | Hash only | Less efficient |
| ECDSA | None (broken) | ❌ No | 33 B | 72 B | Discrete log | Bitcoin/ETH use this |

**Why XMSS wins for SNTI:**

1. **Hash-only security**: No new mathematical assumptions. Security relies entirely on SHA-256, which has 50+ years of analysis.
2. **Smallest quantum-safe public key**: 64 bytes — enabling efficient on-chain storage.
3. **NIST-approved**: Regulatory compliance from day one.
4. **Production-proven**: Used in real deployments (IETF RFC 8391).
5. **Stateful advantage**: Key state enables efficient verification and mining integration.

### 4.3 The Innovation: Proof-of-Useful-Work

Traditional Proof-of-Work produces **nothing of value**:
Traditional Mining:

Electricity → SHA-256 hashing → Heat + CO₂ + Block reward

(The hashes are thrown away. They have no use outside mining.)
Assentian-PQE Proof-of-Useful-Work produces **real cryptographic infrastructure**:
SNTI Mining:

Electricity → XMSS key generation → Quantum-safe signatures → Block reward

(The XMSS operations actively secure the network against quantum attacks.)
Every block mined on Assentian-PQE contributes a verified XMSS key pair and signature to the blockchain's security infrastructure. Mining IS security.

---

## 5. Competitive Landscape

### 5.1 The Honest Picture

Assentian-PQE acknowledges the work that came before it. We do not exist in a vacuum.

#### QRL (Quantum Resistant Ledger)

| Aspect | QRL | SNTI |
|---|---|---|
| Launch | June 2018 | June 2026 |
| Consensus | Proof of Stake | Proof-of-Useful-Work |
| Signature | XMSS-SHA2_10_256 | XMSS-SHA2_10_256 |
| Mineable | ❌ No | ✅ Yes |
| Bitcoin Core base | ❌ No | ✅ Yes |
| Useful work | ❌ No | ✅ Yes |
| DeFi roadmap | Limited | Full |

QRL proved XMSS works in production blockchain. SNTI adds mining, useful work, and a Bitcoin Core foundation.

#### IOTA

IOTA uses Winternitz OTS (a simpler hash-based scheme) in a DAG architecture. Not mineable, not NIST-standardized, different security model. Not a direct competitor.

#### Bitcoin / Ethereum PQC Migration

The most common question: "What if Bitcoin just migrates to PQC?"

The honest answer: Bitcoin migration is **not technically straightforward**. It requires:
- Consensus among thousands of node operators
- Migration of ~4 million exposed addresses
- Hard fork coordination across exchanges, wallets, miners
- 5–10 year transition period minimum

Ethereum faces similar challenges. Even optimistic timelines suggest 2030+ for completion.

**By the time Bitcoin completes PQC migration, SNTI will have 4+ years of battle-tested operation.**

### 5.2 Competitive Position
POST-QUANTUM BLOCKCHAIN LANDSCAPE (2026)

Theoretical ◄──────────────────────────────────────────► Operational

MatRiCT+    SPHINCS+    Dilithium-    IOTA        QRL         SNTI ★
(paper)     (theory)    Ethereum      (DAG,       (PoS,       (PoUW,
                        (EIP draft)   W-OTS)      XMSS)       mineable,
                                                              BTC Core,
                                                              LIVE)

◄── Not mineable ──────────────────────────────────── Mineable ──►
◄── Single purpose ────────────────────────────── Full ecosystem ─►
◄── Unproven ──────────────────────────────────── Production ──►
### 5.3 Feature Matrix

| Feature | Bitcoin | Ethereum | QRL | SNTI |
|---|---|---|---|---|
| Quantum-safe signatures | ❌ ECDSA | ❌ ECDSA | ✅ XMSS | ✅ XMSS |
| NIST-standardized | N/A | N/A | ✅ SP 800-208 | ✅ SP 800-208 |
| Mineable | ✅ PoW | ❌ PoS | ❌ PoS | ✅ PoUW |
| Useful mining work | ❌ | ❌ | ❌ | ✅ |
| Bitcoin Core base | ✅ | ❌ | ❌ | ✅ |
| Live mainnet (2026) | ✅ | ✅ | ✅ | ✅ |
| No pre-mine | ✅ | ❌ | ✅ | ✅ |
| Fair launch | ✅ | ❌ | ✅ | ✅ |
| DeFi ecosystem | ✅ | ✅ | ❌ | ✅ Planned |

---

## 6. Architecture

### 6.1 System Overview
┌─────────────────────────────────────────────────────────────┐

│                    ASSENTIAN-PQE NETWORK                     │

│                                                             │

│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐      │

│  │  Miner   │───▶│ Stratum Pool │───▶│  Full Node   │      │

│  │(CPU/GPU) │    │  (Wave 2)    │    │  (bitcoind)  │      │

│  └──────────┘    └──────────────┘    └──────────────┘      │

│       │                                     │               │

│       ▼                                     ▼               │

│  ┌──────────┐                      ┌──────────────┐        │

│  │ XMSS Key │                      │  Block       │        │

│  │ Gen+Sign │                      │  Explorer    │        │

│  └──────────┘                      └──────────────┘        │

│                                                             │

│  ┌───────────────────────────────────────────────────┐     │

│  │              Blockchain Layer                      │     │

│  │  Bitcoin Core 27.0 • UTXO • SegWit • P2WPKH      │     │

│  │  XMSS-SHA2_10_256 • PoUW • Sighash-v2            │     │

│  └───────────────────────────────────────────────────┘     │

└─────────────────────────────────────────────────────────────┘
### 6.2 Block Structure
┌────────────────────────────────────────┐

│             SNTI BLOCK                  │

├────────────────────────────────────────┤

│  Block Header (148 bytes)              │

│  ├── nVersion       (4 bytes)          │

│  ├── hashPrevBlock  (32 bytes)         │

│  ├── hashMerkleRoot (32 bytes)         │

│  ├── nTime          (4 bytes)          │

│  ├── nBits          (4 bytes)          │

│  ├── nNonce         (4 bytes, = 0)     │

│  ├── xmssRoot       (32 bytes) ← PoUW │

│  ├── nLeafIndex     (4 bytes)  ← PoUW │

│  └── commitmentsRoot(32 bytes) ← PoUW │

├────────────────────────────────────────┤

│  Coinbase Transaction                  │

│  ├── vout[0]: Mining reward (SNTI)     │

│  ├── vout[1]: Witness commitment       │

│  ├── vout[2]: OP_RETURN PoUWv2Proof   │

│  │            (2,660 bytes, PW2\x02)   │

│  └── vout[3]: OP_RETURN failed seeds  │

│               (optional, key der.)     │

├────────────────────────────────────────┤

│  Transactions (standard UTXO)          │

│  └── XMSS-signed inputs               │

└────────────────────────────────────────┘
### 6.3 Key Security Features

**Sighash-v2 (Cross-Index Attack Prevention)**

Assentian-PQE implements a hardened sighash scheme:


## 7. Proof-of-Useful-Work
### 7.1 PoUW v2 — Pure XMSS Tree Building (Live since Jun 24, 2026)

**SHA-256 nonce search has been completely removed.** Building the XMSS Merkle tree IS the proof of work.

#### How PoUW v2 Works

Step 1: Miner loads persistent XMSS tree state from disk
- If none exists or tree is exhausted: build a new tree (Step 2)
- If valid tree exists with root < target: skip to Step 4

Step 2: Miner builds a new XMSS keypair (height=10, 1024 leaves)
- Uses `xmss_keypair()` — cryptographically random keypair generation
- Cost: ~6 seconds per attempt on Intel Xeon @ 2.5GHz
- Output: `xmssRoot` = Merkle root hash (32 bytes), persisted to disk

Step 3: Check if `xmssRoot < target`
- YES → valid tree found, save state, proceed to Step 4
- NO → discard tree, build new one (back to Step 2)

Step 4: Sign block preimage with WOTS+ (next available leaf)
- `preimage = SHA256(nVersion || hashPrevBlock || nTime || nBits)`
- One tree (same `xmssRoot`) serves up to 1024 consecutive blocks, each using a different leaf index
- Leaf index saved atomically to disk before block is returned — prevents WOTS+ reuse on restart
- Embed `PoUWv2Proof` in coinbase OP_RETURN (2,660 bytes total)

Step 5: Submit block — node verifies:
- `block.xmssRoot < target` (PoW check)
- `PoUWv2Proof.Deserialize()` — extract proof components
- `CheckPoUWv2()` — WOTS+ signature verified via `xmss_sign_open()`
- Leaf index uniqueness — scan last 1,024 blocks, reject if `(xmssRoot, leafIndex)` pair reused

#### Why This IS "Useful Work"

Every mining attempt produces a complete XMSS keypair with 1024 one-time signatures — directly useful post-quantum cryptographic material. Unlike SHA-256 which produces nothing of value, XMSS tree building:

- Generates quantum-resistant key material
- Advances global post-quantum cryptographic infrastructure
- Proves the miner performed real cryptographic computation

#### Difficulty & Performance

| Parameter | Value |
|---|---|
| Tree height | 10 (1024 leaves) |
| Build time (1 core) | ~6.17 seconds |
| Target attempts/block | 156 (4 cores × 39/core) |
| Difficulty algorithm | EMA per-block (α=0.1) |
| powLimit | 2²⁵⁶ / 156 |
| Target block time | 60 seconds |
| Genesis nBits | 0x2001a41a |

#### PoUW v2 Proof Format (coinbase OP_RETURN, 2,660 bytes)

| Field | Size | Description |
|---|---|---|
| Magic | 4 bytes | `PW2\x02` |
| SK_SEED | 96 bytes | SK_SEED + SK_PRF + PUB_SEED |
| xmss_pk | 64 bytes | root + PUB_SEED |
| auth_path | 320 bytes | 10 × 32 bytes node hashes |
| wots_sig | 2144 bytes | WOTS+ signature |
| r | 32 bytes | signature randomness |

## 8. Security Model

### 8.1 Threat Model

| Threat | Classical | Quantum | SNTI Defense |
|---|---|---|---|
| Signature forgery | Infeasible (ECDSA) | **Trivial (Shor's)** | XMSS: hash-based, quantum-safe |
| Key recovery | Infeasible | **Trivial** | XMSS: no private key exposure |
| 51% attack | Expensive | Same cost | PoUW: requires XMSS keygen |
| Replay attack | Prevented by nonce | Same | Sighash-v2 + leaf_index |
| Cross-index attack | N/A | N/A | Sighash-v2 prevents it |
| Key exhaustion | N/A | N/A | Key retirement protocol |
| Wallet compromise | Physical security | Same | Encryption at rest |

### 8.2 Security Audits

Current status:
- Internal security review: ✅ Complete
- Sighash-v2 design review: ✅ Complete
- Key retirement protocol: ✅ Implemented
- External audit (Trail of Bits / Halborn): 🔜 Planned Q4 2026

Assentian-PQE is actively seeking funding for a professional security audit. Budget requirement: $20,000–$100,000.

### 8.3 Known Limitations

**XMSS is stateful.** Unlike ECDSA, XMSS requires tracking which leaf indices have been used. WOTS+ is a one-time signature scheme: signing two different messages with the same leaf exposes the WOTS private key, which would allow an attacker to forge block signatures for that keypair.

Assentian-PQE enforces strict protection against this:
- **Write-before-use**: leaf index is saved to disk atomically *before* the mined block is returned. If the disk write fails, mining aborts — the block is never returned and the leaf is never exposed.
- **Consensus-level rejection**: full nodes scan the last 1,024 blocks and reject any block whose `(xmssRoot, leafIndex)` pair has already appeared on chain.
- **Exhaustion rebuild**: when all 1,024 leaves of a tree are used, a new keypair is built automatically before the next block is mined.

---

## 9. Tokenomics

### 9.1 Supply Schedule

Total Supply: **210,000,000 SNTI** (hard cap — 10× Bitcoin's 21M, scaled for 60-second block time)

```
├── Block 0–2,100,000:         50 SNTI/block   (~4 years)
├── Block 2,100,000–4,200,000: 25 SNTI/block   (~4 years)
├── Block 4,200,000–6,300,000: 12.5 SNTI/block (~4 years)
└── ... halvings continue until ~2140
```

**No pre-mine. No VC allocation. No insider rounds.** All SNTI enters circulation through mining — identical to Bitcoin's fair launch model.

### 9.2 Emission Schedule

| Phase | Blocks | Reward | SNTI/Day | Era |
|---|---|---|---|---|
| Genesis | 0–2,100k | 50 SNTI | ~72,000 | 2026–2030 |
| Halving 1 | 2,100k–4,200k | 25 SNTI | ~36,000 | 2030–2034 |
| Halving 2 | 4,200k–6,300k | 12.5 SNTI | ~18,000 | 2034–2038 |
| Halving 3 | 6,300k–8,400k | 6.25 SNTI | ~9,000 | 2038–2042 |

*Note: 1,440 blocks/day at 60-second target.*

### 9.3 Value Drivers

1. **Scarcity**: Fixed 21M supply — same model as Bitcoin
2. **Utility**: Only quantum-safe mineable chain — unique use case
3. **Regulatory**: NIST-compliant = institutional-grade
4. **Network effect**: Miners → hashrate → security → value
5. **Quantum inflection**: Value accelerates as quantum threat materializes
6. **Deflationary**: 50% of transaction fees burned

---

## 10. Roadmap

### ✅ Phase 0: Foundation (Complete — June 2026)

- ✅ XMSS-SHA2_10_256 integrated into Bitcoin Core 27.0
- ✅ Proof-of-Useful-Work (PoUW) v2 consensus — XMSS tree building IS the mining algorithm
- ✅ Sighash-v2 (cross-index attack prevention)
- ✅ Key retirement protocol (one-time XMSS addresses)
- ✅ Encryption at rest for XMSS wallet state
- ✅ Wallet backup/restore with XMSS state verification
- ✅ Testnet live (PoUW v2 genesis Jun 24, 2026 — `d02122cd...`)
- ✅ Block explorer operational
- ✅ WOTS+ leaf reuse protection enforced (abort on save failure — Jun 25, 2026)
- ✅ XMSS miner state persistence verified — 1 tree reused across 1,024 blocks (Jun 25, 2026)
- ✅ WOTS+ full signature verification via `xmss_sign_open()` in `CheckPoUWv2()`
- ⚠️ Stratum server pending PoUW v2 update (v1 format incompatible)

### ✅ Phase 1: Mainnet Launched — June 26, 2026

- ✅ Mainnet genesis block — June 26, 2026 (`b4a26aef...`, nBits `0x2001a41a`)
- ✅ 3-node network — Indonesia + USA (KC) + Singapore (SG), 1170+ blocks
- ✅ DNS seeds — seed/seed2/seed3.assentian.network (3 IPs, round-robin)
- ✅ Web wallet — assentian.network/wallet/
- ✅ Block explorer — assentian.network/explorer/
- ✅ Whitepaper HTML version — assentian.network/whitepaper.html
- ✅ Internal deep audit — 12 bugs found & fixed (29 Jun 2026)
- ✅ Send/receive SNTI verified end-to-end
- [ ] External security audit (Trail of Bits / Halborn) — Q4 2026
- [ ] Community launch (Discord, Telegram, Twitter) — pending

### 🔜 Phase 2: Exchange & Wallet (Q1–Q2 2027)

- [ ] Desktop wallet (Qt GUI)
- [ ] Hardware wallet support (Ledger/Trezor research)
- [ ] First exchange listing (DEX priority)
- [ ] Mobile wallet (Android first)
- [ ] Payment API v1.0
- [ ] Merchant SDK

### 🔜 Phase 3: Ecosystem (Q3–Q4 2027)

- [ ] Layer-2 payment channels (Lightning-compatible)
- [ ] Atomic swaps (SNTI ↔ BTC)
- [ ] DeFi bridge
- [ ] Governance system (on-chain voting)
- [ ] SNTI Grant Program ($500k equivalent)
- [ ] iOS wallet

### 🔜 Phase 4: Enterprise (2028+)

- [ ] Enterprise node solutions
- [ ] Government partnership program
- [ ] Post-quantum TLS certificate integration
- [ ] IoT security use cases
- [ ] Cross-chain interoperability
- [ ] Academic research partnerships

---

## 11. Technical Specifications

### 11.1 XMSS Parameters

| Parameter | Value | Description |
|---|---|---|
| Scheme | XMSS-SHA2_10_256 | SHA-256, tree height 10 |
| OID | 0x00000001 | RFC 8391 identifier |
| n | 32 bytes | Hash output size |
| w | 16 | Winternitz parameter |
| h | 10 | Merkle tree height |
| Public key | 64 bytes | root (32B) + PUB_SEED (32B) |
| Signature | 2,500 bytes | Full XMSS signature |
| Sigs per key | 1,024 | 2^10 leaf nodes |
| Security level | 128-bit | NIST Level 1 |

### 11.2 Network Parameters

| Parameter | Mainnet | Testnet |
|---|---|---|
| Magic bytes | SNTI (0x53,0x4E,0x54,0x49) | sTST (0x73,0x54,0x53,0x54) |
| P2P port | 9333 | 19333 |
| RPC port | 9332 | 18332 |
| Address format | bech32m (`snti1…`) | bech32m (`tsnti1…`) |
| Bech32 HRP | snti | tsnti |
| Genesis hash | b4a26aef52f6f503... | — |
| Genesis nNonce | 0 (PoUW v2) | 0 (PoUW v2) |
| Genesis nBits | 0x2001a41a | 0x207fffff |
| Max block size | 4 MB | 4 MB |
| Block weight limit | 4,000,000 | 4,000,000 |

### 11.3 Sighash-v2 Specification
Standard sighash (v1):

sighash = SHA256(serialized_tx_data)
Assentian-PQE sighash (v2):

sighash_v2 = SHA256(sighash_v1 || leaf_index_BE)
Where:

leaf_index_BE = 4-byte big-endian XMSS leaf index
Security benefit:

A signature valid at leaf index N cannot be replayed at index M.

Prevents cross-index forgery attacks on XMSS-signed transactions.
### 11.4 CheckPoUW Validation

Every block undergoes a two-stage validation:

**Stage 1 — Header check** (`CheckBlockHeader`):
```
block.xmssRoot < target   (compact nBits)
```

**Stage 2 — Full proof check** (`CheckPoUW`):
```
1. Scan coinbase vouts for OP_RETURN with magic PW2\x02
2. Deserialize PoUWv2Proof (2,660 bytes):
     seed(96) | xmss_pk(64) | auth_path(320) | wots_sig(2144) | r(32)
3. Verify proof.GetRoot() < target
4. Compute preimage = SHA256(nVersion || hashPrevBlock || nTime || nBits)
5. Reconstruct SM buffer: [idx(4) | r(32) | wots_sig(2144) | auth_path(320) | preimage(32)]
6. xmss_sign_open(SM, xmss_pk) — recovers message, verifies WOTS+ chain
7. Assert recovered message == preimage
8. Scan last 1,024 blocks: reject if (xmssRoot, nLeafIndex) already used
```

The preimage intentionally excludes `hashMerkleRoot` and `xmssRoot` to avoid a circular dependency (the proof is embedded in the coinbase, which changes the merkle root when inserted).

---


---

## 12. Blockchain Scalability & The XMSS Size Trade-off

### 12.1 The Honest Question

Institutional investors will ask: *"XMSS signatures are 2,500 bytes. ECDSA is 72 bytes. Won't this bloat the blockchain?"*

This is the right question. This section answers it directly.

### 12.2 The Size Reality

| Signature Scheme | Sig Size | Pubkey | Total | Quantum-Safe |
|---|---|---|---|---|
| ECDSA (Bitcoin) | 72 bytes | 33 bytes | ~105 bytes | ❌ No |
| Ed25519 (Solana) | 64 bytes | 32 bytes | ~96 bytes | ❌ No |
| **XMSS (SNTI)** | **2,500 bytes** | **64 bytes** | **~2,564 bytes** | **✅ Yes** |
| FALCON (lattice) | 666 bytes | 897 bytes | ~1,563 bytes | ✅ Yes |
| SPHINCS+ | 8,000 bytes | 32 bytes | ~8,032 bytes | ✅ Yes |

XMSS signatures are **34x larger** than ECDSA. This is a deliberate engineering trade-off — not an oversight.

### 12.3 Current Impact: Minimal

In Assentian-PQE's current architecture, XMSS signatures appear **only in the coinbase transaction** (one per block). Standard user-to-user transactions use P2WPKH (standard SegWit), which is identical in size to Bitcoin transactions.
Current SNTI block anatomy:

├── Coinbase tx:     ~2,800 bytes  (XMSS pubkey + signature)

└── User txs:        ~220 bytes each (standard SegWit — same as Bitcoin)
Block size overhead vs Bitcoin: +2,500 bytes per block

With 4MB max block size:        0.06% overhead — negligible
**Today, SNTI block size is virtually identical to Bitcoin.**

### 12.4 SegWit Witness Discount

XMSS signatures are stored in the **witness** portion of the coinbase transaction. Bitcoin's SegWit protocol applies a **75% discount** to witness data weight:
XMSS signature weight calculation:

Raw size:        2,500 bytes

Witness weight:  2,500 × 0.25 = 625 weight units
ECDSA equivalent:

Raw size:        72 bytes

Witness weight:  72 × 0.25 = 18 weight units
Effective ratio after SegWit discount: ~35x → ~8-9x
The SegWit discount significantly reduces the fee premium for XMSS-signed inputs.

### 12.5 Projected Chain Growth

| Scenario | Tx/Day | Chain Growth/Year | 10-Year Size |
|---|---|---|---|
| Bitcoin (current) | ~500,000 | ~50 GB | ~600 GB |
| SNTI (coinbase only) | ~1,440 | ~1.5 GB | ~15 GB |
| SNTI (all tx XMSS) | ~50,000 | ~45 GB | ~450 GB |
| SNTI (L2 + settlement) | ~1,440 | ~1.5 GB | ~15 GB |

**Key insight:** With Layer-2 adoption (Lightning-style payment channels), SNTI's on-chain footprint remains comparable to Bitcoin. The XMSS overhead is absorbed at the settlement layer, not every micro-transaction.

### 12.6 The Five Mitigations

**Mitigation 1: Pruning (Available Now)**

Bitcoin Core's pruning mode allows nodes to discard historical block data while retaining the full UTXO set. SNTI inherits this capability. A pruned SNTI node requires only ~10 GB regardless of chain age — making full node operation accessible to anyone with a consumer laptop.

**Mitigation 2: SegWit Witness Discount (Active)**

All XMSS signatures are stored in witness data, receiving the 75% weight discount built into the SegWit protocol. This reduces effective block space consumption by 4x compared to naive implementation.

**Mitigation 3: Layer-2 Payment Channels (Roadmap Q3 2027)**

The most powerful mitigation. Lightning Network-style payment channels move the vast majority of transactions off-chain:
Without L2:  1,000 transactions = 1,000 on-chain XMSS signatures

With L2:     1,000 transactions = 2 on-chain settlements (open + close)
Result: 500x reduction in on-chain XMSS overhead for high-frequency payments
**Mitigation 4: Archival vs. Light Nodes**

SNTI supports three node modes:
- **Full archival node**: Complete chain history (~15 GB/year)
- **Pruned full node**: UTXO set only (~10 GB total, any age)
- **SPV light node**: Headers only (~50 MB) — sufficient for wallet use

Institutional infrastructure uses archival nodes. Consumer wallets use SPV. The economics remain favorable at both ends.

**Mitigation 5: Future Signature Upgrade Path**

SNTI's architecture supports signature scheme upgrades via soft fork. If a more compact quantum-safe scheme achieves sufficient security confidence, migration is possible without chain restart:
Potential future schemes:

FALCON-512:  666 bytes  (9x smaller than XMSS, lattice-based)

Dilithium2:  2,420 bytes (similar to XMSS, lattice-based)
SNTI position: XMSS today (hash-based, zero new assumptions)

→ upgrade path open as PQC landscape matures
### 12.7 The Fundamental Trade-off

This is not a flaw to hide. It is a trade-off to understand:
┌─────────────────────────────────────────────────────────┐

│              THE XMSS TRADE-OFF                          │

│                                                         │

│  WHAT YOU GIVE UP:                                      │

│  └── Signature size: 2,500 bytes vs 72 bytes (ECDSA)   │

│                                                         │

│  WHAT YOU GET:                                          │

│  └── Immunity to Shor's algorithm                       │

│  └── NIST SP 800-208 compliance                         │

│  └── Zero new cryptographic assumptions                 │

│  └── 15+ years of security analysis                     │

│  └── No migration needed when quantum computers arrive  │

│                                                         │

│  CONTEXT:                                               │

│  └── Storage costs fall 30-40% per year (Moore's Law)  │

│  └── 10-year SNTI chain ≈ 15 GB (pruned: ~10 GB)      │

│  └── A 4TB SSD costs $80 today                         │

│  └── ECDSA will be broken. XMSS will not.             │

└─────────────────────────────────────────────────────────┘
### 12.8 Comparison: QRL's 8-Year Track Record

QRL (Quantum Resistant Ledger) has operated an XMSS blockchain since June 2018 — 8 years of production data.

QRL chain size after 8 years: **~50 GB** (with moderate transaction volume).

For context: Bitcoin's chain is ~600 GB after 15 years with significantly higher transaction volume. XMSS bloat in practice, with low-to-moderate volume, is entirely manageable.

**SNTI's projection, assuming similar growth trajectory to QRL: ~15-30 GB after 10 years.**

### 12.9 The Institutional Perspective

For institutional investors evaluating blockchain infrastructure:

| Concern | Reality |
|---|---|
| "2,500 byte signatures will bloat the chain" | With pruning + L2, 10-year chain ≈ 15 GB |
| "Storage costs will be prohibitive" | 4TB SSD = $80 today, falling 35%/year |
| "Transaction fees will be too high" | SegWit discount + L2 keeps fees competitive |
| "Throughput will be too low" | L2 channels handle 1M+ tx/sec off-chain |
| "Can't compete with ECDSA chains" | ECDSA chains will be quantum-broken by 2030 |

**The question is not "Is XMSS perfectly efficient?" — it is not.**
**The question is "Is the trade-off worth making?" — unambiguously yes.**

When a sufficiently powerful quantum computer arrives, every ECDSA blockchain faces an existential crisis. Storage optimization can be engineered. Quantum resistance cannot be retrofitted cheaply.

**Assentian-PQE made the right trade-off on day one.**

---
## 13. Risk Analysis

### 13.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| XMSS key exhaustion | Low | Medium | 1,024 sigs/key; rotation enforced |
| Implementation bugs | Medium | High | External audit planned; bug bounty |
| Quantum faster than expected | Low | Positive | SNTI already quantum-safe |
| XMSS superseded by better PQC | Low | Medium | Upgrade path via soft fork |
| State management errors | Low | High | Atomic writes (fsync) prevent corruption; cross-machine `wallet.dat` restore is a documented user risk, not automatically mitigated — see README.md / MINING_GUIDE.md |
| Legacy ECDSA opcodes (OP_CHECKSIG) inherited from Bitcoin Core | Low | Low | Not enforced-rejected at consensus level; no wallet or tooling generates ECDSA scripts, and no ECDSA-signed transaction has ever been mined — documented here for transparency rather than left implicit |

### 13.2 Market Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Bitcoin adopts PQC (by 2030) | 15% | High | 4+ year head start; network effect |
| Low initial hashrate | High | Medium | CPU-friendly launch; no ASIC advantage |
| Price volatility | High | Medium | Utility-driven demand |
| Exchange listing delays | Medium | High | DEX-first strategy |

### 13.3 Regulatory Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Mining regulation | Medium | Medium | Useful-work narrative; green energy |
| Securities classification | Low | High | Fair launch; no pre-mine; utility token |
| PQC export controls | Very Low | Low | XMSS is currently unrestricted globally |
| Exchange compliance | Medium | Medium | Legal review before listings |

### 13.4 Competitive Analysis

**Scenario A (35%): Bitcoin delays PQC migration**
SNTI has clear runway to 2030+. Best case for network effect accumulation.

**Scenario B (35%): Bitcoin begins PQC migration (2028–2030)**
Migration takes 5–10 years. SNTI maintains quantum-safe advantage throughout transition. Value proposition: "Migration risk-free from day one."

**Scenario C (20%): New PQC chain launches with better tech**
SNTI's Bitcoin Core foundation, first-mover status, and established mining network provide competitive moat.

**Scenario D (10%): Quantum threat overstated, mass adoption delayed**
SNTI still operates as a sound-money, fixed-supply cryptocurrency with unique useful-work narrative. Downside protection from Bitcoin-model tokenomics.

---

## 14. Team & Governance

### 14.1 Core Team

**Asep Mulya** — Founder & Lead Developer
- Creator of Assentian-PQE (SNTI)
- Designed and implemented PoUW consensus
- Implemented XMSS integration into Bitcoin Core
- Sighash-v2 design and implementation
- Contact: assentianpqe@gmail.com

### 14.2 Open Source Contribution

Assentian-PQE is built on the shoulders of giants:

- **Bitcoin Core developers** — 15+ years of battle-tested codebase
- **QRL team** — First production XMSS blockchain (2018)
- **NIST PQC team** — XMSS standardization (SP 800-208)
- **Andreas Hülsing & Joost Rijneveld** — XMSS reference implementation
- **The broader PQC research community** — 15+ years of cryptanalysis

### 14.3 Governance Model

**Phase 1 (2026–2027):** Founder-led development
- Rapid iteration and bug fixes
- Community input via GitHub issues
- Transparent changelog and commit history

**Phase 2 (2027–2028):** Community governance introduction
- On-chain proposal system
- SNTI token voting (1 SNTI = 1 vote)
- Core developer multisig for emergency fixes

**Phase 3 (2028+):** Fully decentralized governance
- Foundation established
- Grant program for ecosystem development
- SNTI Improvement Proposals (SIPs)

### 14.4 Legal

- **Copyright**: Asep Mulya, 2026
- **License**: Business Source License 1.1 (BSL-1.1)
- **License conversion**: Automatically converts to GPL-2.0 on January 1, 2030
- **GitHub**: https://github.com/assentian-network/snti

---

## 15. Conclusion

The quantum threat to existing blockchain infrastructure is not hypothetical. It is a mathematically certain outcome of quantum computing progress — the only uncertainty is timing.

Assentian-PQE (SNTI) does not wait for the threat to materialize. It is **built for the post-quantum world from genesis** — June 26, 2026.

**What sets SNTI apart:**

1. **Operational, not theoretical** — Mainnet live, mining working, blocks confirmed
2. **NIST-compliant** — XMSS from SP 800-208, the gold standard for stateful PQC
3. **Bitcoin DNA** — 15 years of battle-tested code as the foundation
4. **Useful work** — Mining produces real cryptographic value, not wasted hashes
5. **Fair launch** — No pre-mine, no VC allocation, no insider advantage
6. **Novel consensus** — The only blockchain where XMSS tree building IS the proof of work, not just the signature scheme

The question investors should ask is not "Will quantum computers threaten ECDSA?" — they will. The question is: **"When the quantum inflection point arrives, which blockchain will already be ready?"**

The answer is Assentian-PQE.

---

## References

1. NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes (2020)
2. IETF RFC 8391 — XMSS: eXtended Merkle Signature Scheme (2018)
3. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (2024)
4. NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (2024)
5. Bitcoin Core — Reference implementation, MIT License
6. Hülsing, A. & Rijneveld, J. — XMSS Reference Implementation
7. IBM Quantum — Quantum computing roadmap 2023–2033
8. Google Quantum AI — Beyond Classical Computing (2019)

---

*Assentian-PQE Whitepaper v1.1 | June 26, 2026*
*Genesis: "Assentian-PQE 22/Jun/2026 XMSS Post Quantum Era - For Sentia"*
*Contact: assentianpqe@gmail.com*
*GitHub: https://github.com/assentian-network/snti*
