# Assentian-PQE (SNTI) — Investor Roadmap
## "The World's First Post-Quantum Proof-of-Work Blockchain"
**Version 1.0 — June 2026**

---

## Executive Summary

Assentian-PQE (SNTI) is the world's first blockchain where **quantum resistance is enforced at the consensus layer**, not just at the signature level. While Bitcoin and Ethereum can be broken by a sufficiently powerful quantum computer — compromising trillions in value — SNTI is designed to survive the quantum era.

We are not adding quantum-resistance as an afterthought. It is the foundation.

- **Consensus:** Proof of Useful Work v2 (PoUW v2) — XMSS tree root must satisfy difficulty target
- **Signatures:** XMSS (eXtended Merkle Signature Scheme) — NIST SP 800-208 standard
- **Mining:** CPU-accessible today; quantum-resistant by design
- **Status:** Mainnet live since June 26, 2026

---

## The Problem: $3 Trillion at Quantum Risk

Bitcoin uses ECDSA (secp256k1) and SHA-256. Ethereum uses ECDSA (secp256k1) and Keccak-256.

Both are vulnerable to Shor's algorithm on a large enough quantum computer:
- ECDSA private keys can be derived from public keys in polynomial time
- Public keys are exposed in every transaction

**Timeline threat:**
| Year | Milestone |
|------|-----------|
| 2024 | NIST finalizes post-quantum standards (CRYSTALS, XMSS, SPHINCS+) |
| 2025 | IBM Condor: 1,121 qubit processor |
| 2027–2030 | Estimates for "cryptographically relevant" quantum computers (CRQC) |
| Post-CRQC | All ECDSA-based blockchains are fundamentally broken |

NIST, NSA, and the EU's ENISA have issued formal guidance: **migrate to post-quantum cryptography now**.

---

## The Solution: Assentian-PQE

### Why XMSS?

XMSS (RFC 8391, NIST SP 800-208) is a hash-based signature scheme:
- Security relies only on hash function collision resistance — unbroken by quantum computers
- Formally standardized by NIST in 2020
- No hardness assumptions that quantum computers can attack

### Why PoUW v2?

Standard Proof-of-Work (Bitcoin's SHA-256) does "useless" computation. PoUW v2 requires miners to:
1. Generate a valid XMSS Merkle tree (1,024 leaves)
2. Find a tree root that satisfies the difficulty target

This means every mining operation **produces a real cryptographic artifact** — a post-quantum key pair — rather than a disposable hash. Mining IS key generation.

### Technical Moat

| Feature | Bitcoin | Ethereum | SNTI |
|---------|---------|----------|------|
| Quantum-resistant signatures | ❌ | ❌ | ✅ XMSS |
| Quantum-resistant consensus | ❌ | ❌ | ✅ PoUW v2 |
| NIST-standardized crypto | ❌ | ❌ | ✅ |
| Mining produces useful work | ❌ | ❌ | ✅ |
| Leaf reuse protection (on-chain) | N/A | N/A | ✅ SNTI M7 |
| EMA difficulty adjustment | ❌ | ✅ | ✅ |

---

## Market Opportunity

### Total Addressable Market

1. **Institutional crypto holders** ($500B+ AUM): Major funds need quantum-safe custody solutions
2. **Central Bank Digital Currencies (CBDCs)**: 130+ countries exploring CBDCs; quantum resistance is a stated requirement
3. **Government/Defense sector**: NSA mandates post-quantum transition by 2030 for national security systems
4. **Enterprise blockchain** (supply chain, healthcare, finance): Long-lived systems need 20-year security horizon

### Competitive Landscape

| Project | PQ Signatures | PQ Consensus | Status |
|---------|---------------|--------------|--------|
| Bitcoin | ❌ | ❌ | Mainnet |
| Ethereum | ❌ | ❌ | Mainnet |
| QRL (Quantum Resistant Ledger) | ✅ XMSS | ❌ PoW SHA-256 | Mainnet, limited adoption |
| IOTA | ✅ Winternitz | ❌ DAG | Mainnet |
| **SNTI** | **✅ XMSS** | **✅ PoUW v2** | **Mainnet June 2026** |

**Key differentiation from QRL**: QRL uses XMSS for signatures but mines with standard SHA-256 PoW. SNTI is the only chain where the mining process itself IS the quantum-resistant work.

---

## Roadmap

### Phase 1 — Foundation (COMPLETE: June 2026)
- [x] XMSS signature integration (NIST SP 800-208)
- [x] PoUW v2 consensus mechanism
- [x] EMA difficulty adjustment (60-second target blocks)
- [x] On-chain leaf index tracking (prevents key reuse attacks — SNTI M7)
- [x] Mainnet genesis block (June 26, 2026)
- [x] Block explorer (assentian.network/explorer/)
- [x] DNS seed infrastructure (seed.assentian.network)
- [x] Web wallet (assentian.network/wallet)

### Phase 2 — Accessibility (Q3 2026, 3 months)
- [ ] **XMSS WebAssembly wallet** — generate SNTI addresses in browser without running a node
  - Client-side key generation: private key never leaves user's device
  - Truly non-custodial web wallet
  - Based on NIST reference implementation (xmss-reference compiled to WASM)
- [ ] **mine.sh one-liner** — single command to download binary, sync node, and start mining
  - Target: `curl snti.sh | bash` to start mining in under 5 minutes
- [ ] **Exportable XMSS key format** — portable wallet file (`.snti` format) for backup and import
- [ ] **Peer discovery improvement** — add more seed nodes for faster sync

### Phase 3 — Ecosystem (Q4 2026, 6 months)
- [ ] **Mobile wallet** (Android) — XMSS key generation on-device
- [ ] **Exchange listings** — target DEX first (Uniswap bridge or native), then CEX
- [ ] **Mining pool protocol** — custom stratum adapter for PoUW v2 (enables pool mining)
- [ ] **Checkpoints** — hardened checkpoints after 10,000 mainnet blocks
- [ ] **External security audit** — Trail of Bits or Halborn ($20k-$100k scope)
- [ ] **Developer SDK** — JavaScript/Python library for SNTI integration

### Phase 4 — Scale (H1 2027)
- [ ] **GPU mining optimization** — PoUW v2 GPU kernel (OpenCL/CUDA)
- [ ] **Smart contract layer** (research) — quantum-resistant VM using hash-based commitments
- [ ] **Institutional custody API** — HSM integration for enterprise key management
- [ ] **Government/CBDC partnerships** — target ASEAN fintech regulatory sandbox
- [ ] **Whitepaper v2 + academic submission** — IEEE/ACM blockchain conference

---

## Tokenomics

| Parameter | Value |
|-----------|-------|
| Ticker | SNTI |
| Block reward | 50 SNTI |
| Block time target | 60 seconds |
| Halving interval | 2,100,000 blocks (~4 years) |
| Max supply | 210,000,000 SNTI |
| Mining | CPU PoUW v2 (XMSS) |
| Consensus | PoUW v2 — EMA difficulty |

**Rationale**: Same emission curve as Bitcoin, but mining produces quantum-resistant cryptographic artifacts. Early miners secure the network AND build the post-quantum key infrastructure.

---

## Security Model

### What has been audited internally
- XMSS Merkle tree construction and verification
- Leaf index reuse protection (on-chain tracking, SNTI M7)
- EMA difficulty calculation (overflow fix June 28, 2026)
- BIP141/SegWit compatibility
- Multi-node consensus testing
- XMSS private key persistence

### Planned external audit
- Scope: consensus layer, XMSS integration, leaf tracking
- Target firms: Trail of Bits, Halborn, Least Authority
- Budget: $20,000–$100,000
- Timeline: Q4 2026 (post-Phase 2)

---

## Team

**Asep Mulya** — Founder & Lead Developer
- Built Assentian-PQE from scratch on Bitcoin Core fork
- Deep expertise: XMSS cryptography, Bitcoin internals, post-quantum protocol design
- Contact: admin@assentian.network

---

## Investment Thesis Summary

> The quantum threat to blockchain is real, documented, and on a 5-10 year timeline.
> Every day that Bitcoin and Ethereum remain on ECDSA is one day closer to a catastrophic
> global cryptographic failure. SNTI is not a hedge — it is the solution.
>
> As the world's first blockchain with quantum resistance enforced at both the signature
> layer AND the consensus layer, SNTI occupies a unique and defensible position.
> Early investors in SNTI are not just buying a coin — they are buying the infrastructure
> for post-quantum finance.

---

## Contact

- Website: https://assentian.network
- Explorer: https://assentian.network/explorer/
- GitHub: https://github.com/assentian-network/snti
- Email: assentianpqe@gmail.com

---

*This document is for informational purposes. SNTI is a new blockchain in early mainnet stage.
All roadmap timelines are estimates. Do your own research.*
