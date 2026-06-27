#!/usr/bin/env python3
import sys

content = open("WHITEPAPER.md").read()

old = (
    "## 7. Proof-of-Useful-Work\n"
    "### 7.1 How PoUW Works\n"
    "Step 1: Miner generates XMSS key pair (one-time setup)\n"
    "\u2514\u2500\u2500 XMSS-SHA2_10_256: 64-byte pubkey, 2,500-byte sig capacity\n"
)

if old not in content:
    # Try simpler search
    idx = content.find("## 7. Proof-of-Useful-Work")
    end = content.find("## 8. Security Model")
    if idx == -1:
        print("Section 7 not found!")
        sys.exit(1)
    old_section = content[idx:end]
    print(f"Found section at {idx}:{end}, length={len(old_section)}")
    # Just replace the whole section
    new_section = """## 7. Proof-of-Useful-Work
### 7.1 PoUW v2 \u2014 Pure XMSS Tree Building (Live since Jun 24, 2026)

**SHA-256 nonce search has been completely removed.** Building the XMSS Merkle tree IS the proof of work.

#### How PoUW v2 Works

Step 1: Miner generates random SK_SEED (96 bytes) \u2014 this is the "nonce"

Step 2: Miner builds full XMSS tree (height=10, 1024 leaves)
- Uses `xmssmt_core_seed_keypair(SK_SEED)` \u2014 deterministic tree build
- Cost: ~6 seconds per attempt on Intel Xeon @ 2.5GHz
- Output: `xmssRoot` = Merkle root hash (32 bytes)

Step 3: Check if `xmssRoot < target`
- YES \u2192 valid block! Sign and submit
- NO \u2192 increment SK_SEED, rebuild tree

Step 4: Sign block preimage with WOTS+ (leaf 0)
- `preimage = SHA256(nVersion || hashPrevBlock || nTime || nBits)`
- Embed `PoUWv2Proof` in coinbase OP_RETURN (2,660 bytes total)

Step 5: Submit block \u2014 node verifies:
- `block.xmssRoot < target` (PoW check)
- `PoUWv2Proof.Deserialize()` \u2014 extract proof components
- `CheckPoUWv2()` \u2014 verify root matches proof

#### Why This IS "Useful Work"

Every mining attempt produces a complete XMSS keypair with 1024 one-time signatures \u2014 directly useful post-quantum cryptographic material. Unlike SHA-256 which produces nothing of value, XMSS tree building:

- Generates quantum-resistant key material
- Advances global post-quantum cryptographic infrastructure
- Proves the miner performed real cryptographic computation

#### Difficulty & Performance

| Parameter | Value |
|---|---|
| Tree height | 10 (1024 leaves) |
| Build time (1 core) | ~6.17 seconds |
| Target attempts/block | 156 (4 cores \xd7 39/core) |
| Difficulty algorithm | EMA per-block (\u03b1=0.1) |
| powLimit | 2\u00b2\u2075\u2076 / 156 |
| Target block time | 60 seconds |
| Genesis nBits | 0x2001a41a |

#### PoUW v2 Proof Format (coinbase OP_RETURN, 2,660 bytes)

| Field | Size | Description |
|---|---|---|
| Magic | 4 bytes | `PW2\\x02` |
| SK_SEED | 96 bytes | SK_SEED + SK_PRF + PUB_SEED |
| xmss_pk | 64 bytes | root + PUB_SEED |
| auth_path | 320 bytes | 10 \xd7 32 bytes node hashes |
| wots_sig | 2144 bytes | WOTS+ signature |
| r | 32 bytes | signature randomness |

"""
    content = content[:idx] + new_section + content[end:]
    open("WHITEPAPER.md","w").write(content)
    print("DONE - section replaced")
else:
    print("Found old section via exact match")
