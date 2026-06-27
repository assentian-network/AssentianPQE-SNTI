#!/usr/bin/env python3
"""
Step 5: Update chainparams.cpp untuk Pure PoUW v2
Jalankan dari: ~/Assentian-PQE/SNTI
"""
import sys, os

CHAINPARAMS = "src/kernel/chainparams.cpp"

# powLimit = 2^256 / 156
POWLIMIT_HEX = "01a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a4"
NBITS_GENESIS = "0x2001a41a"
NTIME_GENESIS = 1782275807  # Jun 24 2026

def patch(content):

    # ── PATCH 1: Update comment PoUW v1 → v2 ────────────────────────────
    MARKER1 = "// SNTI PoUW v2: Pure XMSS Tree Building"
    if MARKER1 not in content:
        old1 = (
            " * Quant Mainnet — post-quantum XMSS signatures, SHA-256 PoW\n"
            " *\n"
            " * Aligned with WHITEPAPER v0.2 Section 9.2 Technical Specifications:\n"
            " *   - P2P Port:      9333  (QNT-specific port)\n"
            " *   - Genesis:       Dynamic on launch (see nTime below)\n"
            " *   - Block Time:    ~60 seconds (target)\n"
            " *   - Halving:       Every 210,000 blocks (~2 years at 60s/block)\n"
            " *   - Max Supply:    21,000,000 QNT\n"
            " *   - Address:       Base58 prefix Q/V, bech32m \"qn\"\n"
            " *   - Magic Bytes:   0x5155414E (\"QUAN\")\n"
            " *   - PoW:           SHA-256 with XMSS-signed blocks (PoUW v1)\n"
            " *\n"
            " * PoUW v1 approach:\n"
            " *   Miners do standard SHA-256 hash grinding (like Bitcoin).\n"
            " *   But block template includes XMSS public key, and the valid block\n"
            " *   must be signed by the miner's XMSS key. The signing IS the useful\n"
            " *   work that produces cryptographic material.\n"
            " */"
        )
        new1 = (
            " * Assentian-PQE Mainnet — Pure Post-Quantum Proof-of-Useful-Work\n"
            " *\n"
            " * SNTI PoUW v2: Pure XMSS Tree Building\n"
            " *   - P2P Port:      39333\n"
            " *   - Genesis:       Jun 24, 2026\n"
            " *   - Block Time:    ~60 seconds (EMA difficulty adjustment)\n"
            " *   - Halving:       Every 2,100,000 blocks (~4 years at 60s/block)\n"
            " *   - Max Supply:    21,000,000 SNTI\n"
            " *   - Address:       bech32m prefix \"qn\"\n"
            " *   - PoW:           Pure XMSS tree building (NO SHA-256 nonce)\n"
            " *\n"
            " * PoUW v2 approach:\n"
            " *   Miner searches SK_SEED (96 bytes) until XMSS root < target.\n"
            " *   Building the full XMSS tree (h=10, 1024 leaves) IS the work.\n"
            " *   block.xmssRoot = XMSS root hash, block.nNonce = 0 (unused).\n"
            " *   Difficulty adjusted per-block via EMA (alpha=0.1).\n"
            " *   powLimit = 2^256/156 (target: 156 attempts per block, 4 cores).\n"
            " */"
        )
        if old1 not in content:
            print("[ERROR] Target Patch 1 (comment) tidak ditemukan")
            return None
        content = content.replace(old1, new1)
        print("[OK] Patch 1: comment updated PoUW v1 → v2")

    # ── PATCH 2: powLimit baru ────────────────────────────────────────────
    MARKER2 = "// SNTI PoUW v2: powLimit = 2^256/156"
    if MARKER2 not in content:
        old2 = '        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");\n        // 60 second target (whitepaper section 6.3)\n        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks\n        consensus.nPowTargetSpacing = 60;  // 60 SECONDS (whitepaper)'
        new2 = (
            f'        // SNTI PoUW v2: powLimit = 2^256/156\n'
            f'        // Target: 1 of 156 XMSS trees valid per block (4 cores, 6.17s/tree, 60s block)\n'
            f'        consensus.powLimit = uint256S("{POWLIMIT_HEX}");\n'
            f'        // SNTI PoUW v2: EMA per-block — nPowTargetTimespan = nPowTargetSpacing\n'
            f'        consensus.nPowTargetTimespan = 60; // EMA uses per-block spacing\n'
            f'        consensus.nPowTargetSpacing = 60;  // 60 seconds target block time'
        )
        if old2 not in content:
            print("[ERROR] Target Patch 2 (powLimit) tidak ditemukan")
            probe = 'consensus.powLimit = uint256S("7fff'
            if probe in content:
                idx = content.index(probe)
                print(f"  [DEBUG] at {idx}:")
                print(repr(content[idx:idx+200]))
            return None
        content = content.replace(old2, new2)
        print("[OK] Patch 2: powLimit = 2^256/156, EMA timespan")

    # ── PATCH 3: Genesis baru ─────────────────────────────────────────────
    MARKER3 = "// SNTI PoUW v2: genesis"
    if MARKER3 not in content:
        old3 = (
            '        genesis = CreateGenesisBlock(1782026818, 26, 0x207fffff, 1, 50 * COIN);\n'
            '        consensus.hashGenesisBlock = uint256S("00146ebb6e8240633c4aef06ca3afbc6c26047f9c3ae5ce1548332a8de149263");'
        )
        new3 = (
            f'        // SNTI PoUW v2: genesis\n'
            f'        // nNonce=0 (unused in PoUW v2), nBits={NBITS_GENESIS}\n'
            f'        // xmssRoot will be computed by first miner — genesis is special case\n'
            f'        genesis = CreateGenesisBlock({NTIME_GENESIS}, 0, {NBITS_GENESIS}, 1, 50 * COIN);\n'
            f'        // hashGenesisBlock will be updated after first mine\n'
            f'        consensus.hashGenesisBlock = genesis.GetHash();'
        )
        if old3 not in content:
            print("[ERROR] Target Patch 3 (genesis) tidak ditemukan")
            probe = "genesis = CreateGenesisBlock(1782026818"
            if probe in content:
                idx = content.index(probe)
                print(f"  [DEBUG] at {idx}:")
                print(repr(content[idx:idx+200]))
            return None
        content = content.replace(old3, new3)
        print("[OK] Patch 3: genesis baru nTime={NTIME_GENESIS}, nBits={NBITS_GENESIS}")

    # ── PATCH 4: Update chainTxData timestamp ────────────────────────────
    MARKER4 = "// SNTI PoUW v2: chainTxData"
    if MARKER4 not in content:
        old4 = (
            '        chainTxData = ChainTxData{\n'
            '            .nTime    = 1781545300,\n'
            '            .nTxCount = 1,\n'
            '            .dTxRate  = 0,\n'
            '        };'
        )
        new4 = (
            f'        // SNTI PoUW v2: chainTxData\n'
            f'        chainTxData = ChainTxData{{\n'
            f'            .nTime    = {NTIME_GENESIS},\n'
            f'            .nTxCount = 1,\n'
            f'            .dTxRate  = 0,\n'
            f'        }};'
        )
        if old4 not in content:
            print("[WARN] chainTxData target tidak ditemukan — skip")
        else:
            content = content.replace(old4, new4)
            print("[OK] Patch 4: chainTxData timestamp updated")

    return content

def main():
    if not os.path.exists(CHAINPARAMS):
        print(f"[ERROR] {CHAINPARAMS} tidak ditemukan")
        sys.exit(1)
    with open(CHAINPARAMS) as f:
        content = f.read()
    original = content
    content = patch(content)
    if content is None:
        print("[FAILED]")
        sys.exit(1)
    if content != original:
        with open(CHAINPARAMS + ".bak_v2", 'w') as f:
            f.write(original)
        with open(CHAINPARAMS, 'w') as f:
            f.write(content)
        print(f"\n[DONE] {CHAINPARAMS} dipatch")
    else:
        print("[INFO] tidak ada perubahan")

if __name__ == "__main__":
    main()
