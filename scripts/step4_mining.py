#!/usr/bin/env python3
"""
Step 4: Ganti SHA-256 nonce grinding dengan XMSS tree search di rpc/mining.cpp
- Hapus old PoUW v1 XMSS signing (sekarang masuk ke tree search)
- Ganti while(nNonce++) dengan while(BuildXMSSTree(seed++))
- Set block.xmssRoot = root, block.nNonce = 0
Jalankan dari: ~/Assentian-PQE/SNTI
"""
import sys, os

MINING_CPP = "src/rpc/mining.cpp"

def patch_mining(content):

    # ── PATCH 1: Tambah include pouw_v2.h ────────────────────────────────
    MARKER1 = "// SNTI PoUW v2 include"
    if MARKER1 not in content:
        # Cari include xmss_bridge.h yang sudah ada
        old1 = "// SNTI: PoUW mining"
        new1 = "// SNTI: PoUW mining\n// SNTI PoUW v2 include\n#include <pouw_v2.h>"
        if old1 not in content:
            print("[ERROR] Target Patch 1 tidak ditemukan")
            return None
        content = content.replace(old1, new1)
        print("[OK] Patch 1: include pouw_v2.h")

    # ── PATCH 2: Ganti GenerateBlock() — hapus PoUW v1, tambah v2 ────────
    MARKER2 = "// SNTI PoUW v2: XMSS tree search mining loop"
    if MARKER2 not in content:
        # Target: seluruh blok dari "// SNTI: PoUW" sampai akhir nNonce loop
        old2 = (
            '    // SNTI: PoUW — Generate XMSS key pair for this block\n'
            '    // The "useful work" is generating an XMSS key pair (~1-2 seconds on CPU)\n'
            '    XMSS::CXMSSKey miner_key;\n'
            '    std::vector<uint8_t> xmss_pk;\n'
            '    bool pouw_active = chainman.GetConsensus().fPoUW;\n'
        )
        if old2 not in content:
            print("[ERROR] Target Patch 2 header tidak ditemukan")
            probe = "SNTI: PoUW"
            if probe in content:
                idx = content.index(probe)
                print(f"  [DEBUG] at {idx}:")
                print(repr(content[idx:idx+150]))
            return None

        # Cari end marker — baris setelah nNonce loop
        end_marker = (
            '    if (max_tries == 0 || chainman.m_interrupt) {\n'
            '        return false;\n'
            '    }\n'
            '    if (block.nNonce == std::numeric_limits<uint32_t>::max()) {\n'
            '        return true;\n'
            '    }'
        )
        if end_marker not in content:
            print("[ERROR] End marker (nNonce check) tidak ditemukan")
            return None

        # Cari posisi old2 dan end_marker
        start_pos = content.index(old2)
        end_pos = content.index(end_marker) + len(end_marker)
        old_block = content[start_pos:end_pos]

        new_block = (
            '    // SNTI PoUW v2: XMSS tree search mining loop\n'
            '    // Miner searches SK_SEED (96 bytes) until XMSS root < target\n'
            '    // No SHA-256 nonce — XMSS tree building IS the proof of work\n'
            '    {\n'
            '        // Initialize seed from block fields for determinism\n'
            '        uint8_t seed[PoUWv2::SEED_BYTES];\n'
            '        {\n'
            '            // seed = SHA256(hashPrevBlock || nTime || nBits || counter)\n'
            '            // We use GetRandBytes for initial seed, then increment counter\n'
            '            GetRandBytes({seed, PoUWv2::SEED_BYTES});\n'
            '        }\n'
            '\n'
            '        uint64_t attempt = 0;\n'
            '        PoUWv2::PoUWv2Proof proof;\n'
            '\n'
            '        // Preimage = data that XMSS signs (block header fields without xmssRoot)\n'
            '        uint256 preimage_hash;\n'
            '        {\n'
            '            HashWriter hw{};\n'
            '            hw << block.nVersion << block.hashPrevBlock\n'
            '               << block.hashMerkleRoot << block.nTime << block.nBits;\n'
            '            preimage_hash = hw.GetHash();\n'
            '        }\n'
            '\n'
            '        arith_uint256 target;\n'
            '        target.SetCompact(block.nBits);\n'
            '\n'
            '        LogPrintf("PoUW v2: starting XMSS tree search (target=%s)\\n",\n'
            '                  ArithToUint256(target).GetHex().substr(0, 16));\n'
            '\n'
            '        while (max_tries > 0 && !chainman.m_interrupt) {\n'
            '            // Build XMSS tree from current seed\n'
            '            if (!PoUWv2::BuildAndSign(seed, preimage_hash.begin(), proof)) {\n'
            '                LogPrintf("PoUW v2: BuildAndSign failed at attempt %llu\\n", attempt);\n'
            '                break;\n'
            '            }\n'
            '\n'
            '            // Check if root < target\n'
            '            uint256 root = proof.GetRoot();\n'
            '            if (UintToArith256(root) <= target) {\n'
            '                // Found valid block!\n'
            '                block.xmssRoot = root;\n'
            '                block.nNonce   = 0; // nNonce unused in PoUW v2\n'
            '\n'
            '                // Embed PoUW v2 proof into coinbase OP_RETURN\n'
            '                std::vector<uint8_t> proof_bytes = proof.Serialize();\n'
            '                CMutableTransaction coinbase(*block.vtx[0]);\n'
            '                CScript proof_script;\n'
            '                proof_script << OP_RETURN << proof_bytes;\n'
            '                coinbase.vout.push_back(CTxOut(0, proof_script));\n'
            '                block.vtx[0] = MakeTransactionRef(std::move(coinbase));\n'
            '                block.hashMerkleRoot = BlockMerkleRoot(block);\n'
            '\n'
            '                LogPrintf("PoUW v2: found valid block! root=%s attempt=%llu\\n",\n'
            '                          root.GetHex().substr(0, 16), attempt);\n'
            '                break;\n'
            '            }\n'
            '\n'
            '            // Increment seed (treat as 96-byte big integer, increment byte 95)\n'
            '            for (int i = PoUWv2::SEED_BYTES - 1; i >= 0; i--) {\n'
            '                if (++seed[i] != 0) break;\n'
            '            }\n'
            '            ++attempt;\n'
            '            --max_tries;\n'
            '\n'
            '            if (attempt % 10 == 0) {\n'
            '                LogPrintf("PoUW v2: attempt %llu, last_root=%s\\n",\n'
            '                          attempt, proof.GetRoot().GetHex().substr(0, 16));\n'
            '            }\n'
            '        }\n'
            '\n'
            '        if (block.xmssRoot.IsNull()) {\n'
            '            // No valid block found\n'
            '            return (chainman.m_interrupt ? false : false);\n'
            '        }\n'
            '    }'
        )

        content = content[:start_pos] + new_block + content[end_pos:]
        print("[OK] Patch 2: SHA-256 nonce loop → XMSS tree search")

    # ── PATCH 3: Update rpc/mining.cpp CheckProofOfWork call ─────────────
    MARKER3 = "// SNTI PoUW v2: submitblock uses xmssRoot"
    if MARKER3 not in content:
        old3 = '           && !CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus())'
        new3 = '           // SNTI PoUW v2: submitblock uses xmssRoot\n           && !CheckProofOfWork(block.xmssRoot, block.nBits, chainman.GetConsensus())'
        if old3 in content:
            content = content.replace(old3, new3)
            print("[OK] Patch 3: submitblock CheckProofOfWork → xmssRoot")
        else:
            print("[WARN] Patch 3 target tidak ditemukan — skip")

    return content

def main():
    path = MINING_CPP
    if not os.path.exists(path):
        print(f"[ERROR] {path} tidak ditemukan")
        sys.exit(1)
    with open(path) as f:
        content = f.read()
    original = content
    content = patch_mining(content)
    if content is None:
        print("[FAILED]")
        sys.exit(1)
    if content != original:
        with open(path + ".bak_v2", 'w') as f:
            f.write(original)
        with open(path, 'w') as f:
            f.write(content)
        print(f"[DONE] {path}")
    else:
        print(f"[INFO] tidak ada perubahan")

if __name__ == "__main__":
    main()
