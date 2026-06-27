#!/usr/bin/env python3
"""
PoUW v2 Key Derivation — Patch Script
1. block.h: tambah commitmentsRoot field
2. mining.cpp: collect failed seeds, embed di coinbase, set commitmentsRoot
3. validation.cpp: verify commitmentsRoot + derive wallet keys di ConnectBlock
Jalankan dari: ~/Assentian-PQE/SNTI
"""
import sys, os

BLOCK_H    = "src/primitives/block.h"
MINING_CPP = "src/rpc/mining.cpp"
VAL_CPP    = "src/validation.cpp"

def patch_block_h(content):
    MARKER = "// SNTI PoUW v2: commitmentsRoot field"
    if MARKER in content:
        print("[SKIP] block.h sudah dipatch")
        return content

    old = (
        "    uint256 xmssRoot;\n"
        "\n"
        "    CBlockHeader()\n"
        "    {\n"
        "        SetNull();\n"
        "    }\n"
        "\n"
        "    // QNT PoUW v2: xmssRoot included in serialization\n"
        "    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.xmssRoot); }\n"
        "\n"
        "    void SetNull()\n"
        "    {\n"
        "        nVersion = 0;\n"
        "        hashPrevBlock.SetNull();\n"
        "        hashMerkleRoot.SetNull();\n"
        "        nTime = 0;\n"
        "        nBits = 0;\n"
        "        nNonce = 0;\n"
        "        xmssRoot.SetNull();\n"
        "    }"
    )
    new = (
        "    uint256 xmssRoot;\n"
        "    // SNTI PoUW v2: commitmentsRoot field\n"
        "    // Merkle root of 10-20 failed SK_SEED commitments\n"
        "    // Binds failed-seed key derivation to this block cryptographically\n"
        "    uint256 commitmentsRoot;\n"
        "\n"
        "    CBlockHeader()\n"
        "    {\n"
        "        SetNull();\n"
        "    }\n"
        "\n"
        "    // SNTI PoUW v2: xmssRoot + commitmentsRoot in serialization\n"
        "    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.xmssRoot, obj.commitmentsRoot); }\n"
        "\n"
        "    void SetNull()\n"
        "    {\n"
        "        nVersion = 0;\n"
        "        hashPrevBlock.SetNull();\n"
        "        hashMerkleRoot.SetNull();\n"
        "        nTime = 0;\n"
        "        nBits = 0;\n"
        "        nNonce = 0;\n"
        "        xmssRoot.SetNull();\n"
        "        commitmentsRoot.SetNull();\n"
        "    }"
    )
    if old not in content:
        print("[ERROR] block.h target tidak ditemukan")
        idx = content.find("uint256 xmssRoot;")
        print(repr(content[idx:idx+200]))
        return None
    content = content.replace(old, new)

    # Update GetBlockHeader() copy
    old2 = (
        "        // SNTI PoUW v2: copy xmssRoot\n"
        "        block.xmssRoot       = xmssRoot;\n"
        "        return block;"
    )
    new2 = (
        "        // SNTI PoUW v2: copy xmssRoot + commitmentsRoot\n"
        "        block.xmssRoot         = xmssRoot;\n"
        "        block.commitmentsRoot  = commitmentsRoot;\n"
        "        return block;"
    )
    if old2 in content:
        content = content.replace(old2, new2)
        print("[OK] block.h: commitmentsRoot field + GetBlockHeader()")
    else:
        print("[WARN] GetBlockHeader copy tidak ditemukan — skip")
        print("[OK] block.h: commitmentsRoot field")
    return content

def patch_mining(content):
    MARKER = "// SNTI PoUW v2: collect failed seeds"
    if MARKER in content:
        print("[SKIP] mining.cpp sudah dipatch")
        return content

    # Tambah include
    old_inc = "// SNTI PoUW v2 include\n#include <pouw_v2.h>"
    new_inc = "// SNTI PoUW v2 include\n#include <pouw_v2.h>\n#include <pouw_v2_keyder.h>"
    if old_inc in content:
        content = content.replace(old_inc, new_inc)
        print("[OK] mining.cpp: include pouw_v2_keyder.h")
    else:
        print("[WARN] include target tidak ditemukan")

    # Tambah failed seed collection di mining loop
    old_loop = (
        "        uint64_t attempt = 0; // note: wraps at 2^64 intentionally\n"
        "        PoUWv2::PoUWv2Proof proof;"
    )
    new_loop = (
        "        uint64_t attempt = 0; // note: wraps at 2^64 intentionally\n"
        "        PoUWv2::PoUWv2Proof proof;\n"
        "        // SNTI PoUW v2: collect failed seeds for key derivation\n"
        "        PoUWv2KeyDer::FailedSeedList failed_seeds;\n"
        "        failed_seeds.block_height = (uint32_t)(pindexPrev ? pindexPrev->nHeight + 1 : 1);"
    )
    if old_loop in content:
        content = content.replace(old_loop, new_loop)
        print("[OK] mining.cpp: FailedSeedList init")
    else:
        print("[ERROR] mining loop target tidak ditemukan")
        return None

    # Collect failed seeds setelah root > target check
    old_fail = (
        '            // Increment seed (treat as 96-byte big integer, increment byte 95)\n'
        '            for (int i = PoUWv2::SEED_BYTES - 1; i >= 0; i--) {\n'
        '                if (++seed[i] != 0) break;\n'
        '            }\n'
        '            ++attempt;\n'
        '            --max_tries;'
    )
    new_fail = (
        '            // SNTI PoUW v2: collect failed seeds (sample every ~N attempts)\n'
        '            if (failed_seeds.entries.size() < PoUWv2KeyDer::MAX_FAILED_SEEDS) {\n'
        '                // Sample: collect first 20 failed seeds\n'
        '                uint256 failed_root = proof.GetRoot();\n'
        '                failed_seeds.AddFailedSeed(seed, failed_root.begin(), failed_seeds.block_height);\n'
        '            }\n'
        '            // Increment seed\n'
        '            for (int i = PoUWv2::SEED_BYTES - 1; i >= 0; i--) {\n'
        '                if (++seed[i] != 0) break;\n'
        '            }\n'
        '            ++attempt;\n'
        '            --max_tries;'
    )
    if old_fail in content:
        content = content.replace(old_fail, new_fail)
        print("[OK] mining.cpp: collect failed seeds")
    else:
        print("[ERROR] failed seed collection target tidak ditemukan")
        return None

    # Set commitmentsRoot dan embed seeds di coinbase setelah block found
    old_found = (
        '                LogPrintf("PoUW v2: found valid block! root=%s attempt=%llu\\n",\n'
        '                          root.GetHex().substr(0, 16), attempt);\n'
        '                break;'
    )
    new_found = (
        '                LogPrintf("PoUW v2: found valid block! root=%s attempt=%llu\\n",\n'
        '                          root.GetHex().substr(0, 16), attempt);\n'
        '\n'
        '                // SNTI PoUW v2: embed failed seeds + set commitmentsRoot\n'
        '                if (failed_seeds.entries.size() >= PoUWv2KeyDer::MIN_FAILED_SEEDS) {\n'
        '                    // Compute Merkle root of commitments\n'
        '                    block.commitmentsRoot = failed_seeds.ComputeMerkleRoot();\n'
        '\n'
        '                    // Embed failed seed list in coinbase OP_RETURN\n'
        '                    std::vector<uint8_t> seeds_bytes = failed_seeds.Serialize();\n'
        '                    CMutableTransaction coinbase_seeds(*block.vtx[0]);\n'
        '                    CScript seeds_script;\n'
        '                    seeds_script << OP_RETURN << seeds_bytes;\n'
        '                    coinbase_seeds.vout.push_back(CTxOut(0, seeds_script));\n'
        '                    block.vtx[0] = MakeTransactionRef(std::move(coinbase_seeds));\n'
        '                    block.hashMerkleRoot = BlockMerkleRoot(block);\n'
        '                    LogPrintf("PoUW v2: embedded %zu failed seeds, commitmentsRoot=%s\\n",\n'
        '                              failed_seeds.entries.size(),\n'
        '                              block.commitmentsRoot.GetHex().substr(0, 16));\n'
        '                }\n'
        '                break;'
    )
    if old_found in content:
        content = content.replace(old_found, new_found)
        print("[OK] mining.cpp: embed failed seeds + commitmentsRoot")
    else:
        print("[ERROR] found block target tidak ditemukan")
        return None

    return content

def patch_validation(content):
    MARKER = "// SNTI PoUW v2: verify commitmentsRoot"
    if MARKER in content:
        print("[SKIP] validation.cpp sudah dipatch")
        return content

    # Tambah include
    old_inc = "// SNTI: XMSS PoUW verification\n#include <xmss_bridge.h>\n#include <pouw_v2.h>"
    new_inc = "// SNTI: XMSS PoUW verification\n#include <xmss_bridge.h>\n#include <pouw_v2.h>\n#include <pouw_v2_keyder.h>"
    if old_inc in content:
        content = content.replace(old_inc, new_inc)
        print("[OK] validation.cpp: include pouw_v2_keyder.h")
    else:
        print("[WARN] validation.cpp include target tidak ditemukan")

    # Tambah verification di ConnectBlock setelah mark leaf index
    old_conn = (
        '    // SNTI PoUW v2: mark PoUW leaf index as used\n'
        '    if (!fJustCheck && m_chainman.GetParams().GetConsensus().fPoUW) {'
    )
    new_conn = (
        '    // SNTI PoUW v2: verify commitmentsRoot + derive wallet keys\n'
        '    if (!fJustCheck && !block.commitmentsRoot.IsNull()) {\n'
        '        // Extract failed seed list from coinbase\n'
        '        const CTransaction& cbTx2 = *block.vtx[0];\n'
        '        PoUWv2KeyDer::FailedSeedList fsl;\n'
        '        bool fsl_found = false;\n'
        '        for (const auto& out : cbTx2.vout) {\n'
        '            const CScript& s = out.scriptPubKey;\n'
        '            CScript::const_iterator pc = s.begin();\n'
        '            opcodetype opc; std::vector<uint8_t> d;\n'
        '            if (!s.GetOp(pc, opc, d)) continue;\n'
        '            if (opc != OP_RETURN) continue;\n'
        '            if (!s.GetOp(pc, opc, d)) continue;\n'
        '            if (d.size() >= 9 && d[0]==\'F\' && d[1]==\'S\' && d[2]==\'L\' && d[3]==0x01) {\n'
        '                if (fsl.Deserialize(d.data(), d.size())) {\n'
        '                    fsl_found = true;\n'
        '                    break;\n'
        '                }\n'
        '            }\n'
        '        }\n'
        '        if (fsl_found) {\n'
        '            // Verify Merkle root matches header\n'
        '            if (!fsl.VerifyAgainstHeader(block.commitmentsRoot)) {\n'
        '                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,\n'
        '                    "pouw-commitments-mismatch",\n'
        '                    "PoUW v2: commitmentsRoot does not match seed list");\n'
        '            }\n'
        '            LogPrint(BCLog::VALIDATION, "PoUW v2: commitmentsRoot verified (%zu seeds)\\n",\n'
        '                     fsl.entries.size());\n'
        '            // Derive wallet keys — stored for later wallet claim\n'
        '            // (wallet integration TODO: register keys with miner wallet)\n'
        '            auto wallet_keys = fsl.DeriveWalletKeys();\n'
        '            LogPrint(BCLog::VALIDATION, "PoUW v2: derived %zu wallet keys from failed seeds\\n",\n'
        '                     wallet_keys.size());\n'
        '        }\n'
        '    }\n'
        '\n'
        '    // SNTI PoUW v2: mark PoUW leaf index as used\n'
        '    if (!fJustCheck && m_chainman.GetParams().GetConsensus().fPoUW) {'
    )
    if old_conn in content:
        content = content.replace(old_conn, new_conn)
        print("[OK] validation.cpp: verify commitmentsRoot + derive keys")
    else:
        print("[ERROR] validation.cpp ConnectBlock target tidak ditemukan")
        probe = "SNTI PoUW v2: mark PoUW leaf index"
        if probe in content:
            idx = content.index(probe)
            print(repr(content[idx-50:idx+100]))
        return None

    return content

def main():
    patches = [
        (BLOCK_H,    patch_block_h),
        (MINING_CPP, patch_mining),
        (VAL_CPP,    patch_validation),
    ]
    for path, fn in patches:
        if not os.path.exists(path):
            print(f"[ERROR] {path} tidak ditemukan")
            sys.exit(1)
        with open(path) as f:
            content = f.read()
        original = content
        result = fn(content)
        if result is None:
            print(f"[FAILED] {path}")
            sys.exit(1)
        content = result
        if content != original:
            with open(path + ".bak_keyder", 'w') as f:
                f.write(original)
            with open(path, 'w') as f:
                f.write(content)
            print(f"[DONE] {path}")
        else:
            print(f"[INFO] {path} tidak ada perubahan")

if __name__ == "__main__":
    main()
