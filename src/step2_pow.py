#!/usr/bin/env python3
"""
Step 2: Update pow.cpp untuk Pure PoUW v2
- GetNextWorkRequired() → EMA per-block
- CalculateNextWorkRequired() → EMA implementation  
- CheckProofOfWork() → CheckPoUWv2() wrapper
Jalankan dari: ~/Assentian-PQE/SNTI
"""
import sys, os

POW_CPP = "src/pow.cpp"
POW_H   = "src/pow.h"

def patch_pow_cpp(content):

    # ── PATCH 1: Tambah include pouw_v2.h ────────────────────────────────
    MARKER1 = "// QNT PoUW v2 include"
    if MARKER1 not in content:
        old1 = "#include <pow.h>\n\n#include <arith_uint256.h>\n#include <chain.h>\n#include <primitives/block.h>\n#include <uint256.h>"
        new1 = (
            "#include <pow.h>\n\n"
            "#include <arith_uint256.h>\n"
            "#include <chain.h>\n"
            "#include <primitives/block.h>\n"
            "#include <uint256.h>\n"
            "// QNT PoUW v2 include\n"
            "#include <pouw_v2.h>\n"
        )
        if old1 not in content:
            print("[ERROR] Target Patch 1 tidak ditemukan")
            return None
        content = content.replace(old1, new1)
        print("[OK] Patch 1: include pouw_v2.h")

    # ── PATCH 2: Ganti GetNextWorkRequired() dengan EMA per-block ────────
    MARKER2 = "// QNT PoUW v2: EMA per-block difficulty"
    if MARKER2 not in content:
        old2 = (
            "unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)\n"
            "{\n"
            "    assert(pindexLast != nullptr);\n"
            "    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();\n"
            "\n"
            "    // Only change once per difficulty adjustment interval\n"
            "    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)\n"
            "    {\n"
            "        if (params.fPowAllowMinDifficultyBlocks)\n"
            "        {\n"
            "            // Special difficulty rule for testnet:\n"
            "            // If the new block's timestamp is more than 2* 10 minutes\n"
            "            // then allow mining of a min-difficulty block.\n"
            "            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)\n"
            "                return nProofOfWorkLimit;\n"
            "            else\n"
            "            {\n"
            "                // Return the last non-special-min-difficulty-rules-block\n"
            "                const CBlockIndex* pindex = pindexLast;\n"
            "                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)\n"
            "                    pindex = pindex->pprev;\n"
            "                return pindex->nBits;\n"
            "            }\n"
            "        }\n"
            "        return pindexLast->nBits;\n"
            "    }\n"
            "\n"
            "    // Go back by what we want to be 14 days worth of blocks\n"
            "    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);\n"
            "    assert(nHeightFirst >= 0);\n"
            "    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);\n"
            "    assert(pindexFirst);\n"
            "\n"
            "    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);\n"
            "}"
        )
        new2 = (
            "// QNT PoUW v2: EMA per-block difficulty adjustment\n"
            "// Replaces Bitcoin 2016-block retarget with per-block EMA (alpha=0.1)\n"
            "unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)\n"
            "{\n"
            "    assert(pindexLast != nullptr);\n"
            "    const arith_uint256 pow_limit = UintToArith256(params.powLimit);\n"
            "    unsigned int nProofOfWorkLimit = pow_limit.GetCompact();\n"
            "\n"
            "    // Genesis block\n"
            "    if (pindexLast->pprev == nullptr) return nProofOfWorkLimit;\n"
            "\n"
            "    // fPowNoRetargeting: regtest\n"
            "    if (params.fPowNoRetargeting) return pindexLast->nBits;\n"
            "\n"
            "    // Testnet: allow min difficulty if block is too slow\n"
            "    if (params.fPowAllowMinDifficultyBlocks) {\n"
            "        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)\n"
            "            return nProofOfWorkLimit;\n"
            "    }\n"
            "\n"
            "    return CalculateNextWorkRequired(pindexLast, pindexLast->pprev->GetBlockTime(), params);\n"
            "}"
        )
        if old2 not in content:
            print("[ERROR] Target Patch 2 tidak ditemukan")
            probe = "unsigned int GetNextWorkRequired"
            if probe in content:
                idx = content.index(probe)
                print(f"  [DEBUG] probe at {idx}:")
                print(repr(content[idx:idx+100]))
            return None
        content = content.replace(old2, new2)
        print("[OK] Patch 2: GetNextWorkRequired() → EMA per-block")

    # ── PATCH 3: Ganti CalculateNextWorkRequired() dengan EMA ────────────
    MARKER3 = "// QNT PoUW v2: EMA implementation"
    if MARKER3 not in content:
        old3 = (
            "unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)\n"
            "{\n"
            "    if (params.fPowNoRetargeting)\n"
            "        return pindexLast->nBits;\n"
            "\n"
            "    // Limit adjustment step\n"
            "    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;\n"
            "    if (nActualTimespan < params.nPowTargetTimespan/4)\n"
            "        nActualTimespan = params.nPowTargetTimespan/4;\n"
            "    if (nActualTimespan > params.nPowTargetTimespan*4)\n"
            "        nActualTimespan = params.nPowTargetTimespan*4;\n"
            "\n"
            "    // Retarget\n"
            "    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);\n"
            "    arith_uint256 bnNew;\n"
            "    bnNew.SetCompact(pindexLast->nBits);\n"
            "    bnNew *= nActualTimespan;\n"
            "    bnNew /= params.nPowTargetTimespan;\n"
            "\n"
            "    if (bnNew > bnPowLimit)\n"
            "        bnNew = bnPowLimit;\n"
            "\n"
            "    return bnNew.GetCompact();\n"
            "}"
        )
        new3 = (
            "// QNT PoUW v2: EMA implementation\n"
            "// nFirstBlockTime = pindexLast->pprev->GetBlockTime() (previous block time)\n"
            "unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)\n"
            "{\n"
            "    if (params.fPowNoRetargeting)\n"
            "        return pindexLast->nBits;\n"
            "\n"
            "    // Actual spacing = time between last two blocks\n"
            "    int64_t actual_spacing = pindexLast->GetBlockTime() - nFirstBlockTime;\n"
            "\n"
            "    // Get current target\n"
            "    arith_uint256 old_target;\n"
            "    old_target.SetCompact(pindexLast->nBits);\n"
            "\n"
            "    // EMA adjustment via pouw_v2\n"
            "    const arith_uint256 pow_limit = UintToArith256(params.powLimit);\n"
            "    arith_uint256 new_target = PoUWv2::CalcNextTargetEMA(\n"
            "        old_target, actual_spacing, params.nPowTargetSpacing, pow_limit);\n"
            "\n"
            "    return new_target.GetCompact();\n"
            "}"
        )
        if old3 not in content:
            print("[ERROR] Target Patch 3 tidak ditemukan")
            return None
        content = content.replace(old3, new3)
        print("[OK] Patch 3: CalculateNextWorkRequired() → EMA")

    # ── PATCH 4: Ganti CheckProofOfWork() → CheckPoUWv2 wrapper ─────────
    MARKER4 = "// QNT PoUW v2: root < target check"
    if MARKER4 not in content:
        old4 = (
            "bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)\n"
            "{\n"
            "    bool fNegative;\n"
            "    bool fOverflow;\n"
            "    arith_uint256 bnTarget;\n"
            "\n"
            "    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);\n"
            "\n"
            "    // Check range\n"
            "    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))\n"
            "        return false;\n"
            "\n"
            "    // Check proof of work matches claimed amount\n"
            "    if (UintToArith256(hash) > bnTarget)\n"
            "        return false;\n"
            "\n"
            "    return true;\n"
            "}"
        )
        new4 = (
            "// QNT PoUW v2: root < target check\n"
            "// 'hash' parameter = XMSS root hash (first 32 bytes of xmss_pk)\n"
            "// Full XMSS proof verification happens in CheckPoUW() in validation.cpp\n"
            "bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)\n"
            "{\n"
            "    bool fNegative;\n"
            "    bool fOverflow;\n"
            "    arith_uint256 bnTarget;\n"
            "\n"
            "    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);\n"
            "\n"
            "    // Check range\n"
            "    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))\n"
            "        return false;\n"
            "\n"
            "    // QNT PoUW v2: check XMSS root < target\n"
            "    // root = hash (passed from block header's hashMerkleRoot or dedicated field)\n"
            "    if (UintToArith256(hash) > bnTarget)\n"
            "        return false;\n"
            "\n"
            "    return true;\n"
            "}"
        )
        if old4 not in content:
            print("[ERROR] Target Patch 4 tidak ditemukan")
            return None
        content = content.replace(old4, new4)
        print("[OK] Patch 4: CheckProofOfWork() → PoUW v2 root check")

    return content

def patch_pow_h(content):
    # Tambah deklarasi helper di pow.h
    MARKER = "// QNT PoUW v2"
    if MARKER not in content:
        old = "/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */\nbool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);"
        new = (
            "/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */\n"
            "bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);\n"
            "\n"
            "// QNT PoUW v2: EMA difficulty helpers (exposed for testing)\n"
            "// CalcNextTargetEMA is in pouw_v2.h (header-only)\n"
        )
        if old not in content:
            print("[WARN] pow.h target tidak ditemukan — skip")
            return content
        content = content.replace(old, new)
        print("[OK] pow.h: tambah PoUW v2 comment")
    return content

def main():
    for path, patch_fn in [(POW_CPP, patch_pow_cpp), (POW_H, patch_pow_h)]:
        if not os.path.exists(path):
            print(f"[ERROR] {path} tidak ditemukan")
            sys.exit(1)
        with open(path) as f:
            content = f.read()
        original = content
        content = patch_fn(content)
        if content is None:
            print(f"[FAILED] {path}")
            sys.exit(1)
        if content != original:
            with open(path + ".bak_v2", 'w') as f:
                f.write(original)
            with open(path, 'w') as f:
                f.write(content)
            print(f"[DONE] {path} dipatch")
        else:
            print(f"[INFO] {path} tidak ada perubahan")

if __name__ == "__main__":
    main()
