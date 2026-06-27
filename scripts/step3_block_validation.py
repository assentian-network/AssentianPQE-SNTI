#!/usr/bin/env python3
"""
Step 3: Pure PoUW v2 — Block header + validation changes
1. src/primitives/block.h  — tambah xmssRoot field, ganti nNonce → 0
2. src/primitives/block.cpp — update GetHash() dan ToString()
3. src/validation.cpp      — CheckBlockHeader() pakai xmssRoot
Jalankan dari: ~/Assentian-PQE/SNTI
"""
import sys, os

BLOCK_H   = "src/primitives/block.h"
BLOCK_CPP = "src/primitives/block.cpp"
VAL_CPP   = "src/validation.cpp"

def patch_block_h(content):

    # ── PATCH 1: Tambah xmssRoot field dan update SERIALIZE ──────────────
    MARKER1 = "// QNT PoUW v2: xmssRoot field"
    if MARKER1 not in content:
        old1 = (
            "    // header\n"
            "    int32_t nVersion;\n"
            "    uint256 hashPrevBlock;\n"
            "    uint256 hashMerkleRoot;\n"
            "    uint32_t nTime;\n"
            "    uint32_t nBits;\n"
            "    uint32_t nNonce;\n"
            "\n"
            "    CBlockHeader()\n"
            "    {\n"
            "        SetNull();\n"
            "    }\n"
            "\n"
            "    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce); }\n"
            "\n"
            "    void SetNull()\n"
            "    {\n"
            "        nVersion = 0;\n"
            "        hashPrevBlock.SetNull();\n"
            "        hashMerkleRoot.SetNull();\n"
            "        nTime = 0;\n"
            "        nBits = 0;\n"
            "        nNonce = 0;\n"
            "    }"
        )
        new1 = (
            "    // header\n"
            "    int32_t nVersion;\n"
            "    uint256 hashPrevBlock;\n"
            "    uint256 hashMerkleRoot;\n"
            "    uint32_t nTime;\n"
            "    uint32_t nBits;\n"
            "    uint32_t nNonce;     // legacy field — set to 0 in PoUW v2\n"
            "    // QNT PoUW v2: xmssRoot field\n"
            "    // XMSS tree root hash — this IS the proof of work.\n"
            "    // Miner searches SK_SEED until xmssRoot < target.\n"
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
        if old1 not in content:
            print("[ERROR] Target Patch 1 (block.h fields) tidak ditemukan")
            return None
        content = content.replace(old1, new1)
        print("[OK] Patch 1: xmssRoot field ditambahkan ke CBlockHeader")

    # ── PATCH 2: Update GetBlockHeader() di CBlock ────────────────────────
    MARKER2 = "// QNT PoUW v2: copy xmssRoot"
    if MARKER2 not in content:
        old2 = (
            "    CBlockHeader GetBlockHeader() const\n"
            "    {\n"
            "        CBlockHeader block;\n"
            "        block.nVersion       = nVersion;\n"
            "        block.hashPrevBlock  = hashPrevBlock;\n"
            "        block.hashMerkleRoot = hashMerkleRoot;\n"
            "        block.nTime          = nTime;\n"
            "        block.nBits          = nBits;\n"
            "        block.nNonce         = nNonce;\n"
            "        return block;\n"
            "    }"
        )
        new2 = (
            "    CBlockHeader GetBlockHeader() const\n"
            "    {\n"
            "        CBlockHeader block;\n"
            "        block.nVersion       = nVersion;\n"
            "        block.hashPrevBlock  = hashPrevBlock;\n"
            "        block.hashMerkleRoot = hashMerkleRoot;\n"
            "        block.nTime          = nTime;\n"
            "        block.nBits          = nBits;\n"
            "        block.nNonce         = nNonce;\n"
            "        // QNT PoUW v2: copy xmssRoot\n"
            "        block.xmssRoot       = xmssRoot;\n"
            "        return block;\n"
            "    }"
        )
        if old2 not in content:
            print("[ERROR] Target Patch 2 (GetBlockHeader) tidak ditemukan")
            return None
        content = content.replace(old2, new2)
        print("[OK] Patch 2: GetBlockHeader() copy xmssRoot")

    return content

def patch_block_cpp(content):
    # ── Update ToString() untuk tampilkan xmssRoot ────────────────────────
    MARKER = "// QNT PoUW v2: xmssRoot in ToString"
    if MARKER not in content:
        old = 'strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\\n",'
        new = (
            '// QNT PoUW v2: xmssRoot in ToString\n'
            '    strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, xmssRoot=%s, vtx=%u)\\n",'
        )
        if old not in content:
            print("[WARN] block.cpp ToString target tidak ditemukan — skip")
            return content

        # Cari args line yang menyertai
        old_full = old + "\n        nHash.ToString(),\n        nVersion,\n        hashPrevBlock.ToString(),\n        hashMerkleRoot.ToString(),\n        nTime, nBits, nNonce,"
        new_full = (
            "// QNT PoUW v2: xmssRoot in ToString\n"
            '    strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, xmssRoot=%s, vtx=%u)\\n",\n'
            "        nHash.ToString(),\n"
            "        nVersion,\n"
            "        hashPrevBlock.ToString(),\n"
            "        hashMerkleRoot.ToString(),\n"
            "        nTime, nBits, nNonce,\n"
            "        xmssRoot.ToString(),"
        )
        old_args = old + "\n        nHash.ToString(),\n        nVersion,\n        hashPrevBlock.ToString(),\n        hashMerkleRoot.ToString(),\n        nTime, nBits, nNonce,"
        if old_args in content:
            content = content.replace(old_args, new_full)
            print("[OK] block.cpp: ToString() updated")
        else:
            print("[WARN] block.cpp ToString args tidak exact — skip")
    return content

def patch_validation(content):
    # ── PATCH: CheckBlockHeader() pakai xmssRoot bukan block.GetHash() ───
    MARKER = "// QNT PoUW v2: check xmssRoot < target"
    if MARKER not in content:
        old = (
            "static bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true)\n"
            "{\n"
            "    // Check proof of work matches claimed amount\n"
            "    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))\n"
            "        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, \"high-hash\", \"proof of work failed\");\n"
            "    return true;\n"
            "}"
        )
        new = (
            "static bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true)\n"
            "{\n"
            "    // QNT PoUW v2: check xmssRoot < target\n"
            "    // xmssRoot is the XMSS tree root — miner searched SK_SEED until root < target\n"
            "    // Full XMSS proof (auth_path + wots_sig) verified in CheckPoUW()\n"
            "    if (fCheckPOW && !CheckProofOfWork(block.xmssRoot, block.nBits, consensusParams))\n"
            "        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, \"high-hash\", \"proof of work failed\");\n"
            "    return true;\n"
            "}"
        )
        if old not in content:
            print("[ERROR] Target CheckBlockHeader tidak ditemukan")
            probe = "static bool CheckBlockHeader"
            if probe in content:
                idx = content.index(probe)
                print(f"  [DEBUG] at {idx}:")
                print(repr(content[idx:idx+250]))
            return None
        content = content.replace(old, new)
        print("[OK] validation.cpp: CheckBlockHeader() → xmssRoot")

    # ── PATCH 2: HasValidProofOfWork() — pakai xmssRoot ──────────────────
    MARKER2 = "// QNT PoUW v2: HasValidProofOfWork uses xmssRoot"
    if MARKER2 not in content:
        old2 = (
            "bool HasValidProofOfWork(const std::vector<CBlockHeader>& headers, const Consensus::Params& consensusParams)\n"
            "{\n"
            "    return std::all_of(headers.cbegin(), headers.cend(),\n"
            "            [&](const auto& header) { return CheckProofOfWork(header.GetHash(), header.nBits, consensusParams);});\n"
            "}"
        )
        new2 = (
            "// QNT PoUW v2: HasValidProofOfWork uses xmssRoot\n"
            "bool HasValidProofOfWork(const std::vector<CBlockHeader>& headers, const Consensus::Params& consensusParams)\n"
            "{\n"
            "    return std::all_of(headers.cbegin(), headers.cend(),\n"
            "            [&](const auto& header) { return CheckProofOfWork(header.xmssRoot, header.nBits, consensusParams);});\n"
            "}"
        )
        if old2 not in content:
            print("[ERROR] Target HasValidProofOfWork tidak ditemukan")
            return None
        content = content.replace(old2, new2)
        print("[OK] validation.cpp: HasValidProofOfWork() → xmssRoot")

    return content

def main():
    patches = [
        (BLOCK_H,   patch_block_h),
        (BLOCK_CPP, patch_block_cpp),
        (VAL_CPP,   patch_validation),
    ]
    for path, fn in patches:
        if not os.path.exists(path):
            print(f"[ERROR] {path} tidak ditemukan")
            sys.exit(1)
        with open(path) as f:
            content = f.read()
        original = content
        content = fn(content)
        if content is None:
            print(f"[FAILED] {path}")
            sys.exit(1)
        if content != original:
            with open(path + ".bak_v2", 'w') as f:
                f.write(original)
            with open(path, 'w') as f:
                f.write(content)
            print(f"[DONE] {path}")
        else:
            print(f"[INFO] {path} tidak ada perubahan")

if __name__ == "__main__":
    main()
