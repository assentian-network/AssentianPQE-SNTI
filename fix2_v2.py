#!/usr/bin/env python3
"""
Fix 2 v2: Tambah chainman parameter ke CheckPoUW, fix semua call sites.
Jalankan dari: ~/Assentian-PQE/SNTI
"""
import sys, os

VALIDATION = "src/validation.cpp"

def check_idempotent(content, marker):
    if marker in content:
        print(f"[SKIP] {marker!r}")
        return True
    return False

def patch(content):

    # ── PATCH 1: Helper MakePoUWLeafKey ──────────────────────────────────
    MARKER1 = "// QNT Fix2: PoUW leaf index tracking helpers"
    if not check_idempotent(content, MARKER1):
        helper = (
            "\n// QNT Fix2: PoUW leaf index tracking helpers\n"
            "static const char DB_POUW_LEAF = 'L';\n"
            "\n"
            "static uint256 MakePoUWLeafKey(const std::vector<uint8_t>& pubkey64, uint32_t leaf_idx)\n"
            "{\n"
            "    uint8_t idx_be[4];\n"
            "    idx_be[0] = (leaf_idx >> 24) & 0xFF;\n"
            "    idx_be[1] = (leaf_idx >> 16) & 0xFF;\n"
            "    idx_be[2] = (leaf_idx >>  8) & 0xFF;\n"
            "    idx_be[3] =  leaf_idx        & 0xFF;\n"
            "    CHash256 hasher;\n"
            "    hasher.Write(pubkey64);\n"
            "    hasher.Write({idx_be, 4});\n"
            "    uint256 result;\n"
            "    hasher.Finalize(result);\n"
            "    return result;\n"
            "}\n\n"
        )
        target1 = "// QNT: Forward declaration — PoUW XMSS signature verification"
        if target1 not in content:
            print(f"[ERROR] Target Patch 1 tidak ditemukan")
            return None
        content = content.replace(target1, helper + target1)
        print("[OK] Patch 1: Helper MakePoUWLeafKey")

    # ── PATCH 2: Forward declaration — tambah chainman param ─────────────
    MARKER2 = "// QNT Fix2: forward decl updated"
    if not check_idempotent(content, MARKER2):
        old2 = "static bool CheckPoUW(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, int nHeight = -1);"
        new2 = "// QNT Fix2: forward decl updated\nstatic bool CheckPoUW(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, ChainstateManager& chainman, int nHeight = -1);"
        if old2 not in content:
            print("[ERROR] Target Patch 2 (forward decl) tidak ditemukan")
            return None
        content = content.replace(old2, new2)
        print("[OK] Patch 2: Forward declaration updated")

    # ── PATCH 3: Call site di CheckBlock (Chainstate::) ──────────────────
    MARKER3 = "// QNT Fix2: call site 1 updated"
    if not check_idempotent(content, MARKER3):
        old3 = "    if (fCheckPOW && !CheckPoUW(block, state, consensusParams)) {"
        new3 = "    // QNT Fix2: call site 1 updated\n    if (fCheckPOW && !CheckPoUW(block, state, consensusParams, m_chainman)) {"
        if old3 not in content:
            print("[ERROR] Target Patch 3 (call site 1) tidak ditemukan")
            return None
        content = content.replace(old3, new3)
        print("[OK] Patch 3: Call site 1 (Chainstate::CheckBlock) updated")

    # ── PATCH 4: Call site di ChainstateManager::CheckBlock ──────────────
    MARKER4 = "// QNT Fix2: call site 2 updated"
    if not check_idempotent(content, MARKER4):
        old4 = "    if (fCheckPOW && !CheckPoUW(block, state, chainman.GetConsensus(), nHeight)) {"
        new4 = "    // QNT Fix2: call site 2 updated\n    if (fCheckPOW && !CheckPoUW(block, state, chainman.GetConsensus(), chainman, nHeight)) {"
        if old4 not in content:
            print("[ERROR] Target Patch 4 (call site 2) tidak ditemukan")
            return None
        content = content.replace(old4, new4)
        print("[OK] Patch 4: Call site 2 (ChainstateManager::CheckBlock) updated")

    # ── PATCH 5: Implementasi CheckPoUW — tambah chainman param + leaf check
    MARKER5 = "// QNT Fix2: implementation updated"
    if not check_idempotent(content, MARKER5):
        old5 = "static bool CheckPoUW(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, int nHeight)"
        new5 = "// QNT Fix2: implementation updated\nstatic bool CheckPoUW(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, ChainstateManager& chainman, int nHeight)"
        if old5 not in content:
            print("[ERROR] Target Patch 5 (impl signature) tidak ditemukan")
            return None
        content = content.replace(old5, new5)
        print("[OK] Patch 5: CheckPoUW signature updated")

    # ── PATCH 6: Insert leaf check di dalam CheckPoUW ────────────────────
    MARKER6 = "// QNT Fix2: check leaf index not already used"
    if not check_idempotent(content, MARKER6):
        old6 = (
            '    LogPrint(BCLog::VALIDATION, "PoUW: block %s verified (pk=%s, sig_len=%d)\\n",\n'
            '             block.GetHash().GetHex(), HexStr(xmss_pk).substr(0, 16), (int)xmss_sig.size());\n'
            '\n'
            '    return true;\n'
            '}\n'
            '\n'
            'void Chai'
        )
        new6 = (
            '    // QNT Fix2: check leaf index not already used\n'
            '    if (xmss_sig.size() < 4) {\n'
            '        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "pouw-sig-too-short",\n'
            '                             "PoUW: XMSS signature too short to extract leaf index");\n'
            '    }\n'
            '    uint32_t leaf_idx = ((uint32_t)xmss_sig[0] << 24) |\n'
            '                        ((uint32_t)xmss_sig[1] << 16) |\n'
            '                        ((uint32_t)xmss_sig[2] <<  8) |\n'
            '                         (uint32_t)xmss_sig[3];\n'
            '    uint256 leaf_key = MakePoUWLeafKey(xmss_pk, leaf_idx);\n'
            '    uint256 existing_block;\n'
            '    if (chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF, leaf_key), existing_block)) {\n'
            '        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "pouw-leaf-reuse",\n'
            '                             strprintf("PoUW: XMSS leaf index %u already used in block %s",\n'
            '                                       leaf_idx, existing_block.GetHex()));\n'
            '    }\n'
            '    LogPrint(BCLog::VALIDATION, "PoUW: block %s verified (pk=%s, leaf_idx=%u, sig_len=%d)\\n",\n'
            '             block.GetHash().GetHex(), HexStr(xmss_pk).substr(0, 16), leaf_idx, (int)xmss_sig.size());\n'
            '\n'
            '    return true;\n'
            '}\n'
            '\n'
            'void Chai'
        )
        if old6 not in content:
            print("[ERROR] Target Patch 6 (leaf check) tidak ditemukan")
            probe = 'LogPrint(BCLog::VALIDATION, "PoUW: block %s verified'
            if probe in content:
                idx = content.index(probe)
                print(f"  [DEBUG] probe at {idx}:")
                print(repr(content[idx:idx+220]))
            return None
        content = content.replace(old6, new6)
        print("[OK] Patch 6: Leaf index check di CheckPoUW")

    # ── PATCH 7: ConnectBlock — mark leaf index ───────────────────────────
    MARKER7 = "// QNT Fix2: mark PoUW leaf index as used"
    if not check_idempotent(content, MARKER7):
        old7 = (
            '    // add this block to the view\'s block chain\n'
            '    view.SetBestBlock(pindex->GetBlockHash());\n'
            '\n'
            '    const auto time_6{SteadyClock::now()};\n'
            '    time_index += time_6 - time_5;'
        )
        new7 = (
            '    // add this block to the view\'s block chain\n'
            '    view.SetBestBlock(pindex->GetBlockHash());\n'
            '\n'
            '    // QNT Fix2: mark PoUW leaf index as used\n'
            '    if (!fJustCheck && consensusParams.fPoUW) {\n'
            '        const CTransaction& cbTx = *block.vtx[0];\n'
            '        std::vector<uint8_t> cb_pk, cb_sig;\n'
            '        for (const auto& out : cbTx.vout) {\n'
            '            const CScript& s = out.scriptPubKey;\n'
            '            CScript::const_iterator pc = s.begin();\n'
            '            opcodetype opc; std::vector<uint8_t> d;\n'
            '            while (s.GetOp(pc, opc, d)) {\n'
            '                if (opc == OP_RETURN) continue;\n'
            '                if (d.size() == 64 && cb_pk.empty()) cb_pk = d;\n'
            '                else if (d.size() > 64 && cb_sig.empty()) cb_sig = d;\n'
            '            }\n'
            '        }\n'
            '        if (cb_pk.size() == 64 && cb_sig.size() >= 4) {\n'
            '            uint32_t cb_leaf = ((uint32_t)cb_sig[0]<<24)|((uint32_t)cb_sig[1]<<16)|\n'
            '                               ((uint32_t)cb_sig[2]<<8)|(uint32_t)cb_sig[3];\n'
            '            uint256 cb_key = MakePoUWLeafKey(cb_pk, cb_leaf);\n'
            '            uint256 bh = block.GetHash();\n'
            '            m_chainman.m_blockman.m_block_tree_db->Write(std::make_pair(DB_POUW_LEAF, cb_key), bh);\n'
            '            LogPrint(BCLog::VALIDATION, "PoUW Fix2: marked leaf=%u block=%s\\n", cb_leaf, bh.GetHex());\n'
            '        }\n'
            '    }\n'
            '\n'
            '    const auto time_6{SteadyClock::now()};\n'
            '    time_index += time_6 - time_5;'
        )
        if old7 not in content:
            print("[ERROR] Target Patch 7 (ConnectBlock mark) tidak ditemukan")
            return None
        content = content.replace(old7, new7)
        print("[OK] Patch 7: ConnectBlock mark leaf index")

    # ── PATCH 8: DisconnectBlock — unmark saat reorg ─────────────────────
    MARKER8 = "// QNT Fix2: unmark PoUW leaf index on reorg"
    if not check_idempotent(content, MARKER8):
        old8 = (
            '    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {\n'
            '        error("DisconnectBlock(): block and undo data inconsistent");\n'
            '        return DISCONNECT_FAILED;\n'
            '    }'
        )
        new8 = (
            '    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {\n'
            '        error("DisconnectBlock(): block and undo data inconsistent");\n'
            '        return DISCONNECT_FAILED;\n'
            '    }\n'
            '\n'
            '    // QNT Fix2: unmark PoUW leaf index on reorg\n'
            '    {\n'
            '        const Consensus::Params& cp = m_chainman.GetParams().GetConsensus();\n'
            '        if (cp.fPoUW) {\n'
            '            const CTransaction& cbTx = *block.vtx[0];\n'
            '            std::vector<uint8_t> cb_pk, cb_sig;\n'
            '            for (const auto& out : cbTx.vout) {\n'
            '                const CScript& s = out.scriptPubKey;\n'
            '                CScript::const_iterator pc = s.begin();\n'
            '                opcodetype opc; std::vector<uint8_t> d;\n'
            '                while (s.GetOp(pc, opc, d)) {\n'
            '                    if (opc == OP_RETURN) continue;\n'
            '                    if (d.size() == 64 && cb_pk.empty()) cb_pk = d;\n'
            '                    else if (d.size() > 64 && cb_sig.empty()) cb_sig = d;\n'
            '                }\n'
            '            }\n'
            '            if (cb_pk.size() == 64 && cb_sig.size() >= 4) {\n'
            '                uint32_t cb_leaf = ((uint32_t)cb_sig[0]<<24)|((uint32_t)cb_sig[1]<<16)|\n'
            '                                   ((uint32_t)cb_sig[2]<<8)|(uint32_t)cb_sig[3];\n'
            '                uint256 cb_key = MakePoUWLeafKey(cb_pk, cb_leaf);\n'
            '                m_chainman.m_blockman.m_block_tree_db->Erase(std::make_pair(DB_POUW_LEAF, cb_key));\n'
            '                LogPrint(BCLog::VALIDATION, "PoUW Fix2: unmarked leaf=%u reorg h=%d\\n",\n'
            '                         cb_leaf, pindex->nHeight);\n'
            '            }\n'
            '        }\n'
            '    }'
        )
        if old8 not in content:
            print("[ERROR] Target Patch 8 (DisconnectBlock) tidak ditemukan")
            return None
        content = content.replace(old8, new8)
        print("[OK] Patch 8: DisconnectBlock unmark leaf index")

    return content

def main():
    if not os.path.exists(VALIDATION):
        print(f"[ERROR] {VALIDATION} tidak ditemukan — jalankan dari ~/Assentian-PQE/SNTI")
        sys.exit(1)
    with open(VALIDATION, 'r') as f:
        content = f.read()
    original = content
    content = patch(content)
    if content is None:
        print("[FAILED]")
        sys.exit(1)
    if content == original:
        print("[INFO] Semua patch sudah diterapkan")
    else:
        with open(VALIDATION + ".bak_fix2", 'w') as f:
            f.write(original)
        with open(VALIDATION, 'w') as f:
            f.write(content)
        print(f"\n[DONE] {VALIDATION} dipatch — backup: {VALIDATION}.bak_fix2")

if __name__ == "__main__":
    main()
