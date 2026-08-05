// Copyright (c) 2026 The Assentian-PQE developers
// SNTI DRAFT: see xmss_leaf_key.h.

#include <xmss_leaf_key.h>

#include <hash.h>
#include <script/solver.h>

uint256 MakePoUWLeafKey(const std::vector<uint8_t>& pubkey64, uint32_t leaf_idx)
{
    uint8_t idx_be[4];
    idx_be[0] = (leaf_idx >> 24) & 0xFF;
    idx_be[1] = (leaf_idx >> 16) & 0xFF;
    idx_be[2] = (leaf_idx >>  8) & 0xFF;
    idx_be[3] =  leaf_idx        & 0xFF;
    CHash256 hasher;
    hasher.Write(pubkey64);
    hasher.Write({idx_be, 4});
    uint256 result;
    hasher.Finalize(result);
    return result;
}

bool ExtractXMSSLeafUse(const CScript& scriptPubKey, const CScript& scriptSig,
                         std::vector<uint8_t>& pubkey_out, uint32_t& leaf_idx_out)
{
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType type = Solver(scriptPubKey, solutions);
    if (type != TxoutType::P2XMSS && type != TxoutType::P2XMSSHASH) return false;

    std::vector<std::vector<unsigned char>> pushes;
    {
        CScript::const_iterator pc = scriptSig.begin();
        opcodetype opcode;
        std::vector<unsigned char> data;
        while (pc != scriptSig.end()) {
            if (!scriptSig.GetOp(pc, opcode, data)) return false;
            if (opcode > OP_PUSHDATA4) return false; // not a plain-push scriptSig -- not our pattern
            pushes.push_back(std::move(data));
        }
    }
    if (pushes.empty()) return false;

    // Where the pubkey comes from differs by type (see script/sign.cpp
    // SignStep(), the code that actually builds these scriptSigs):
    //  - P2XMSS (bare): scriptPubKey itself is <pubkey> OP_XMSS_CHECKSIG, so
    //    the pubkey is pushed by scriptPubKey, NOT scriptSig -- Solver()
    //    already gave it to us in solutions[0]. scriptSig is chunks only.
    //  - P2XMSSHASH: scriptPubKey only carries HASH160(pubkey), so the real
    //    pubkey must be supplied in scriptSig -- pushed LAST, after the
    //    chunks (see SignStep()'s `ret.push_back(pubkey)` at the end).
    std::vector<unsigned char> pk;
    size_t n_chunk_pushes;
    if (type == TxoutType::P2XMSS) {
        pk = solutions[0];
        n_chunk_pushes = pushes.size();
    } else {
        pk = pushes.back();
        n_chunk_pushes = pushes.size() - 1;
    }
    if (pk.size() != 64) return false;

    static const size_t XMSS_MAX_SIG_BYTES = 4096; // mirrors interpreter.cpp OP_XMSS_CHECKSIG
    std::vector<uint8_t> sig;
    sig.reserve(XMSS_MAX_SIG_BYTES);
    for (size_t i = 0; i < n_chunk_pushes; i++) {
        const auto& chunk = pushes[i];
        if (chunk.empty() || chunk.size() > 520) return false; // malformed -- can't be the sig CheckInputScripts verified
        sig.insert(sig.end(), chunk.begin(), chunk.end());
        if (sig.size() >= XMSS_MAX_SIG_BYTES) break;
    }
    if (sig.size() < 4) return false;

    pubkey_out = pk;
    leaf_idx_out = ((uint32_t)sig[0] << 24) | ((uint32_t)sig[1] << 16) |
                   ((uint32_t)sig[2] << 8)  |  (uint32_t)sig[3];
    return true;
}
