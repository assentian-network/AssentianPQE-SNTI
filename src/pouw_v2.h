// Copyright (c) 2026 The Assentian-PQE developers
// Distributed under the MIT software license.
//
// SNTI PoUW v2 — Pure XMSS Tree Building as Proof of Work
//
// Mining: miner searches SK_SEED such that XMSS root < target
// Verify: node rebuilds root from auth_path and checks root < target
//
// "Nonce" = SK_SEED (32 bytes) + SK_PRF (32 bytes) + PUB_SEED (32 bytes)
// The seed is used LOCALLY by the miner to build the XMSS tree.
// It is NOT included in the serialized proof — only the resulting
// xmss_pk (root+PUB_SEED), auth_path, wots_sig, and r are broadcast.

#ifndef ASSENTIAN_POUW_V2_H
#define ASSENTIAN_POUW_V2_H

#pragma once

extern "C" {
#include "xmss.h"
#include "xmss_core.h"
#include "params.h"
#include "xmss_commons.h"
}

#include <arith_uint256.h>
#include <uint256.h>
#include <cstring>
#include <vector>
#include <array>

namespace PoUWv2 {

// ── Constants ────────────────────────────────────────────────────────────────
static constexpr uint32_t XMSS_OID         = 0x00000001; // XMSS-SHA2_10_256
static constexpr size_t   TREE_HEIGHT      = 10;
static constexpr size_t   N                = 32;          // hash bytes
static constexpr size_t   WOTS_SIG_BYTES   = 2144;       // WOTS+ sig
static constexpr size_t   AUTH_PATH_BYTES  = 320;        // 10 * 32
static constexpr size_t   PK_BYTES         = 64;         // root(32)+PUB_SEED(32)
static constexpr size_t   SEED_BYTES       = 96;         // SK_SEED+SK_PRF+PUB_SEED (miner-local, not in proof)
static constexpr size_t   R_BYTES          = 32;         // randomness in sig

// Magic bytes for coinbase identification
static constexpr uint8_t MAGIC[4] = {'P','W','2',0x02};

// ── PoUWv2Proof struct ───────────────────────────────────────────────────────
// Contains only the data needed for verification. The 96-byte seed
// (SK_SEED|SK_PRF|PUB_SEED) is NEVER included — it is private to the miner.
struct PoUWv2Proof {
    uint8_t xmss_pk[PK_BYTES];         // 64 bytes: root|PUB_SEED
    uint8_t auth_path[AUTH_PATH_BYTES]; // 320 bytes: 10 node hashes
    uint8_t wots_sig[WOTS_SIG_BYTES];  // 2144 bytes: WOTS+ signature
    uint8_t r[R_BYTES];                // 32 bytes: signature randomness

    // Total serialized size
    static constexpr size_t SERIAL_SIZE = 4 + PK_BYTES +
                                          AUTH_PATH_BYTES + WOTS_SIG_BYTES + R_BYTES;
    // = 4 + 64 + 320 + 2144 + 32 = 2564 bytes

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> out;
        out.reserve(SERIAL_SIZE);
        out.insert(out.end(), MAGIC, MAGIC + 4);
        out.insert(out.end(), xmss_pk, xmss_pk + PK_BYTES);
        out.insert(out.end(), auth_path, auth_path + AUTH_PATH_BYTES);
        out.insert(out.end(), wots_sig, wots_sig + WOTS_SIG_BYTES);
        out.insert(out.end(), r, r + R_BYTES);
        return out;
    }

    bool Deserialize(const uint8_t* data, size_t len) {
        if (len < SERIAL_SIZE) return false;
        if (memcmp(data, MAGIC, 4) != 0) return false;
        size_t off = 4;
        memcpy(xmss_pk,   data + off, PK_BYTES);        off += PK_BYTES;
        memcpy(auth_path, data + off, AUTH_PATH_BYTES); off += AUTH_PATH_BYTES;
        memcpy(wots_sig,  data + off, WOTS_SIG_BYTES);  off += WOTS_SIG_BYTES;
        memcpy(r,         data + off, R_BYTES);
        return true;
    }

    // Root hash = first 32 bytes of xmss_pk
    uint256 GetRoot() const {
        uint256 root;
        memcpy(root.begin(), xmss_pk, 32);
        return root;
    }
};

inline bool CheckPoUWv2(const PoUWv2Proof& proof,
                        const uint8_t* block_hash32,
                        const arith_uint256& target,
                        uint32_t nLeafIndex = 0)
{
    // 1. PoW check: root < target
    uint256 root = proof.GetRoot();
    if (UintToArith256(root) > target) return false;

    // 2. WOTS+ verify via xmss_sign_open
    // SM format for xmss_sign_open (matches xmss_sign output):
    // [idx(index_bytes) | R(n) | WOTS_sig(wots_sig_bytes) | auth_path(tree_height*n) | msg(32)]
    xmss_params params;
    if (xmss_parse_oid(&params, XMSS_OID) != 0) return false;

    // Build PK with OID prefix: OID(4) | root(32) | PUB_SEED(32)
    std::vector<uint8_t> pk_with_oid(4 + PK_BYTES, 0);
    pk_with_oid[0] = (XMSS_OID >> 24) & 0xFF;
    pk_with_oid[1] = (XMSS_OID >> 16) & 0xFF;
    pk_with_oid[2] = (XMSS_OID >>  8) & 0xFF;
    pk_with_oid[3] =  XMSS_OID        & 0xFF;
    memcpy(pk_with_oid.data() + 4, proof.xmss_pk, PK_BYTES);

    // SM = sig + msg, where sig = params.sig_bytes
    // params.sig_bytes = index_bytes(4) + n(32) + wots_sig_bytes(2144) + tree_height*n(320) = 2500
    const size_t sm_size = (size_t)params.sig_bytes + 32;
    std::vector<uint8_t> sm(sm_size + 64, 0); // +64 safety

    // Fill SM: [idx(4) | R(32) | WOTS_sig(2144) | auth_path(320) | msg(32)]
    size_t off = 0;
    // idx = nLeafIndex big-endian, index_bytes=4
    sm[0] = (nLeafIndex >> 24) & 0xFF;
    sm[1] = (nLeafIndex >> 16) & 0xFF;
    sm[2] = (nLeafIndex >>  8) & 0xFF;
    sm[3] =  nLeafIndex        & 0xFF;
    off = (size_t)params.index_bytes; // =4

    memcpy(sm.data() + off, proof.r,         R_BYTES);          off += R_BYTES;
    memcpy(sm.data() + off, proof.wots_sig,  WOTS_SIG_BYTES);   off += WOTS_SIG_BYTES;
    memcpy(sm.data() + off, proof.auth_path, AUTH_PATH_BYTES);  off += AUTH_PATH_BYTES;
    memcpy(sm.data() + off, block_hash32,    32);               off += 32;

    // xmss_sign_open writes at msg_out[params.sig_bytes] internally,
    // so msg_out must be at least params.sig_bytes + msg_size.
    std::vector<uint8_t> msg_out((size_t)params.sig_bytes + 32 + 64, 0);
    unsigned long long msg_len = 0;

    int ret = xmss_sign_open(msg_out.data(), &msg_len,
                             sm.data(), (unsigned long long)sm_size,
                             pk_with_oid.data());
    if (ret != 0) return false;

    // 3. Verify recovered message matches block_hash
    if (msg_len != 32) return false;
    if (memcmp(msg_out.data(), block_hash32, 32) != 0) return false;

    return true;
}

// ── EMA Difficulty Adjustment ─────────────────────────────────────────────────
// Per-block EMA with alpha=0.1
// new = old*(1-alpha) + old*(actual/target)*alpha
//     = old * (900*target + 100*actual) / (1000*target)
inline arith_uint256 CalcNextTargetEMA(const arith_uint256& old_target,
                                       int64_t actual_spacing,
                                       int64_t target_spacing,
                                       const arith_uint256& pow_limit)
{
    // Clamp actual to [target/4, target*20]
    // Lower clamp (target/4 = 15s) limits difficulty from spiking too fast on bursts.
    // Upper clamp raised from 4× to 20× so a stuck chain recovers in ~5 blocks instead
    // of ~30 blocks.  Max recovery ratio per slow block: (900T+100×20T)/(1000T) = 2.9×.
    if (actual_spacing < target_spacing / 4)  actual_spacing = target_spacing / 4;
    if (actual_spacing > target_spacing * 20) actual_spacing = target_spacing * 20;

    // Integer EMA: multiply by 1000 to avoid float
    // new = old * (900*T + 100*A) / (1000*T)
    int64_t numerator   = 900LL * target_spacing + 100LL * actual_spacing;
    int64_t denominator = 1000LL * target_spacing;

    // Overflow-safe EMA: divide before multiply.
    // old_target ≈ pow_limit ≈ 2^249; multiplying by numerator first (≤78000≈2^17)
    // yields ~2^266 which overflows uint256. Dividing first gives ~2^233,
    // then multiplying stays within 2^250. Precision loss is < numerator/old_target ≈ 2^-232.
    arith_uint256 new_target = old_target;
    new_target /= (uint64_t)denominator;
    new_target *= (uint64_t)numerator;

    // Clamp to [pow_limit >> 10, pow_limit]
    if (new_target > pow_limit) new_target = pow_limit;
    arith_uint256 min_target = pow_limit >> 10;
    if (new_target < min_target) new_target = min_target;

    return new_target;
}

// ── Initial powLimit for PoUW v2 ─────────────────────────────────────────────
// Target: 1 of 156 trees valid at genesis (4 core, 6.17s/tree, 60s block)
// powLimit_v2 = 2^256 / 156
// In hex: 0x01A4B0... 
// Use: "01a4b0f8d0a0000000000000000000000000000000000000000000000000000000"
// nBits compact: 0x2001A4B0
static const char* POUW_V2_POW_LIMIT =
    "01a4b0f8d0a0000000000000000000000000000000000000000000000000000000";

} // namespace PoUWv2

#endif // ASSENTIAN_POUW_V2_H
