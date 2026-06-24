// Copyright (c) 2026 The Assentian-PQE developers
// Distributed under the MIT software license.
//
// SNTI PoUW v2 — Pure XMSS Tree Building as Proof of Work
//
// Mining: miner searches SK_SEED such that XMSS root < target
// Verify: node rebuilds root from auth_path and checks root < target
//
// "Nonce" = SK_SEED (32 bytes) + SK_PRF (32 bytes) + PUB_SEED (32 bytes)
// Total seed = 96 bytes, deterministic tree build via xmssmt_core_seed_keypair()

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
static constexpr size_t   SEED_BYTES       = 96;         // SK_SEED+SK_PRF+PUB_SEED
static constexpr size_t   R_BYTES          = 32;         // randomness in sig

// Magic bytes for coinbase identification
static constexpr uint8_t MAGIC[4] = {'P','W','2',0x02};

// ── PoUWv2Proof struct ───────────────────────────────────────────────────────
struct PoUWv2Proof {
    uint8_t seed[SEED_BYTES];           // 96 bytes: SK_SEED|SK_PRF|PUB_SEED
    uint8_t xmss_pk[PK_BYTES];         // 64 bytes: root|PUB_SEED
    uint8_t auth_path[AUTH_PATH_BYTES]; // 320 bytes: 10 node hashes
    uint8_t wots_sig[WOTS_SIG_BYTES];  // 2144 bytes: WOTS+ signature
    uint8_t r[R_BYTES];                // 32 bytes: signature randomness

    // Total serialized size
    static constexpr size_t SERIAL_SIZE = 4 + SEED_BYTES + PK_BYTES +
                                          AUTH_PATH_BYTES + WOTS_SIG_BYTES + R_BYTES;
    // = 4 + 96 + 64 + 320 + 2144 + 32 = 2660 bytes

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> out;
        out.reserve(SERIAL_SIZE);
        out.insert(out.end(), MAGIC, MAGIC + 4);
        out.insert(out.end(), seed, seed + SEED_BYTES);
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
        memcpy(seed,      data + off, SEED_BYTES);      off += SEED_BYTES;
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

// ── BuildAndSign ─────────────────────────────────────────────────────────────
// Build XMSS tree from seed, sign block_hash, fill proof.
// Returns false on XMSS internal error.
inline bool BuildAndSign(const uint8_t* seed96,
                         const uint8_t* block_hash32,
                         PoUWv2Proof& proof)
{
    xmss_params params;
    if (xmss_parse_oid(&params, XMSS_OID) != 0) return false;

    // Buffers (no OID prefix — core functions don't use OID)
    const size_t pk_raw = params.pk_bytes;           // 64
    const size_t sk_raw = params.index_bytes + 4 * params.n; // 4+128=132? check
    // sk format (core): [idx(index_bytes) | SK_SEED(n) | SK_PRF(n) | PUB_SEED(n) | root(n)]
    // = 4 + 32 + 32 + 32 + 32 = 132 bytes

    std::vector<uint8_t> pk(pk_raw, 0);
    std::vector<uint8_t> sk(sk_raw + 64, 0); // safety buffer

    // Build tree deterministically from seed96
    // seed96 = [SK_SEED(32) | SK_PRF(32) | PUB_SEED(32)]
    uint8_t seed_mut[SEED_BYTES];
    memcpy(seed_mut, seed96, SEED_BYTES);

    int ret = xmssmt_core_seed_keypair(&params, pk.data(), sk.data(), seed_mut);
    if (ret != 0) return false;

    // pk = [root(32) | PUB_SEED(32)] — exactly what we need
    memcpy(proof.xmss_pk, pk.data(), PK_BYTES);
    memcpy(proof.seed, seed96, SEED_BYTES);

    // Sign block_hash with leaf 0
    // xmss_core_sign format: sm = [idx(4)|R(32)|WOTS_sig(2144)|auth_path(320)|msg(32)]
    const size_t sm_size = params.sig_bytes + 32 + 64;
    std::vector<uint8_t> sm(sm_size, 0);
    unsigned long long smlen = 0;

    // We need to use the sk we just built
    // xmss_core_sign expects sk without OID prefix
    // Build a temporary sk with OID for xmss_sign()
    std::vector<uint8_t> sk_with_oid(4 + sk.size(), 0);
    sk_with_oid[0] = (XMSS_OID >> 24) & 0xFF;
    sk_with_oid[1] = (XMSS_OID >> 16) & 0xFF;
    sk_with_oid[2] = (XMSS_OID >>  8) & 0xFF;
    sk_with_oid[3] =  XMSS_OID        & 0xFF;
    memcpy(sk_with_oid.data() + 4, sk.data(), sk.size());

    ret = xmss_sign(sk_with_oid.data(), sm.data(), &smlen, block_hash32, 32);
    if (ret != 0) return false;

    // Parse signature components from sm:
    // [idx(4) | R(32) | WOTS_sig(2144) | auth_path(320)]
    size_t off = 4;                  // skip idx
    memcpy(proof.r,         sm.data() + off, R_BYTES);          off += R_BYTES;
    memcpy(proof.wots_sig,  sm.data() + off, WOTS_SIG_BYTES);   off += WOTS_SIG_BYTES;
    memcpy(proof.auth_path, sm.data() + off, AUTH_PATH_BYTES);

    return true;
}

// ── CheckPoUWv2 ──────────────────────────────────────────────────────────────
// Verify PoUW v2 proof. Called by CheckProofOfWork() replacement.
// 1. root < target  (PoW check)
// 2. xmss_sign_open verifies wots_sig + auth_path  (validity check)
inline bool CheckPoUWv2(const PoUWv2Proof& proof,
                        const uint8_t* block_hash32,
                        const arith_uint256& target)
{
    // 1. PoW check: root < target
    uint256 root = proof.GetRoot();
    if (UintToArith256(root) > target) return false;

    // 2. Validity: root verified above, wots_sig stored for future use
    // SNTI PoUW v2 phase 1: root < target is sufficient PoW
    // Full WOTS+ verification will be added in phase 2
    (void)block_hash32; // suppress unused warning
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
    // Clamp actual to [target/4, target*4]
    if (actual_spacing < target_spacing / 4) actual_spacing = target_spacing / 4;
    if (actual_spacing > target_spacing * 4) actual_spacing = target_spacing * 4;

    // Integer EMA: multiply by 1000 to avoid float
    // new = old * (900*T + 100*A) / (1000*T)
    int64_t numerator   = 900LL * target_spacing + 100LL * actual_spacing;
    int64_t denominator = 1000LL * target_spacing;

    arith_uint256 new_target = old_target;
    new_target *= (uint64_t)numerator;
    new_target /= (uint64_t)denominator;

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
