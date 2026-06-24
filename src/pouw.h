// Copyright (c) 2025 The Quant developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QUANT_POUW_H
#define QUANT_POUW_H

/**
 * QNT Proof-of-Useful-Work (PoUW) v1
 *
 * Concept: Miners perform SHA-256 hash grinding (like Bitcoin PoW) BUT
 * the valid block must also be signed by the miner's XMSS key.
 *
 * The XMSS signing IS the useful work — it produces a cryptographic
 * signature that proves the miner generated and managed an XMSS key pair.
 * This is fundamentally different from Bitcoin's "useless" SHA-256 hashes.
 *
 * PoUW Algorithm:
 *   1. Miner generates XMSS key pair (one-time cost, ~1-2 seconds on CPU)
 *   2. Miner constructs block template with coinbase to their XMSS address
 *   3. Miner grinds SHA-256 nonce (standard PoW)
 *   4. When PoW solution found, miner XMSS-signs the block header
 *   5. Block is valid ONLY if both:
 *      a) SHA-256 hash < difficulty target (standard PoW)
 *      b) XMSS signature is valid for the miner's public key
 *
 * This means every mined block produces a valid XMSS key pair + signature,
 * contributing to the post-quantum security infrastructure.
 *
 * The XMSS public key is included in the coinbase transaction (OP_RETURN),
 * making it verifiable by all nodes.
 */

extern "C" {
#include "xmss.h"
}

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>

namespace QNT {
namespace PoUW {

// XMSS parameter set for QNT mining
static constexpr uint32_t XMSS_OID = 0x00000001;  // XMSS-SHA2_10_256
static constexpr size_t XMSS_PK_SIZE = 64;          // root(32) + PUB_SEED(32)
static constexpr size_t XMSS_SK_SIZE = 2048;        // generous buffer
static constexpr size_t XMSS_SIG_SIZE = 3000;       // max sig size

/**
 * Miner's XMSS key state.
 * Each miner has ONE key pair. After each sign, the key advances.
 * CRITICAL: Key must be persisted after each sign to prevent key reuse.
 */
struct MinerKey {
    std::vector<uint8_t> sk;  // Secret key (with OID prefix)
    std::vector<uint8_t> pk;  // Public key (with OID prefix)
    uint32_t index;           // Current signature index (0..1023)
    bool valid;

    MinerKey() : index(0), valid(false) {}

    bool Generate() {
        sk.resize(XMSS_SK_SIZE, 0);
        pk.resize(XMSS_OID_LEN + XMSS_PK_SIZE, 0);

        int ret = xmss_keypair(pk.data(), sk.data(), XMSS_OID);
        if (ret != 0) {
            valid = false;
            return false;
        }

        // Determine actual sk size
        size_t actual = XMSS_SK_SIZE;
        while (actual > 4 && sk[actual-1] == 0) actual--;
        actual += 64; // safety margin
        sk.resize(actual);

        index = 0;
        valid = true;
        return true;
    }

    // Get 64-byte public key (without OID prefix) for address
    std::vector<uint8_t> GetPubKey64() const {
        if (!valid || pk.size() < XMSS_OID_LEN + XMSS_PK_SIZE) return {};
        return std::vector<uint8_t>(pk.begin() + XMSS_OID_LEN, pk.end());
    }

    // Sign block header (32-byte hash)
    bool SignBlock(const uint8_t* hash32, std::vector<uint8_t>& sig) {
        if (!valid) return false;
        if (index >= 1024) return false;  // Key exhausted

        // xmss_sign expects: sk, sm_out, smlen, message, mlen
        size_t sm_buf_size = XMSS_SIG_SIZE + 32;
        std::vector<uint8_t> sm(sm_buf_size, 0);
        unsigned long long smlen = 0;

        // Make mutable copy of sk (xmss_sign updates it)
        std::vector<uint8_t> sk_copy(sk.begin(), sk.end());

        int ret = xmss_sign(sk_copy.data(), sm.data(), &smlen, hash32, 32);
        if (ret != 0 || smlen < 32) return false;

        // Extract signature (remove appended message)
        size_t sig_len = (size_t)smlen - 32;
        sig.assign(sm.begin(), sm.begin() + sig_len);

        // Update key state (index incremented internally by xmss_sign)
        sk = sk_copy;
        index++;

        return true;
    }

    // Serialize key for persistence
    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> data;
        // index (4 bytes)
        data.push_back((index >> 24) & 0xFF);
        data.push_back((index >> 16) & 0xFF);
        data.push_back((index >> 8) & 0xFF);
        data.push_back(index & 0xFF);
        // sk size (4 bytes)
        uint32_t sk_size = (uint32_t)sk.size();
        data.push_back((sk_size >> 24) & 0xFF);
        data.push_back((sk_size >> 16) & 0xFF);
        data.push_back((sk_size >> 8) & 0xFF);
        data.push_back(sk_size & 0xFF);
        // sk data
        data.insert(data.end(), sk.begin(), sk.end());
        return data;
    }

    // Deserialize key from persisted data
    bool Deserialize(const std::vector<uint8_t>& data) {
        if (data.size() < 8) return false;
        index = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                ((uint32_t)data[2] << 8) | (uint32_t)data[3];
        uint32_t sk_size = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                           ((uint32_t)data[6] << 8) | (uint32_t)data[7];
        if (data.size() < 8 + sk_size) return false;
        sk.assign(data.begin() + 8, data.begin() + 8 + sk_size);

        // Reconstruct pk from sk
        pk.resize(XMSS_OID_LEN + XMSS_PK_SIZE, 0);
        // Copy OID from sk
        for (int i = 0; i < (int)XMSS_OID_LEN; i++) {
            pk[XMSS_OID_LEN - i - 1] = (XMSS_OID >> (8 * i)) & 0xFF;
        }
        // Extract root and PUB_SEED from sk
        // sk format: [OID(4) || index(4) || SK_SEED(32) || SK_PRF(32) || PUB_SEED(32) || root(32)]
        if (sk.size() >= 104 + 32) {
            memcpy(pk.data() + XMSS_OID_LEN, sk.data() + 104, 32);      // root
            memcpy(pk.data() + XMSS_OID_LEN + 32, sk.data() + 72, 32); // PUB_SEED
        }

        valid = true;
        return true;
    }
};

/**
 * Verify a PoUW block signature.
 * Called by nodes to verify that a mined block has valid XMSS signature.
 *
 * @param block_hash  32-byte block header hash
 * @param sig         XMSS signature
 * @param pk64        64-byte miner public key (root || PUB_SEED)
 * @return true if valid PoUW
 */
inline bool VerifyPoUW(const uint8_t* block_hash,
                       const std::vector<uint8_t>& sig,
                       const uint8_t* pk64)
{
    // Build pk with OID prefix
    std::vector<uint8_t> pk(XMSS_OID_LEN + XMSS_PK_SIZE);
    pk[0] = (XMSS_OID >> 24) & 0xFF;
    pk[1] = (XMSS_OID >> 16) & 0xFF;
    pk[2] = (XMSS_OID >> 8) & 0xFF;
    pk[3] = XMSS_OID & 0xFF;
    memcpy(pk.data() + XMSS_OID_LEN, pk64, XMSS_PK_SIZE);

    // Build sm = [signature || message]
    std::vector<uint8_t> sm(sig.size() + 32);
    memcpy(sm.data(), sig.data(), sig.size());
    memcpy(sm.data() + sig.size(), block_hash, 32);

    // SNTI FIX (17/Jun/2026): m must be at least params.sig_bytes + 32
    // bytes — see xmss_bridge.cpp Verify() for the full explanation.
    xmss_params params;
    if (xmss_parse_oid(&params, XMSS_OID) != 0) {
        return false;
    }

    unsigned long long mlen = 0;
    std::vector<uint8_t> m(params.sig_bytes + 32, 0);

    int ret = xmss_sign_open(m.data(), &mlen, sm.data(),
                             (unsigned long long)sm.size(), pk.data());

    return (ret == 0);
}

/**
 * Calculate work score for difficulty comparison.
 * In PoUW v1, this is simply the SHA-256 hash of the block header.
 * The XMSS signature is verified separately as a validity check.
 *
 * Future PoUW v2 may incorporate XMSS key generation time into the score.
 */
/**
 * Calculate work score for difficulty comparison.
 * In PoUW v1, this is simply the SHA-256 hash of the block header.
 * The XMSS signature is verified separately as a validity check.
 *
 * Future PoUW v2 may incorporate XMSS key generation time into the score.
 *
 * NOTE: This function requires Bitcoin Core's hash.h (CSHA256).
 * For standalone use, provide your own SHA-256 implementation.
 */
// inline uint256_t CalculateWorkScore(const uint8_t* block_header, size_t len) {
//     CSHA256 sha;
//     sha.Write(block_header, len);
//     uint256_t result;
//     sha.Finalize(result.data());
//     return result;
// }

} // namespace PoUW
} // namespace QNT

#endif // QUANT_POUW_H
