// Copyright (c) 2025 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QUANT_XMSS_STATE_H
#define QUANT_XMSS_STATE_H

/**
 * SNTI XMSS State Management
 *
 * XMSS is a STATEFUL signature scheme. Each private key can produce exactly
 * 2^h signatures (1024 for XMSS-SHA2_10_256). After each signature, the
 * internal state (index) advances. CRITICAL RULES:
 *
 *   1. NEVER reuse a key index — doing so leaks the private key
 *   2. ALWAYS persist key state after each sign
 *   3. ALWAYS verify key state before signing
 *   4. ALWAYS check remaining signatures before signing
 *
 * SNTI addresses encode the XMSS public key. Since XMSS keys are one-time-use
 * (per index), SNTI addresses are effectively single-use for SENDING.
 * Receiving is always safe (public key doesn't change).
 *
 * Address lifecycle:
 *   Generate → Index 0
 *   After 1 send → Index 1 (old address still receives, but DON'T send from it)
 *   After 1024 sends → Key exhausted, generate new key pair
 *
 * For v1, SNTI uses a simplified model:
 *   - One address per wallet (like Bitcoin)
 *   - After each send, the wallet generates a NEW change address
 *   - Old addresses can still receive (public key is the same)
 *   - Only the SENDING address needs index tracking
 */

extern "C" {
#include "xmss.h"
#include "params.h"
}

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <optional>

namespace SNTI {
namespace XMSS {

static constexpr uint32_t SNTI_XMSS_OID = 0x00000001;
static constexpr size_t SNTI_XMSS_PK_SIZE = 64;
static constexpr size_t SNTI_XMSS_OID_LEN = 4;
static constexpr uint32_t SNTI_XMSS_MAX_SIGS = 1024;  // 2^10

/**
 * Key state for a single XMSS key pair.
 * Thread-safe with mutex.
 */
class KeyState {
public:
    KeyState() : m_index(0), m_valid(false) {}

    // Generate new key pair
    bool Generate() {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Allocate exactly the right size using params (no trailing-zero trimming)
        xmss_params xp;
        if (xmss_parse_oid(&xp, SNTI_XMSS_OID) != 0) {
            m_valid = false;
            return false;
        }
        size_t sk_buf = SNTI_XMSS_OID_LEN + (size_t)xp.sk_bytes;

        m_sk.resize(sk_buf, 0);
        m_pk.resize(SNTI_XMSS_OID_LEN + SNTI_XMSS_PK_SIZE, 0);

        int ret = xmss_keypair(m_pk.data(), m_sk.data(), SNTI_XMSS_OID);
        if (ret != 0) {
            m_valid = false;
            return false;
        }

        m_index = 0;
        m_valid = true;
        return true;
    }

    // Sign a 32-byte hash. Returns signature or empty on failure.
    std::optional<std::vector<uint8_t>> Sign(const uint8_t* hash32) {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_valid || m_index >= SNTI_XMSS_MAX_SIGS) {
            return std::nullopt;
        }

        // Derive buffer size from params rather than hardcoding 3000.
        // xmss_sign writes sig_bytes + message_len bytes into sm.
        xmss_params xp_sign;
        if (xmss_parse_oid(&xp_sign, SNTI_XMSS_OID) != 0) return std::nullopt;
        size_t sm_buf_size = xp_sign.sig_bytes + 32 + 64; // sig + msg + safety margin
        std::vector<uint8_t> sm(sm_buf_size, 0);
        unsigned long long smlen = 0;

        std::vector<uint8_t> sk_copy(m_sk.begin(), m_sk.end());

        int ret = xmss_sign(sk_copy.data(), sm.data(), &smlen, hash32, 32);
        if (ret != 0 || smlen < 32) {
            return std::nullopt;
        }

        size_t sig_len = (size_t)smlen - 32;
        std::vector<uint8_t> sig(sm.begin(), sm.begin() + sig_len);

        // Update key state
        m_sk = sk_copy;
        m_index++;

        return sig;
    }

    // Get 64-byte public key (root || PUB_SEED)
    std::vector<uint8_t> GetPubKey64() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_valid || m_pk.size() < SNTI_XMSS_OID_LEN + SNTI_XMSS_PK_SIZE) {
            return {};
        }
        return std::vector<uint8_t>(
            m_pk.begin() + SNTI_XMSS_OID_LEN,
            m_pk.end()
        );
    }

    // Get full public key with OID prefix
    std::vector<uint8_t> GetPubKeyFull() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pk;
    }

    // Get current index
    uint32_t GetIndex() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_index;
    }

    // Get remaining signatures
    uint32_t GetRemaining() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_valid || m_index >= SNTI_XMSS_MAX_SIGS) return 0;
        return SNTI_XMSS_MAX_SIGS - m_index;
    }

    // Check if key is valid and has remaining signatures
    bool IsValid() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_valid && m_index < SNTI_XMSS_MAX_SIGS;
    }

    // Check if key is exhausted
    bool IsExhausted() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_valid && m_index >= SNTI_XMSS_MAX_SIGS;
    }

    // Serialize for persistence
    std::vector<uint8_t> Serialize() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<uint8_t> data;

        // Magic: "QXMSS" (5 bytes)
        data.push_back('Q');
        data.push_back('X');
        data.push_back('M');
        data.push_back('S');
        data.push_back('S');

        // Version (1 byte)
        data.push_back(1);

        // Index (4 bytes, big-endian)
        data.push_back((m_index >> 24) & 0xFF);
        data.push_back((m_index >> 16) & 0xFF);
        data.push_back((m_index >> 8) & 0xFF);
        data.push_back(m_index & 0xFF);

        // Valid flag (1 byte)
        data.push_back(m_valid ? 1 : 0);

        // SK size (4 bytes, big-endian)
        uint32_t sk_size = (uint32_t)m_sk.size();
        data.push_back((sk_size >> 24) & 0xFF);
        data.push_back((sk_size >> 16) & 0xFF);
        data.push_back((sk_size >> 8) & 0xFF);
        data.push_back(sk_size & 0xFF);

        // SK data
        data.insert(data.end(), m_sk.begin(), m_sk.end());

        // PK data
        data.insert(data.end(), m_pk.begin(), m_pk.end());

        return data;
    }

    // Deserialize from persisted data
    bool Deserialize(const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Check magic
        if (data.size() < 14) return false;
        if (data[0] != 'Q' || data[1] != 'X' || data[2] != 'M' ||
            data[3] != 'S' || data[4] != 'S') {
            return false;
        }

        // Version
        if (data[5] != 1) return false;

        // Index
        m_index = ((uint32_t)data[6] << 24) | ((uint32_t)data[7] << 16) |
                  ((uint32_t)data[8] << 8) | (uint32_t)data[9];

        // Valid
        m_valid = (data[10] != 0);

        // SK size
        uint32_t sk_size = ((uint32_t)data[11] << 24) | ((uint32_t)data[12] << 16) |
                           ((uint32_t)data[13] << 8) | (uint32_t)data[14];

        if (data.size() < 15 + sk_size) return false;

        m_sk.assign(data.begin() + 15, data.begin() + 15 + sk_size);

        // Reconstruct PK from SK
        m_pk.resize(SNTI_XMSS_OID_LEN + SNTI_XMSS_PK_SIZE, 0);
        for (int i = 0; i < (int)SNTI_XMSS_OID_LEN; i++) {
            m_pk[SNTI_XMSS_OID_LEN - i - 1] = (SNTI_XMSS_OID >> (8 * i)) & 0xFF;
        }
        if (m_sk.size() >= 104 + 32) {
            memcpy(m_pk.data() + SNTI_XMSS_OID_LEN, m_sk.data() + 104, 32);
            memcpy(m_pk.data() + SNTI_XMSS_OID_LEN + 32, m_sk.data() + 72, 32);
        }

        return m_valid;
    }

    // Securely wipe key material
    void Clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        memset(m_sk.data(), 0, m_sk.size());
        memset(m_pk.data(), 0, m_pk.size());
        m_sk.clear();
        m_pk.clear();
        m_index = 0;
        m_valid = false;
    }

private:
    mutable std::mutex m_mutex;
    std::vector<uint8_t> m_sk;
    std::vector<uint8_t> m_pk;
    uint32_t m_index;
    bool m_valid;
};

/**
 * Verify an XMSS signature against a public key.
 * This is the node-side verification — no secret key needed.
 *
 * XMSS-SHA2_10_256 sig_bytes = idx(4) + R(32) + WOTS(2144) + auth(320) = 2500.
 * xmss_sign_open writes (smlen - sig_bytes) bytes into the output buffer.
 * With smlen = sig.size() + 32, that is (sig.size() + 32 - 2500) bytes written.
 * For sig.size() > 2500 this exceeds the 32-byte message buffer → heap overflow.
 * Guard: reject any signature whose size != 2500 before calling the library.
 */
inline bool VerifySignature(const uint8_t* hash32,
                            const std::vector<uint8_t>& sig,
                            const uint8_t* pk64)
{
    // XMSS-SHA2_10_256 signatures are exactly 2500 bytes.
    // Reject early to prevent xmss_sign_open writing past the 32-byte output buffer.
    xmss_params params;
    if (xmss_parse_oid(&params, SNTI_XMSS_OID) != 0) return false;
    if (sig.size() != params.sig_bytes) return false;

    // Build pk with OID prefix
    std::vector<uint8_t> pk(SNTI_XMSS_OID_LEN + SNTI_XMSS_PK_SIZE);
    pk[0] = (SNTI_XMSS_OID >> 24) & 0xFF;
    pk[1] = (SNTI_XMSS_OID >> 16) & 0xFF;
    pk[2] = (SNTI_XMSS_OID >> 8) & 0xFF;
    pk[3] = SNTI_XMSS_OID & 0xFF;
    memcpy(pk.data() + SNTI_XMSS_OID_LEN, pk64, SNTI_XMSS_PK_SIZE);

    // Build sm = [signature || message]. smlen = sig_bytes + 32,
    // so xmss_sign_open writes exactly 32 bytes into m — safe.
    std::vector<uint8_t> sm(sig.size() + 32);
    memcpy(sm.data(), sig.data(), sig.size());
    memcpy(sm.data() + sig.size(), hash32, 32);

    unsigned long long mlen = 0;
    std::vector<uint8_t> m(32, 0);

    int ret = xmss_sign_open(m.data(), &mlen, sm.data(),
                             (unsigned long long)sm.size(), pk.data());

    return (ret == 0 && mlen == 32);
}

} // namespace XMSS
} // namespace SNTI

#endif // QUANT_XMSS_STATE_H
