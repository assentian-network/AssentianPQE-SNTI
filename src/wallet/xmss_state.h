// Copyright (c) 2025 The Quant developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QUANT_XMSS_STATE_H
#define QUANT_XMSS_STATE_H

/**
 * QNT XMSS State Management
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
 * QNT addresses encode the XMSS public key. Since XMSS keys are one-time-use
 * (per index), QNT addresses are effectively single-use for SENDING.
 * Receiving is always safe (public key doesn't change).
 *
 * Address lifecycle:
 *   Generate → Index 0
 *   After 1 send → Index 1 (old address still receives, but DON'T send from it)
 *   After 1024 sends → Key exhausted, generate new key pair
 *
 * For v1, QNT uses a simplified model:
 *   - One address per wallet (like Bitcoin)
 *   - After each send, the wallet generates a NEW change address
 *   - Old addresses can still receive (public key is the same)
 *   - Only the SENDING address needs index tracking
 */

extern "C" {
#include "xmss.h"
}

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <optional>

namespace QNT {
namespace XMSS {

static constexpr uint32_t QNT_XMSS_OID = 0x00000001;
static constexpr size_t QNT_XMSS_PK_SIZE = 64;
static constexpr size_t QNT_XMSS_OID_LEN = 4;
static constexpr uint32_t QNT_XMSS_MAX_SIGS = 1024;  // 2^10

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

        m_sk.resize(2048, 0);
        m_pk.resize(QNT_XMSS_OID_LEN + QNT_XMSS_PK_SIZE, 0);

        int ret = xmss_keypair(m_pk.data(), m_sk.data(), QNT_XMSS_OID);
        if (ret != 0) {
            m_valid = false;
            return false;
        }

        // Determine actual sk size
        size_t actual = 2048;
        while (actual > 4 && m_sk[actual-1] == 0) actual--;
        actual += 64;
        m_sk.resize(actual);

        m_index = 0;
        m_valid = true;
        return true;
    }

    // Sign a 32-byte hash. Returns signature or empty on failure.
    std::optional<std::vector<uint8_t>> Sign(const uint8_t* hash32) {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_valid || m_index >= QNT_XMSS_MAX_SIGS) {
            return std::nullopt;
        }

        size_t sm_buf_size = 3000;
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
        if (!m_valid || m_pk.size() < QNT_XMSS_OID_LEN + QNT_XMSS_PK_SIZE) {
            return {};
        }
        return std::vector<uint8_t>(
            m_pk.begin() + QNT_XMSS_OID_LEN,
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
        if (!m_valid) return 0;
        return QNT_XMSS_MAX_SIGS - m_index;
    }

    // Check if key is valid and has remaining signatures
    bool IsValid() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_valid && m_index < QNT_XMSS_MAX_SIGS;
    }

    // Check if key is exhausted
    bool IsExhausted() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_valid && m_index >= QNT_XMSS_MAX_SIGS;
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
        m_pk.resize(QNT_XMSS_OID_LEN + QNT_XMSS_PK_SIZE, 0);
        for (int i = 0; i < (int)QNT_XMSS_OID_LEN; i++) {
            m_pk[QNT_XMSS_OID_LEN - i - 1] = (QNT_XMSS_OID >> (8 * i)) & 0xFF;
        }
        if (m_sk.size() >= 104 + 32) {
            memcpy(m_pk.data() + QNT_XMSS_OID_LEN, m_sk.data() + 104, 32);
            memcpy(m_pk.data() + QNT_XMSS_OID_LEN + 32, m_sk.data() + 72, 32);
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
 */
inline bool VerifySignature(const uint8_t* hash32,
                            const std::vector<uint8_t>& sig,
                            const uint8_t* pk64)
{
    // Build pk with OID prefix
    std::vector<uint8_t> pk(QNT_XMSS_OID_LEN + QNT_XMSS_PK_SIZE);
    pk[0] = (QNT_XMSS_OID >> 24) & 0xFF;
    pk[1] = (QNT_XMSS_OID >> 16) & 0xFF;
    pk[2] = (QNT_XMSS_OID >> 8) & 0xFF;
    pk[3] = QNT_XMSS_OID & 0xFF;
    memcpy(pk.data() + QNT_XMSS_OID_LEN, pk64, QNT_XMSS_PK_SIZE);

    // Build sm = [signature || message]
    std::vector<uint8_t> sm(sig.size() + 32);
    memcpy(sm.data(), sig.data(), sig.size());
    memcpy(sm.data() + sig.size(), hash32, 32);

    unsigned long long mlen = 0;
    std::vector<uint8_t> m(32, 0);

    int ret = xmss_sign_open(m.data(), &mlen, sm.data(),
                             (unsigned long long)sm.size(), pk.data());

    return (ret == 0);
}

} // namespace XMSS
} // namespace QNT

#endif // QUANT_XMSS_STATE_H
