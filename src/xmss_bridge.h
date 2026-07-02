// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_XMSS_BRIDGE_H
#define BITCOIN_XMSS_BRIDGE_H

// C++ standard headers must NOT be inside extern "C"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <stdexcept>
#include <string>

// C headers wrapped in extern "C"
extern "C" {
#include "xmss.h"
#include "params.h"
}

namespace XMSS {

// XMSS parameter set: SHA2, height=10, 256-bit security
static constexpr uint32_t XMSS_OID_SHA2_10_256 = 0x00000001;

using SecureVec = std::vector<uint8_t>;

/**
 * CXMSSKey - C++ wrapper for XMSS (eXtended Merkle Signature Scheme)
 *
 * Implements stateful XMSS signing. The secret key is updated after
 * each call to Sign(), so the serialized key must be persisted
 * back to disk/state after each use.
 *
 * XMSS-SHA2_10_256 parameter set: 2^10 = 1024 signatures per key.
 */
class CXMSSKey
{
public:
    CXMSSKey();
    ~CXMSSKey();

    // Disable copy to prevent accidental key duplication
    CXMSSKey(const CXMSSKey&) = delete;
    CXMSSKey& operator=(const CXMSSKey&) = delete;

    // Allow move
    CXMSSKey(CXMSSKey&& other) noexcept;
    CXMSSKey& operator=(CXMSSKey&& other) noexcept;

    /**
     * Generate a new XMSS key pair.
     * @return true on success, false on failure
     */
    bool Generate();

    /**
     * Sign a 32-byte hash (e.g., SHA256 digest).
     * This is stateful - the internal secret key is updated after each sign.
     * @param hash  32-byte message hash to sign
     * @param sig   Output: signature bytes
     * @return true on success, false on failure
     */
    bool Sign(const std::vector<uint8_t>& hash, std::vector<uint8_t>& sig);

    /**
     * Verify a signature.
     * @param hash          32-byte message hash
     * @param sig           Signature bytes (as produced by Sign)
     * @param pubkey_bytes  64-byte public key (root || PUB_SEED)
     * @return true if signature is valid, false otherwise
     */
    bool Verify(const std::vector<uint8_t>& hash,
                const std::vector<uint8_t>& sig,
                const std::vector<uint8_t>& pubkey_bytes);

    /**
     * Get the public key (64 bytes: root || PUB_SEED).
     * Only available after Generate() or Load().
     * @return 64-byte public key
     */
    std::vector<uint8_t> GetPubKey() const;

    /**
     * Serialize the secret key.
     * @return serialized secret key bytes
     */
    std::vector<uint8_t> GetPrivKey() const;

    /**
     * Load a key from serialized secret key bytes.
     * Derives the public key from the secret key.
     * @param sk_bytes serialized secret key from GetPrivKey()
     * @return true on success, false on failure
     */
    bool Load(const std::vector<uint8_t>& sk_bytes);

    /**
     * Check if the key is valid (has been generated or loaded).
     * @return true if the key is ready for use
     */
    bool IsValid() const { return m_has_key; }

    /**
     * Securely wipe all key material from memory.
     */
    void Clear();

private:
    unsigned char* m_pk;  // Public key buffer (includes OID prefix)
    unsigned char* m_sk;  // Secret key buffer (includes OID prefix)
    size_t m_pk_len;
    size_t m_sk_len;
    bool m_has_key;

    // Helper to zero memory securely
    static void SecureClear(void* ptr, size_t len);
};

/**
 * SNTI PoUW v2 (audit T-1): rebuild the XMSS root deterministically from a
 * claimed 96-byte seed [SK_SEED(32) | SK_PRF(32) | PUB_SEED(32)].
 * Used by consensus validation to confirm a Failed-Seed-List entry's
 * xmss_root actually derives from its claimed sk_seed (not an arbitrary
 * value submitted by a dishonest miner).
 * @param seed96    96-byte seed material
 * @param out_root  Output: 32-byte computed XMSS root
 * @return true on success, false on failure
 */
bool ComputeRootFromSeed(const std::vector<uint8_t>& seed96, std::vector<uint8_t>& out_root);

} // namespace XMSS

#endif // BITCOIN_XMSS_BRIDGE_H
