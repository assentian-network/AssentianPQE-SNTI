// Copyright (c) 2025-2026 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SNTI M1/M2: CXMSSKeyStore is a legacy class from the "Quant" codebase era.
// The canonical wallet signing path uses wallet::CXMSSSigner (xmss_signer.h),
// which integrates with SigningProvider and persists state via CWallet.
// CXMSSKeyStore does NOT fsync after signing and must not be used for
// transaction signing — XMSS leaf reuse from a missed persist leaks the key.
#ifndef BITCOIN_WALLET_XMSS_KEYSTORE_H
#define BITCOIN_WALLET_XMSS_KEYSTORE_H

#include <xmss_bridge.h>
#include <sync.h>
#include <serialize.h>
#include <util/time.h>
#include <logging.h>

#include <map>
#include <vector>
#include <string>
#include <mutex>

// SNTI: XMSS wallet key entry
// Stores an XMSS keypair with metadata
struct CXMSSKeyEntry {
    std::vector<uint8_t> pubkey;   // 64-byte XMSS public key (root || PUB_SEED)
    std::vector<uint8_t> seckey;   // Serialized XMSS secret key
    uint32_t leaf_index;           // Current leaf index (XMSS is stateful!)
    std::string label;             // Human-readable label
    int64_t creation_time;         // Unix timestamp

    CXMSSKeyEntry() : leaf_index(0), creation_time(0) {}

    SERIALIZE_METHODS(CXMSSKeyEntry, obj) {
        READWRITE(obj.pubkey, obj.seckey, obj.leaf_index, obj.label, obj.creation_time);
    }
};

/** SNTI: XMSS Wallet Key Store
 *
 * Manages XMSS keypairs for the wallet.
 *
 * CRITICAL: XMSS is stateful. Each signature consumes one leaf.
 * The leaf_index MUST be persisted after every sign operation.
 * If a leaf is reused, the security of the scheme is compromised.
 */
class CXMSSKeyStore
{
private:
    mutable RecursiveMutex cs_xmss;
    std::map<std::vector<uint8_t>, CXMSSKeyEntry> xmss_keys GUARDED_BY(cs_xmss); // pubkey → entry

public:
    CXMSSKeyStore() = default;

    /** Generate a new XMSS keypair and store it */
    std::vector<uint8_t> GenerateKey(const std::string& label = "")
    {
        LOCK(cs_xmss);

        XMSS::CXMSSKey key;
        if (!key.Generate()) {
            throw std::runtime_error("CXMSSKeyStore::GenerateKey: XMSS key generation failed");
        }

        CXMSSKeyEntry entry;
        entry.pubkey = key.GetPubKey();
        entry.seckey = key.GetPrivKey();
        entry.leaf_index = 0;
        entry.label = label;
        entry.creation_time = GetTime();

        std::vector<uint8_t> pubkey_copy = entry.pubkey;
        xmss_keys[pubkey_copy] = std::move(entry);

        return pubkey_copy;
    }

    /** Import an existing XMSS keypair from serialized secret key */
    std::vector<uint8_t> ImportKey(const std::vector<uint8_t>& seckey, const std::string& label = "")
    {
        LOCK(cs_xmss);

        XMSS::CXMSSKey key;
        if (!key.Load(seckey)) {
            throw std::runtime_error("CXMSSKeyStore::ImportKey: Failed to load XMSS key");
        }

        CXMSSKeyEntry entry;
        entry.pubkey = key.GetPubKey();
        entry.seckey = seckey;
        entry.leaf_index = 0;
        entry.label = label;
        entry.creation_time = GetTime();

        std::vector<uint8_t> pubkey_copy = entry.pubkey;
        xmss_keys[pubkey_copy] = std::move(entry);

        return pubkey_copy;
    }

    /** Sign a hash with the XMSS key identified by pubkey.
     *  Updates the leaf_index after signing (stateful!).
     *  Returns the signature, or empty vector on failure.
     *
     *  NOTE: This method is NOT the active transaction-signing path.
     *  Real transaction signing goes through CXMSSSigner::SignXMSS() which
     *  calls CWallet::PersistXMSSState() (with fsync) immediately after.
     *  Do NOT call this directly without arranging persistent storage of the
     *  updated leaf_index and seckey — XMSS leaf reuse allows private-key
     *  recovery from two signatures with the same index.
     */
    std::vector<uint8_t> Sign(const std::vector<uint8_t>& pubkey, const std::vector<uint8_t>& hash)
    {
        LOCK(cs_xmss);

        auto it = xmss_keys.find(pubkey);
        if (it == xmss_keys.end()) {
            return {};
        }

        CXMSSKeyEntry& entry = it->second;

        if (entry.leaf_index >= 1024) {
            LogPrintf("CXMSSKeyStore::Sign: key exhausted (leaf_index=%u >= 1024), refusing to sign\n", entry.leaf_index);
            return {};
        }

        XMSS::CXMSSKey key;
        if (!key.Load(entry.seckey)) {
            return {};
        }

        std::vector<uint8_t> sig;
        if (!key.Sign(hash, sig)) {
            return {};
        }

        // CRITICAL: Update leaf index after successful sign
        entry.leaf_index++;

        // Update secret key serialization (internal state changed)
        entry.seckey = key.GetPrivKey();

        return sig;
    }

    /** Verify an XMSS signature */
    bool Verify(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pubkey) const
    {
        LOCK(cs_xmss);
        XMSS::CXMSSKey key;
        return key.Verify(hash, sig, pubkey);
    }

    /** Check if we have the private key for a given pubkey */
    bool HaveKey(const std::vector<uint8_t>& pubkey) const
    {
        LOCK(cs_xmss);
        return xmss_keys.count(pubkey) > 0;
    }

    /** Get the public key for a given pubkey (identity — just validates existence) */
    std::vector<uint8_t> GetPubKey(const std::vector<uint8_t>& pubkey) const
    {
        LOCK(cs_xmss);
        auto it = xmss_keys.find(pubkey);
        if (it != xmss_keys.end()) {
            return it->second.pubkey;
        }
        return {};
    }

    /** Get all XMSS public keys */
    std::vector<std::vector<uint8_t>> GetXMSSKeys() const
    {
        LOCK(cs_xmss);
        std::vector<std::vector<uint8_t>> result;
        result.reserve(xmss_keys.size());
        for (const auto& [pubkey, entry] : xmss_keys) {
            result.push_back(pubkey);
        }
        return result;
    }

    /** Get key entry (for persistence) */
    bool GetKeyEntry(const std::vector<uint8_t>& pubkey, CXMSSKeyEntry& entry) const
    {
        LOCK(cs_xmss);
        auto it = xmss_keys.find(pubkey);
        if (it != xmss_keys.end()) {
            entry = it->second;
            return true;
        }
        return false;
    }

    /** Get all key entries (for wallet save) */
    std::vector<CXMSSKeyEntry> GetAllKeyEntries() const
    {
        LOCK(cs_xmss);
        std::vector<CXMSSKeyEntry> result;
        result.reserve(xmss_keys.size());
        for (const auto& [pubkey, entry] : xmss_keys) {
            result.push_back(entry);
        }
        return result;
    }

    /** Restore key entries (for wallet load) */
    void RestoreKeyEntries(const std::vector<CXMSSKeyEntry>& entries)
    {
        LOCK(cs_xmss);
        xmss_keys.clear();
        for (const auto& entry : entries) {
            xmss_keys[entry.pubkey] = entry;
        }
    }

    /** Get remaining signatures count for a key */
    uint32_t GetRemainingSignatures(const std::vector<uint8_t>& pubkey) const
    {
        LOCK(cs_xmss);
        auto it = xmss_keys.find(pubkey);
        if (it != xmss_keys.end()) {
            // XMSS-SHA2_10_256 has 2^10 = 1024 signatures.
            // Guard against underflow if leaf_index somehow exceeds 1024.
            if (it->second.leaf_index >= 1024) return 0;
            return 1024 - it->second.leaf_index;
        }
        return 0;
    }
};

#endif // BITCOIN_WALLET_XMSS_KEYSTORE_H
