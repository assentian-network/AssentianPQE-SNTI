// Copyright (c) 2025 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_XMSS_SIGNER_H
#define BITCOIN_WALLET_XMSS_SIGNER_H

#include <script/signingprovider.h>
#include <script/solver.h>
#include <script/script.h>
#include <xmss_bridge.h>
#include <wallet/xmss_address.h>
#include <wallet/xmss_state.h>
#include <sync.h>

#include <map>
#include <vector>
#include <string>
#include <mutex>

namespace wallet {

/**
 * SNTI: XMSS Wallet Signer
 *
 * Manages XMSS key pairs for transaction signing.
 * XMSS is stateful — each signature advances the leaf index.
 * The key state MUST be persisted after every sign operation.
 *
 * This class wraps XMSS::CXMSSKey and provides the SigningProvider
 * interface for integration with Bitcoin Core's transaction signing flow.
 *
 * Key identification:
 *   - XMSS keys are identified by their 64-byte public key (root || PUB_SEED)
 *   - We use a custom address type for XMSS (not CKeyID which is RIPEMD160(SHA256(pubkey)))
 *   - Address = Base58Check(0x01 || SHA256(pubkey)[0:20]) — similar to P2PKH but different prefix
 */
class CXMSSSigner : public SigningProvider
{
public:
    CXMSSSigner() = default;

    // Disable copy (key material)
    CXMSSSigner(const CXMSSSigner&) = delete;
    CXMSSSigner& operator=(const CXMSSSigner&) = delete;

    // Allow move
    CXMSSSigner(CXMSSSigner&&) = default;
    CXMSSSigner& operator=(CXMSSSigner&&) = default;

    /**
     * Add an XMSS key pair to this signer.
     * Takes ownership of the key material.
     * @param pubkey 64-byte public key (root || PUB_SEED)
     * @param seckey Full secret key (with OID prefix)
     * @return true on success
     */
    bool AddXMSSKey(const std::vector<uint8_t>& pubkey, const std::vector<uint8_t>& seckey);

    /**
     * Generate a new XMSS key pair and add it to the signer.
     * @param label Human-readable label for the key
     * @return The 64-byte public key of the generated key, empty on failure
     */
    std::vector<uint8_t> GenerateKey(const std::string& label = "");

    /**
     * Check if we have the private key for a given XMSS public key.
     * @param pubkey 64-byte XMSS public key
     * @return true if we can sign with this key
     */
    bool HaveKey(const std::vector<uint8_t>& pubkey) const;

    /**
     * Get the current leaf index for a key.
     * @param pubkey 64-byte XMSS public key
     * @return leaf index, or 0 if key not found
     */
    uint32_t GetLeafIndex(const std::vector<uint8_t>& pubkey) const;

    /**
     * Get all XMSS public keys managed by this signer.
     * @return vector of 64-byte public keys
     */
    std::vector<std::vector<uint8_t>> GetXMSSKeys() const;

    /**
     * Sign a hash with the XMSS key corresponding to the given public key.
     * This is stateful — the key's leaf index advances after signing.
     * @param hash 32-byte hash to sign
     * @param pubkey 64-byte XMSS public key
     * @param sig Output: XMSS signature (~2500 bytes)
     * @return true on success
     */
    bool Sign(const uint256& hash, const std::vector<uint8_t>& pubkey, std::vector<uint8_t>& sig);

    // SigningProvider interface
    bool GetCScript(const CScriptID& scriptid, CScript& script) const override { return false; }
    bool HaveCScript(const CScriptID& scriptid) const override { return false; }
    bool GetPubKey(const CKeyID& address, CPubKey& pubkey) const override;
    bool GetKey(const CKeyID& address, CKey& key) const override;
    bool HaveKey(const CKeyID& address) const override;
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override { return false; }
    bool GetTaprootSpendData(const XOnlyPubKey& output_key, TaprootSpendData& spenddata) const override { return false; }
    bool GetTaprootBuilder(const XOnlyPubKey& output_key, TaprootBuilder& builder) const override { return false; }

    // SNTI: XMSS signing support
    bool SignXMSS(const uint256& hash, const std::vector<uint8_t>& pubkey, std::vector<uint8_t>& sig) const override;
    bool HaveXMSSKey(const std::vector<uint8_t>& pubkey) const override;
    std::vector<uint8_t> GetXMSSPubKey(const CKeyID& address) const override;
    uint32_t GetXMSSLeafIndex(const std::vector<uint8_t>& pubkey) const override;
    uint32_t GetXMSSChainId() const override;

    // SNTI: State persistence — save/load all key states to/from a blob
    // Returns serialized state for all keys (QXMSS format from xmss_state.h)
    std::vector<uint8_t> SaveState() const;
    // Load key states from serialized blob
    bool LoadState(const std::vector<uint8_t>& data);
    // Check if any key is near exhaustion (< 10% remaining)
    bool HasExhaustedKeys() const;
    // Count keys that have not yet been used (retired == false)
    uint32_t CountFreshKeys() const;

    // SNTI (gap #3): check if a key has already signed once and is
    // therefore permanently retired (one-time-address enforcement).
    bool IsXMSSKeyRetired(const std::vector<uint8_t>& pubkey) const;

    // SNTI: Get pubkey by address hash (uint160 / CKeyID)
    std::vector<uint8_t> GetPubKeyForHash(const uint160& addr_hash) const;

    /**
     * Get the secret key bytes for a given XMSS public key.
     * WARNING: handle with extreme care.
     * @param pubkey 64-byte XMSS public key
     * @return serialized secret key bytes, or empty if not found
     */
    std::vector<uint8_t> GetSecKeyForPubkey(const std::vector<uint8_t>& pubkey) const;

private:
    mutable RecursiveMutex cs_xmss_signer;

    struct XMSSKeyEntry {
        XMSS::CXMSSKey key;
        std::vector<uint8_t> pubkey;  // 64-byte pubkey (root || PUB_SEED)
        std::string label;
        uint32_t leaf_index{0};
        // SNTI (gap #3): true once this key has signed -- every XMSS
        // address is treated as one-time-use ("swept" address), so a
        // retired key must never be allowed to sign again even if leaf
        // indices remain technically available.
        bool retired{false};
        // SNTI fix (1 Jul 2026): true if this key's sk arrived via
        // AddXMSSKey() (importxmsskey RPC, i.e. sk material generated by
        // some OTHER system such as the miner) rather than this wallet's
        // own GenerateKey(). An imported key with no unified-ledger file
        // (xmss_tree_ledger.h) is a tree whose true leaf progress this
        // wallet cannot verify -- it may have been mined past leaf 0 by
        // whatever system produced it, including after rotating away from
        // being that system's "active" tree before the ledger existed to
        // adopt it. SignXMSS() must refuse such keys outright rather than
        // fall back to the one-shot policy below, which assumes (safely,
        // for GenerateKey()-created keys) that this wallet is the sole
        // holder of the key's state.
        bool imported{false};

        XMSSKeyEntry() = default;
        XMSSKeyEntry(XMSSKeyEntry&&) = default;
        XMSSKeyEntry& operator=(XMSSKeyEntry&&) = default;
        XMSSKeyEntry(const XMSSKeyEntry&) = delete;
        XMSSKeyEntry& operator=(const XMSSKeyEntry&) = delete;
    };

    // Map from 64-byte pubkey → key entry
    std::map<std::vector<uint8_t>, XMSSKeyEntry> xmss_keys GUARDED_BY(cs_xmss_signer);

    // Map from CKeyID (hash of pubkey) → 64-byte pubkey for SigningProvider interface
    std::map<CKeyID, std::vector<uint8_t>> key_id_map GUARDED_BY(cs_xmss_signer);

    /**
     * Compute a CKeyID-like identifier for an XMSS public key.
     * Uses HASH160 of the 64-byte pubkey (same as Bitcoin P2PKH but different version byte).
     */
    static CKeyID GetXMSSKeyID(const std::vector<uint8_t>& pubkey);
};

/**
 * SNTI: XMSS Script parsing helper
 *
 * Detects XMSS script types. XMSS scripts use 64-byte public keys
 * (vs 33/65-byte for ECDSA, 32-byte for Schnorr).
 *
 * XMSS script types:
 *   - P2XMSS: OP_XMSS_CHECKSIG <64-byte-pubkey>
 *   - P2XMSSHASH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_XMSS_CHECKSIG
 */
constexpr size_t XMSS_PUBKEY_SIZE = 64;

/** Check if a script is an XMSS script (contains 64-byte pubkey) */
bool IsXMSSScript(const CScript& script);

/** Extract 64-byte XMSS public key from a script */
std::vector<uint8_t> GetXMSSPubkeyFromScript(const CScript& script);

/** Create a P2XMSS output script for a 64-byte public key */
CScript GetXMSSScriptForPubkey(const std::vector<uint8_t>& pubkey);

/** Create a P2XMSSHASH output script for a 64-byte public key */
CScript GetXMSSHashScriptForPubkey(const std::vector<uint8_t>& pubkey);

} // namespace wallet

#endif // BITCOIN_WALLET_XMSS_SIGNER_H
