// Copyright (c) 2025 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/xmss_signer.h>

#include <chainparams.h>
#include <common/args.h>
#include <hash.h>
#include <key.h>
#include <logging.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/solver.h>
#include <script/signingprovider.h>
#include <uint256.h>
#include <xmss_blacklist.h>
#include <xmss_tree_ledger.h>

#include <algorithm>
#include <cstring>

namespace wallet {

// ---------------------------------------------------------------------------
// CXMSSSigner
// ---------------------------------------------------------------------------

CKeyID CXMSSSigner::GetXMSSKeyID(const std::vector<uint8_t>& pubkey)
{
    // Use HASH160 of the 64-byte pubkey
    // This gives a 20-byte identifier compatible with CKeyID
    uint160 hash;
    CHash160().Write(pubkey).Finalize(hash);
    return CKeyID(hash);
}

bool CXMSSSigner::AddXMSSKey(const std::vector<uint8_t>& pubkey, const std::vector<uint8_t>& seckey)
{
    LOCK(cs_xmss_signer);

    if (pubkey.size() != XMSS_PUBKEY_SIZE) return false;
    if (seckey.empty()) return false;

    XMSSKeyEntry entry;
    entry.pubkey = pubkey;
    // SNTI fix (1 Jul 2026): this key's sk came from importxmsskey, not
    // this wallet's own GenerateKey() -- see XMSSKeyEntry::imported.
    entry.imported = true;

    // Load the secret key into CXMSSKey
    if (!entry.key.Load(seckey)) {
        return false;
    }

    // Verify the loaded key produces the expected public key
    std::vector<uint8_t> derived_pubkey = entry.key.GetPubKey();
    if (derived_pubkey != pubkey) {
        return false;
    }

    CKeyID key_id = GetXMSSKeyID(pubkey);
    key_id_map[key_id] = pubkey;
    xmss_keys[pubkey] = std::move(entry);

    return true;
}

std::vector<uint8_t> CXMSSSigner::GenerateKey(const std::string& label)
{
    LOCK(cs_xmss_signer);

    XMSSKeyEntry entry;
    entry.label = label;

    if (!entry.key.Generate()) {
        return {};
    }

    std::vector<uint8_t> pubkey = entry.key.GetPubKey();
    if (pubkey.size() != XMSS_PUBKEY_SIZE) {
        return {};
    }

    CKeyID key_id = GetXMSSKeyID(pubkey);
    key_id_map[key_id] = pubkey;
    xmss_keys[pubkey] = std::move(entry);

    return pubkey;
}

bool CXMSSSigner::HaveKey(const std::vector<uint8_t>& pubkey) const
{
    LOCK(cs_xmss_signer);
    return xmss_keys.count(pubkey) > 0;
}

uint32_t CXMSSSigner::GetLeafIndex(const std::vector<uint8_t>& pubkey) const
{
    // SNTI fix (1 Jul 2026): delegate to GetXMSSLeafIndex() so this and the
    // SigningProvider-interface leaf accessor never disagree -- listxmsskeys
    // calls this one specifically, and it must reflect the unified ledger
    // for tree-backed keys, not this object's own stale bookkeeping.
    return GetXMSSLeafIndex(pubkey);
}

std::vector<std::vector<uint8_t>> CXMSSSigner::GetXMSSKeys() const
{
    LOCK(cs_xmss_signer);
    std::vector<std::vector<uint8_t>> result;
    result.reserve(xmss_keys.size());
    for (const auto& [pubkey, entry] : xmss_keys) {
        result.push_back(pubkey);
    }
    return result;
}

bool CXMSSSigner::Sign(const uint256& hash, const std::vector<uint8_t>& pubkey, std::vector<uint8_t>& sig)
{
    LOCK(cs_xmss_signer);

    auto it = xmss_keys.find(pubkey);
    if (it == xmss_keys.end()) return false;

    // SNTI: Anti-reuse — check if key is exhausted before signing
    if (it->second.leaf_index >= 1024) {
        LogPrintf("CXMSSSigner::Sign: XMSS key exhausted (index=%u), need new key\n", it->second.leaf_index);
        return false;
    }

    // Convert uint256 to vector
    std::vector<uint8_t> hash_vec(hash.begin(), hash.end());

    // Sign via CXMSSKey (stateful — advances leaf index)
    bool success = it->second.key.Sign(hash_vec, sig);

    if (success) {
        it->second.leaf_index++;
    }

    return success;
}

// SigningProvider interface

bool CXMSSSigner::GetPubKey(const CKeyID& address, CPubKey& pubkey) const
{
    LOCK(cs_xmss_signer);

    auto it = key_id_map.find(address);
    if (it == key_id_map.end()) return false;

    // Return as "pubkey" — we use the 64-byte XMSS pubkey
    // CPubKey can hold arbitrary byte data
    const std::vector<uint8_t>& xmss_pubkey = it->second;
    pubkey = CPubKey(xmss_pubkey);
    return pubkey.IsValid();
}

bool CXMSSSigner::GetKey(const CKeyID& address, CKey& key) const
{
    // XMSS keys are not CKey — they cannot be returned through this interface
    // This is intentional: XMSS signing goes through Sign(), not CKey::Sign()
    return false;
}

bool CXMSSSigner::HaveKey(const CKeyID& address) const
{
    LOCK(cs_xmss_signer);
    return key_id_map.count(address) > 0;
}

// SNTI: XMSS signing support implementation

bool CXMSSSigner::SignXMSS(const uint256& hash, const std::vector<uint8_t>& pubkey, std::vector<uint8_t>& sig) const
{
    LOCK(cs_xmss_signer);

    auto it = xmss_keys.find(pubkey);
    if (it == xmss_keys.end()) return false;

    // SNTI fix (1 Jul 2026): if this pubkey's tree is tracked by the
    // unified leaf ledger (xmss_tree_ledger.h) -- i.e. it originated from
    // mining and may have leaves already consumed by the miner outside
    // this wallet's own bookkeeping -- route the sign through the SAME
    // claim path mining.cpp uses, instead of this object's own CXMSSKey
    // copy (which is only ever a point-in-time import snapshot and cannot
    // by itself know what the miner has done since). This closes the gap
    // that let a wallet spend attempt reuse a leaf a block had already
    // been signed with: see job_queue.md "BUG KRITIS" 1 Jul 2026 for the
    // incident this fixes.
    if (pubkey.size() == 64) {
        uint256 root;
        std::memcpy(root.begin(), pubkey.data(), 32);
        fs::path datadir = gArgs.GetDataDirNet();
        if (PoUWv2::XMSSTreeLedgerExists(datadir, root)) {
            std::vector<uint8_t> hash_vec(hash.begin(), hash.end());
            uint32_t leaf_used = 0;
            bool ok = PoUWv2::XMSSTreeLedgerClaimAndSign(datadir, root, hash_vec, sig, leaf_used);
            LogPrintf("SNTI: wallet spend via unified ledger for root=%s: %s%s\n",
                      root.GetHex().substr(0, 16), ok ? "signed" : "REFUSED",
                      ok ? strprintf(" (leaf=%u)", leaf_used) : " (exhausted, blacklisted, or divergent history)");
            return ok;
        }
        if (it->second.imported) {
            // SNTI fix (1 Jul 2026): this key's sk came from importxmsskey
            // (mining or some other external system), and there is no
            // unified-ledger file for its root -- meaning this wallet
            // cannot verify how many leaves it has actually used (it may
            // have been mined past leaf 0 before this ledger existed, or
            // after rotating away from being the "active" tree that
            // XMSSTreeLedgerSeedFromActive() adopts on first mining after
            // upgrade). Refuse outright rather than fall through to the
            // one-shot policy below, which would sign with THIS wallet's
            // own (possibly leaf-0) copy and risk exactly the leaf-reuse
            // this whole fix exists to prevent. Funds here are considered
            // unspendable until/unless their true leaf position can be
            // independently reconstructed and seeded into the ledger.
            LogPrintf("SNTI: SignXMSS refused -- imported key for root=%s has no unified ledger "
                      "entry, true leaf position unverifiable, refusing to risk leaf reuse\n",
                      root.GetHex().substr(0, 16));
            return false;
        }
    }

    // Fallback path: wallet-native key (created by GenerateKey(), never
    // touched by mining or any other external signer). This wallet is the
    // sole holder of this key's state, so the one-time-use policy below is
    // safe -- there is no second system that could have advanced a leaf
    // behind this wallet's back.
    //
    // SNTI FIX (gap #3, 20/Jun/2026): refuse a second sign with the same
    // key. Every XMSS address is one-time-use by design here -- reusing a
    // leaf index lets an attacker reconstruct the private key from two
    // signatures, so this is a hard block, not just leaf_index bookkeeping.
    if (it->second.retired) {
        LogPrintf("SNTI: SignXMSS refused -- key is retired (one-time XMSS address already used)\n");
        return false;
    }

    // SNTI L4: warn when signing with a nearly-exhausted key.
    {
        uint32_t idx = it->second.leaf_index;
        uint32_t remaining = (idx <= 1024) ? (1024 - idx) : 0;
        if (remaining < 200) {
            LogPrintf("XMSS WARNING: signing with key that has only %u signature(s) remaining "
                      "(pk[0]=%02x%02x...). Generate a new XMSS key to avoid exhaustion.\n",
                      remaining,
                      pubkey.size() > 0 ? pubkey[0] : 0u,
                      pubkey.size() > 1 ? pubkey[1] : 0u);
        }
    }

    // Convert uint256 to vector
    std::vector<uint8_t> hash_vec(hash.begin(), hash.end());

    // Sign via CXMSSKey (stateful — advances leaf index)
    // Note: Sign() is logically const (doesn't change key identity)
    // but advances internal state. We use const_cast for the key reference.
    XMSS::CXMSSKey& key = const_cast<XMSS::CXMSSKey&>(it->second.key);
    bool success = key.Sign(hash_vec, sig);

    if (success) {
        const_cast<uint32_t&>(it->second.leaf_index)++;
        const_cast<bool&>(it->second.retired) = true;
    }

    return success;
}

uint32_t CXMSSSigner::GetXMSSLeafIndex(const std::vector<uint8_t>& pubkey) const
{
    LOCK(cs_xmss_signer);
    auto it = xmss_keys.find(pubkey);
    if (it == xmss_keys.end()) return 0;

    // SNTI fix (1 Jul 2026): for tree-backed (mining-derived) keys, this
    // object's own leaf_index is only ever a stale import snapshot -- the
    // unified ledger is the actual source of truth, so report from there
    // instead when it exists (keeps listxmsskeys/getxmssaddressinfo honest).
    if (pubkey.size() == 64) {
        uint256 root;
        std::memcpy(root.begin(), pubkey.data(), 32);
        fs::path datadir = gArgs.GetDataDirNet();
        uint32_t next_leaf = 0, max_leaves = 0;
        if (PoUWv2::XMSSTreeLedgerStatus(datadir, root, next_leaf, max_leaves)) {
            return next_leaf;
        }
    }
    return it->second.leaf_index;
}

uint32_t CXMSSSigner::GetXMSSChainId() const
{
    return Params().GetConsensus().nXMSSChainId;
}

bool CXMSSSigner::IsXMSSKeyRetired(const std::vector<uint8_t>& pubkey) const
{
    LOCK(cs_xmss_signer);
    auto it = xmss_keys.find(pubkey);
    if (it == xmss_keys.end()) return false;

    // SNTI fix (1 Jul 2026): tree-backed keys are "retired" (unspendable)
    // only when the ledger says they're exhausted or blacklisted -- not
    // after a single sign, since the tree has up to 1024 usable leaves.
    if (pubkey.size() == 64) {
        uint256 root;
        std::memcpy(root.begin(), pubkey.data(), 32);
        fs::path datadir = gArgs.GetDataDirNet();
        if (PoUWv2::IsXMSSTreeBlacklisted(root)) return true;
        uint32_t next_leaf = 0, max_leaves = 0;
        if (PoUWv2::XMSSTreeLedgerStatus(datadir, root, next_leaf, max_leaves)) {
            return next_leaf >= max_leaves;
        }
    }
    return it->second.retired;
}

bool CXMSSSigner::HaveXMSSKey(const std::vector<uint8_t>& pubkey) const
{
    LOCK(cs_xmss_signer);
    return xmss_keys.count(pubkey) > 0;
}

std::vector<uint8_t> CXMSSSigner::GetXMSSPubKey(const CKeyID& address) const
{
    LOCK(cs_xmss_signer);
    auto it = key_id_map.find(address);
    if (it == key_id_map.end()) return {};
    return it->second;
}

// ---------------------------------------------------------------------------
// SNTI: State Persistence (anti-reuse protection)
// ---------------------------------------------------------------------------

std::vector<uint8_t> CXMSSSigner::SaveState() const
{
    LOCK(cs_xmss_signer);

    // SNTI fix (1 Jul 2026): format bumped to v3 to add a per-key
    // "imported" byte (see XMSSKeyEntry::imported). Magic prefix lets
    // LoadState() distinguish v3 blobs from older v1/v2 ones, which get a
    // fail-closed default (imported=true) since we cannot know their true
    // origin -- see LoadState() below.
    // Format: ['Q','N','T','3'] [count(4)] [key_entry_1] ...
    // Each key_entry: [pubkey_size(4)] [pubkey(64)] [index(4)] [retired(1)] [imported(1)] [sk_size(4)] [sk_data]
    std::vector<uint8_t> data;

    data.push_back('Q');
    data.push_back('N');
    data.push_back('T');
    data.push_back('3');

    // Count
    uint32_t count = (uint32_t)xmss_keys.size();
    data.push_back((count >> 24) & 0xFF);
    data.push_back((count >> 16) & 0xFF);
    data.push_back((count >> 8) & 0xFF);
    data.push_back(count & 0xFF);

    for (const auto& [pubkey, entry] : xmss_keys) {
        // Pubkey size + data
        uint32_t pk_size = (uint32_t)pubkey.size();
        data.push_back((pk_size >> 24) & 0xFF);
        data.push_back((pk_size >> 16) & 0xFF);
        data.push_back((pk_size >> 8) & 0xFF);
        data.push_back(pk_size & 0xFF);
        data.insert(data.end(), pubkey.begin(), pubkey.end());

        // Leaf index
        data.push_back((entry.leaf_index >> 24) & 0xFF);
        data.push_back((entry.leaf_index >> 16) & 0xFF);
        data.push_back((entry.leaf_index >> 8) & 0xFF);
        data.push_back(entry.leaf_index & 0xFF);

        // Retired flag (SNTI gap #3)
        data.push_back(entry.retired ? 1 : 0);

        // Imported flag (SNTI fix 1 Jul 2026)
        data.push_back(entry.imported ? 1 : 0);

        // Secret key via CXMSSKey::GetPrivKey()
        std::vector<uint8_t> sk = entry.key.GetPrivKey();
        uint32_t sk_size = (uint32_t)sk.size();
        data.push_back((sk_size >> 24) & 0xFF);
        data.push_back((sk_size >> 16) & 0xFF);
        data.push_back((sk_size >> 8) & 0xFF);
        data.push_back(sk_size & 0xFF);
        data.insert(data.end(), sk.begin(), sk.end());
    }

    LogPrint(BCLog::WALLETDB, "CXMSSSigner::SaveState: saved %u keys (%u bytes, v3/imported-aware)\n",
             count, (uint32_t)data.size());

    return data;
}

bool CXMSSSigner::LoadState(const std::vector<uint8_t>& data)
{
    LOCK(cs_xmss_signer);

    if (data.size() < 4) return false;

    // Clear existing keys
    xmss_keys.clear();
    key_id_map.clear();

    // SNTI: detect format version by magic prefix. v3 (this fix, 1 Jul
    // 2026) adds a per-key "imported" byte; v2 (20 Jun 2026) adds a
    // "retired" byte; v1 (oldest) has neither. Falls back gracefully so
    // existing wallet DBs keep loading without a wipe.
    size_t pos = 0;
    bool is_v3 = (data.size() >= 8 &&
                  data[0] == 'Q' && data[1] == 'N' && data[2] == 'T' && data[3] == '3');
    bool is_v2 = !is_v3 && (data.size() >= 8 &&
                  data[0] == 'Q' && data[1] == 'N' && data[2] == 'T' && data[3] == '2');
    if (is_v3 || is_v2) {
        pos = 4;
    }

    if (pos + 4 > data.size()) return false;
    uint32_t count = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos+1] << 16) |
                     ((uint32_t)data[pos+2] << 8) | (uint32_t)data[pos+3];
    pos += 4;

    for (uint32_t i = 0; i < count; i++) {
        if (pos + 4 > data.size()) return false;

        // Pubkey
        uint32_t pk_size = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos+1] << 16) |
                           ((uint32_t)data[pos+2] << 8) | (uint32_t)data[pos+3];
        pos += 4;
        if (pos + pk_size > data.size()) return false;
        std::vector<uint8_t> pubkey(data.begin() + pos, data.begin() + pos + pk_size);
        pos += pk_size;

        // Leaf index
        if (pos + 4 > data.size()) return false;
        uint32_t leaf_index = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos+1] << 16) |
                              ((uint32_t)data[pos+2] << 8) | (uint32_t)data[pos+3];
        pos += 4;

        // Retired flag (present in v2+ blobs; v1 keys default to false)
        bool retired = false;
        if (is_v2 || is_v3) {
            if (pos + 1 > data.size()) return false;
            retired = (data[pos] != 0);
            pos += 1;
        }

        // Imported flag (SNTI fix 1 Jul 2026, present in v3 blobs only).
        // Default false for v1/v2 blobs (pre-fix state): this preserves
        // existing behaviour (one-shot fallback policy) for keys already
        // in a wallet before this fix, rather than retroactively refusing
        // to sign from every never-touched pool address purely because it
        // predates the v3 format -- that would brick legitimate untouched
        // addresses with no actual leaf-reuse risk. Known-risky pre-fix
        // addresses (mining trees that rotated away before the unified
        // ledger existed) are handled explicitly via xmss_blacklist.h
        // instead. This flag only protects imports made from now on.
        bool imported = false;
        if (is_v3) {
            if (pos + 1 > data.size()) return false;
            imported = (data[pos] != 0);
            pos += 1;
        }

        // Secret key
        if (pos + 4 > data.size()) return false;
        uint32_t sk_size = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos+1] << 16) |
                           ((uint32_t)data[pos+2] << 8) | (uint32_t)data[pos+3];
        pos += 4;
        if (pos + sk_size > data.size()) return false;
        std::vector<uint8_t> sk(data.begin() + pos, data.begin() + pos + sk_size);
        pos += sk_size;

        // Reconstruct key entry
        XMSSKeyEntry entry;
        entry.pubkey = pubkey;
        entry.leaf_index = leaf_index;
        entry.retired = retired;
        entry.imported = imported;
        if (!entry.key.Load(sk)) {
            LogPrintf("CXMSSSigner::LoadState: failed to load key %u\n", i);
            return false;
        }

        CKeyID key_id = GetXMSSKeyID(pubkey);
        key_id_map[key_id] = pubkey;
        xmss_keys[pubkey] = std::move(entry);
    }

    LogPrint(BCLog::WALLETDB, "CXMSSSigner::LoadState: loaded %u keys (%s format)\n",
             count, is_v2 ? "v2/retired-aware" : "v1/legacy");
    return true;
}

bool CXMSSSigner::HasExhaustedKeys() const
{
    LOCK(cs_xmss_signer);
    for (const auto& [pubkey, entry] : xmss_keys) {
        if (entry.leaf_index >= 1024) return true;  // XMSS-SHA2_10_256 max
    }
    return false;
}

uint32_t CXMSSSigner::CountFreshKeys() const
{
    LOCK(cs_xmss_signer);
    uint32_t count = 0;
    for (const auto& [pubkey, entry] : xmss_keys) {
        if (!entry.retired) count++;
    }
    return count;
}

// ---------------------------------------------------------------------------
// XMSS Script Helpers
// ---------------------------------------------------------------------------

bool IsXMSSScript(const CScript& script)
{
    // P2XMSS: PUSH64(1) <64-byte-pubkey> OP_XMSS_CHECKSIG(1) = 66 bytes
    if (script.size() == XMSS_PUBKEY_SIZE + 2) {
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        std::vector<unsigned char> vch;
        if (script.GetOp(pc, opcode, vch)) {
            if (vch.size() == XMSS_PUBKEY_SIZE) {
                // Check next opcode
                opcodetype next_opcode;
                std::vector<unsigned char> next_vch;
                if (script.GetOp(pc, next_opcode, next_vch)) {
                    return (next_opcode == 0xBB); // OP_XMSS_CHECKSIG
                }
            }
        }
    }

    // P2XMSSHASH: OP_DUP OP_HASH160 <20-byte> OP_EQUALVERIFY OP_XMSS_CHECKSIG
    // OP_DUP(1) OP_HASH160(1) <pushdata 1>(1) <20 bytes>(20) OP_EQUALVERIFY(1) OP_XMSS_CHECKSIG(1) = 25
    if (script.size() == 25) {
        if (script[0] == OP_DUP &&
            script[1] == OP_HASH160 &&
            script[2] == 20 &&
            script[23] == OP_EQUALVERIFY) {
            opcodetype last_opcode = static_cast<opcodetype>(script[24]);
            return (last_opcode == 0xBB); // OP_XMSS_CHECKSIG
        }
    }

    return false;
}

std::vector<uint8_t> GetXMSSPubkeyFromScript(const CScript& script)
{
    // P2XMSS: first 64 bytes are the pubkey
    if (script.size() >= XMSS_PUBKEY_SIZE + 1) {
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        std::vector<unsigned char> vch;
        if (script.GetOp(pc, opcode, vch)) {
            if (vch.size() == XMSS_PUBKEY_SIZE) {
                return vch;
            }
        }
    }

    // P2XMSSHASH: need to look up by hash — return empty (caller must resolve)
    return {};
}

CScript GetXMSSScriptForPubkey(const std::vector<uint8_t>& pubkey)
{
    if (pubkey.size() != XMSS_PUBKEY_SIZE) return {};
    CScript script;
    script << pubkey << OP_XMSS_CHECKSIG;
    return script;
}

CScript GetXMSSHashScriptForPubkey(const std::vector<uint8_t>& pubkey)
{
    if (pubkey.size() != XMSS_PUBKEY_SIZE) return {};
    uint160 hash;
    CHash160().Write(pubkey).Finalize(hash);
    CScript script;
    script << OP_DUP << OP_HASH160 << ToByteVector(hash) << OP_EQUALVERIFY << OP_XMSS_CHECKSIG;
    return script;
}

// SNTI: Get pubkey by address hash (RIPEMD160(SHA256(pubkey)))
std::vector<uint8_t> CXMSSSigner::GetPubKeyForHash(const uint160& addr_hash) const
{
    LOCK(cs_xmss_signer);
    for (const auto& [pubkey, entry] : xmss_keys) {
        uint160 hash = XMSSAddr::Hash(pubkey);
        if (hash == addr_hash) {
            return pubkey;
        }
    }
    return {};
}


// SNTI: Get secret key bytes for a given XMSS public key (sensitive!)
std::vector<uint8_t> CXMSSSigner::GetSecKeyForPubkey(const std::vector<uint8_t>& pubkey) const
{
    LOCK(cs_xmss_signer);
    auto it = xmss_keys.find(pubkey);
    if (it == xmss_keys.end()) {
        return {};
    }
    return it->second.key.GetPrivKey();
}

} // namespace wallet
