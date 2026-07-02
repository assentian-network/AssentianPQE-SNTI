// Copyright (c) 2026 The Assentian-PQE developers
// See xmss_tree_ledger.h for the problem this solves.

#include <xmss_tree_ledger.h>
#include <xmss_blacklist.h>

#include <logging.h>
#include <random.h>
#include <util/fs.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <fcntl.h>
#include <unistd.h>

extern "C" {
#include "xmss.h"
}

namespace PoUWv2 {

GlobalMutex g_xmss_ledger_mutex;

namespace {

fs::path LedgerDir(const fs::path& datadir)
{
    return datadir / "xmss_trees";
}

fs::path LedgerPathFor(const fs::path& datadir, const uint256& root)
{
    // One immutable-by-name file per tree. Once created it is never deleted
    // or repointed to a different tree, unlike the old xmss_miner_state.dat
    // "active tree" pointer which got silently overwritten on rotation.
    return LedgerDir(datadir) / fs::PathFromString(root.GetHex() + ".dat");
}

// SNTI SECURITY FIX (audit KRITIS #6, 2 Jul 2026): xmss_tree_ledger's mutex
// only serializes claims WITHIN one running process. If the same tree's SK
// is ever loaded on a second machine/datadir (restored backup, VPS
// migration where the old node was never actually shut down, etc.), each
// side's ledger evolves independently with no way to know about the other
// -- reproducing the exact miner-vs-wallet leaf desync this file was built
// to fix, just at a cross-node scope instead of cross-process.
//
// Full protection against two *simultaneously running* copies would need a
// live cross-node coordination oracle, which trades away node autonomy for
// a problem that -- for this project's actual threat model -- is really
// "protect one key-holder from their own careless dual-run", not
// "arbitrate between independent parties" (every miner has their own
// distinct key; nobody else's key can ever collide with yours).
//
// So instead: stamp every ledger file with a random ID unique to this
// datadir, generated once and reused for the datadir's lifetime. Any ledger
// file whose stored stamp doesn't match ours was last written by a
// DIFFERENT datadir -- almost always exactly the "restored a copy without
// retiring the original" accident that caused the original bug. Refuse to
// sign until the operator explicitly acknowledges the risk (by touching a
// sentinel file), converting a silent double-use into a hard stop.
fs::path InstanceIdPathFor(const fs::path& datadir)
{
    return LedgerDir(datadir) / fs::PathFromString(".instance_id");
}

std::array<uint8_t, OWNER_STAMP_BYTES> GetOrCreateInstanceId(const fs::path& datadir)
{
    fs::path dir = LedgerDir(datadir);
    if (!fs::exists(dir)) fs::create_directories(dir);
    fs::path p = InstanceIdPathFor(datadir);

    std::array<uint8_t, OWNER_STAMP_BYTES> id{};
    if (fs::exists(p)) {
        std::ifstream f(p, std::ios::binary);
        if (f.is_open()) {
            f.read(reinterpret_cast<char*>(id.data()), id.size());
            if (f.gcount() == static_cast<std::streamsize>(id.size())) return id;
        }
    }
    // First run for this datadir (or unreadable file) -- mint a fresh one.
    GetStrongRandBytes(Span<unsigned char>(id.data(), id.size()));
    int fd = open(fs::PathToString(p).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        ssize_t written = write(fd, id.data(), id.size());
        if (written < 0 || static_cast<size_t>(written) != id.size()) {
            LogPrintf("XMSSTreeLedger: WARNING failed to persist instance ID -- "
                      "ownership stamping will not survive a restart\n");
        } else {
            fsync(fd);
        }
        close(fd);
    } else {
        LogPrintf("XMSSTreeLedger: WARNING could not create instance ID file -- "
                  "ownership stamping will not survive a restart\n");
    }
    return id;
}

bool IsZeroStamp(const std::array<uint8_t, OWNER_STAMP_BYTES>& s)
{
    return std::all_of(s.begin(), s.end(), [](uint8_t b) { return b == 0; });
}

// One-shot manual override: operator creates
// <datadir>/xmss_trees/<root>.forceclaim to acknowledge the risk and let
// THIS datadir take over a tree last stamped by another instance. Consumed
// (deleted) on use so it doesn't silently mask future genuine conflicts.
fs::path ForceClaimSentinelPathFor(const fs::path& datadir, const uint256& root)
{
    return LedgerDir(datadir) / fs::PathFromString(root.GetHex() + ".forceclaim");
}

// Load raw ledger bytes for `root`. Caller holds g_xmss_ledger_mutex.
bool LoadLocked(const fs::path& datadir, const uint256& root, XMSSMinerState& state)
{
    fs::path p = LedgerPathFor(datadir, root);
    if (!fs::exists(p)) return false;

    std::ifstream f(p, std::ios::binary);
    if (!f.is_open()) return false;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    if (!state.Deserialize(data)) {
        LogPrintf("XMSSTreeLedger: corrupt ledger file for root=%s\n", root.GetHex().substr(0, 16));
        return false;
    }
    if (state.xmssRoot != root) {
        LogPrintf("XMSSTreeLedger: ledger file root mismatch (file=%s expected=%s)\n",
                  state.xmssRoot.GetHex().substr(0, 16), root.GetHex().substr(0, 16));
        return false;
    }
    return true;
}

// Persist `state` for its own root, atomically (temp file + fsync + rename).
// Caller holds g_xmss_ledger_mutex.
bool SaveLocked(const fs::path& datadir, const XMSSMinerState& state)
{
    fs::path dir = LedgerDir(datadir);
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }

    fs::path p = LedgerPathFor(datadir, state.xmssRoot);
    fs::path tmp = p;
    tmp += ".tmp";

    std::vector<uint8_t> data = state.Serialize();

    int fd = open(fs::PathToString(tmp).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LogPrintf("XMSSTreeLedger: failed to open temp file for write\n");
        return false;
    }
    ssize_t written = write(fd, data.data(), data.size());
    if (written < 0 || static_cast<size_t>(written) != data.size()) {
        LogPrintf("XMSSTreeLedger: write failed\n");
        close(fd);
        return false;
    }
    // fsync before rename: a crash between write and rename must never leave
    // a leaf claimed in memory but not durably recorded on disk -- that gap
    // is exactly how a restart could re-claim (reuse) the same leaf.
    if (fsync(fd) != 0) {
        LogPrintf("XMSSTreeLedger: fsync failed\n");
        close(fd);
        return false;
    }
    close(fd);

    fs::rename(tmp, p);
    return true;
}

} // namespace

bool XMSSTreeLedgerExists(const fs::path& datadir, const uint256& root)
{
    LOCK(g_xmss_ledger_mutex);
    return fs::exists(LedgerPathFor(datadir, root));
}

bool XMSSTreeLedgerSeedFromActive(const fs::path& datadir, const XMSSMinerState& active_state)
{
    LOCK(g_xmss_ledger_mutex);
    fs::path p = LedgerPathFor(datadir, active_state.xmssRoot);
    if (fs::exists(p)) {
        // Never clobber an existing ledger -- it may already be ahead of
        // whatever snapshot the caller has in memory.
        return false;
    }
    if (!active_state.IsValid()) return false;
    XMSSMinerState stamped = active_state;
    stamped.version = STATE_VERSION;
    stamped.ownerStamp = GetOrCreateInstanceId(datadir);
    return SaveLocked(datadir, stamped);
}

bool XMSSTreeLedgerInit(const fs::path& datadir, const XMSSMinerState& fresh_state)
{
    LOCK(g_xmss_ledger_mutex);
    if (!fresh_state.IsValid()) return false;
    fs::path p = LedgerPathFor(datadir, fresh_state.xmssRoot);
    if (fs::exists(p)) {
        // Tree already has a ledger (e.g. process restarted after building
        // this tree but before mining a block with it) -- don't reset it.
        return true;
    }
    XMSSMinerState stamped = fresh_state;
    stamped.version = STATE_VERSION;
    stamped.ownerStamp = GetOrCreateInstanceId(datadir);
    return SaveLocked(datadir, stamped);
}

bool XMSSTreeLedgerClaimAndSign(const fs::path& datadir,
                                 const uint256& root,
                                 const std::vector<uint8_t>& hash32,
                                 std::vector<uint8_t>& sig_out,
                                 uint32_t& leaf_used_out)
{
    LOCK(g_xmss_ledger_mutex);

    if (IsXMSSTreeBlacklisted(root)) {
        LogPrintf("XMSSTreeLedger: refused -- root=%s is blacklisted (known-divergent history)\n",
                  root.GetHex().substr(0, 16));
        return false;
    }

    XMSSMinerState state;
    if (!LoadLocked(datadir, root, state)) {
        LogPrintf("XMSSTreeLedger: no ledger for root=%s -- cannot sign (never mined with the "
                  "unified ledger, or archive missing)\n", root.GetHex().substr(0, 16));
        return false;
    }

    // SNTI SECURITY FIX (audit KRITIS #6, 2 Jul 2026): refuse to sign if this
    // ledger file was last stamped by a DIFFERENT datadir/instance, unless
    // the operator has explicitly dropped a one-shot override sentinel. See
    // the comment above InstanceIdPathFor() for the threat this closes.
    const auto my_id = GetOrCreateInstanceId(datadir);
    if (!IsZeroStamp(state.ownerStamp) && state.ownerStamp != my_id) {
        fs::path sentinel = ForceClaimSentinelPathFor(datadir, root);
        if (fs::exists(sentinel)) {
            LogPrintf("XMSSTreeLedger: WARNING operator override used -- claiming root=%s for this "
                      "datadir even though it was last stamped by a different instance. If the other "
                      "machine is NOT actually retired/offline, this WILL risk leaking the tree's "
                      "private key.\n", root.GetHex().substr(0, 16));
            fs::remove(sentinel); // one-shot
            state.ownerStamp = my_id;
        } else {
            LogPrintf("XMSSTreeLedger: REFUSING sign for root=%s -- this ledger was last written by a "
                      "DIFFERENT machine/datadir (ownership stamp mismatch). This almost always means a "
                      "wallet backup or ledger file was copied/restored here while the original machine "
                      "may still hold the same key -- signing from both risks leaking the XMSS private "
                      "key. If you are CERTAIN the original machine is permanently retired/offline, "
                      "create %s once to force this datadir to take over.\n",
                      root.GetHex().substr(0, 16), fs::PathToString(sentinel));
            return false;
        }
    }
    state.version = STATE_VERSION;
    state.ownerStamp = my_id; // claim/reaffirm ownership before this save

    if (state.IsExhausted()) {
        LogPrintf("XMSSTreeLedger: root=%s exhausted (%u/%u leaves used)\n",
                  root.GetHex().substr(0, 16), state.nextLeafIndex, XMSS_MAX_LEAVES);
        return false;
    }
    if (hash32.size() != 32) return false;

    xmss_params params;
    if (xmss_parse_oid(&params, XMSS_OID) != 0) return false;

    // Cross-check: the leaf index embedded in the SK blob itself must match
    // our tracked nextLeafIndex before we let it sign anything. Any mismatch
    // means the ledger file and the SK state have diverged (should be
    // impossible with a single writer, but this is the last line of defense
    // against ever signing with a leaf we can't account for).
    const uint8_t* sk_data = state.sk.data();
    uint32_t sk_idx = ((uint32_t)sk_data[4] << 24) | ((uint32_t)sk_data[5] << 16) |
                       ((uint32_t)sk_data[6] << 8)  |  (uint32_t)sk_data[7];
    if (sk_idx != state.nextLeafIndex) {
        LogPrintf("XMSSTreeLedger: REFUSING sign -- SK internal idx=%u != ledger nextLeafIndex=%u "
                  "for root=%s. This must never happen; treating as unsafe.\n",
                  sk_idx, state.nextLeafIndex, root.GetHex().substr(0, 16));
        return false;
    }

    const size_t sm_size = params.sig_bytes + hash32.size() + 64;
    std::vector<uint8_t> sm(sm_size, 0);
    unsigned long long smlen = 0;

    uint32_t leaf_used = state.nextLeafIndex;
    int ret = xmss_sign(state.sk.data(), sm.data(), &smlen, hash32.data(), hash32.size());
    if (ret != 0) {
        LogPrintf("XMSSTreeLedger: xmss_sign failed ret=%d for root=%s\n",
                  ret, root.GetHex().substr(0, 16));
        return false;
    }

    state.nextLeafIndex++;

    // Persist BEFORE returning the signature to the caller. If this fails,
    // we must not hand back a signature whose leaf-consumption was never
    // recorded -- that is exactly the WOTS+ reuse scenario this file exists
    // to prevent (mirrors the same rule already applied in mining.cpp).
    if (!SaveLocked(datadir, state)) {
        LogPrintf("XMSSTreeLedger: CRITICAL: sign succeeded but save failed for root=%s leaf=%u -- "
                  "discarding signature to avoid unrecorded leaf use.\n",
                  root.GetHex().substr(0, 16), leaf_used);
        return false;
    }

    sig_out.assign(sm.begin(), sm.begin() + (size_t)smlen - hash32.size());
    leaf_used_out = leaf_used;
    return true;
}

bool XMSSTreeLedgerStatus(const fs::path& datadir, const uint256& root,
                           uint32_t& next_leaf_out, uint32_t& max_leaves_out)
{
    LOCK(g_xmss_ledger_mutex);
    XMSSMinerState state;
    if (!LoadLocked(datadir, root, state)) return false;
    next_leaf_out = state.nextLeafIndex;
    max_leaves_out = XMSS_MAX_LEAVES;
    return true;
}

} // namespace PoUWv2
