// Copyright (c) 2026 The Assentian-PQE developers
// SNTI: Unified XMSS tree leaf ledger.
//
// Root cause this fixes: mining (XMSSMinerState, xmss_miner_state.dat) and
// wallet spend-signing (CXMSSSigner, wallet.dat) used to keep TWO independent
// copies of the same tree's secret key, each with its own leaf-index counter
// that never synced with the other. Whichever side signed first (mining or a
// wallet spend) advanced its OWN counter only -- the other side stayed stale
// and could unknowingly reuse an already-used leaf. Two XMSS signatures over
// different messages from the same leaf leak the tree's private key.
//
// Fix: exactly one persisted, fsync'd file per tree (keyed by root hash),
// and exactly one claim path (ClaimLeafAndSign) that BOTH mining and wallet
// spend code must call, serialized under a single process-wide mutex. There
// is no longer a "miner's copy" and a "wallet's copy" -- there is one file
// and one lock.

#ifndef ASSENTIAN_XMSS_TREE_LEDGER_H
#define ASSENTIAN_XMSS_TREE_LEDGER_H

#include <xmss_miner_state.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>

#include <vector>

namespace PoUWv2 {

// Guards every leaf claim (mining AND wallet spend) across every tree in
// this process. A tree's file is Load-modify-Save'd entirely while this is
// held, so two callers racing for the same tree can never both claim the
// same leaf -- the second caller's Load() will see the first caller's Save().
extern GlobalMutex g_xmss_ledger_mutex;

// Returns true if `root` has an archived ledger file (i.e. this pubkey's
// tree is known to the miner/wallet-shared ledger, whether it is currently
// the active mining tree or an older, rotated-out one).
bool XMSSTreeLedgerExists(const fs::path& datadir, const uint256& root) EXCLUSIVE_LOCKS_REQUIRED(!g_xmss_ledger_mutex);

// Explicitly seed the archive for `root` from an already-known state (used
// once, at fix-deploy time, to adopt the miner's *currently active* tree
// into the shared ledger so it becomes spendable through the same path).
// Does nothing (returns false) if an archive for this root already exists --
// this must never overwrite a ledger that may already have advanced leaves.
bool XMSSTreeLedgerSeedFromActive(const fs::path& datadir, const XMSSMinerState& active_state)
    EXCLUSIVE_LOCKS_REQUIRED(!g_xmss_ledger_mutex);

// The one and only leaf-claim entry point. Loads the ledger for `root`,
// refuses if exhausted or blacklisted (see xmss_blacklist.h), signs hash32
// with the next never-used leaf, persists (fsync) BEFORE returning, all
// under g_xmss_ledger_mutex. Callers (mining.cpp, xmss_signer.cpp) must NOT
// keep any independent leaf-index bookkeeping for tree-backed keys.
bool XMSSTreeLedgerClaimAndSign(const fs::path& datadir,
                                 const uint256& root,
                                 const std::vector<uint8_t>& hash32,
                                 std::vector<uint8_t>& sig_out,
                                 uint32_t& leaf_used_out)
    EXCLUSIVE_LOCKS_REQUIRED(!g_xmss_ledger_mutex);

// Mining-only: claim the next leaf of `root` using `sk` bytes the caller
// already holds (used the first time a tree is built, before any archive
// file exists yet -- creates the archive file as a side effect). After this
// call, ClaimLeafAndSign() must be used for all further leaves of this tree.
bool XMSSTreeLedgerInit(const fs::path& datadir, const XMSSMinerState& fresh_state)
    EXCLUSIVE_LOCKS_REQUIRED(!g_xmss_ledger_mutex);

// Read-only status peek for RPC/audit tooling. Returns false if unknown root.
bool XMSSTreeLedgerStatus(const fs::path& datadir, const uint256& root,
                           uint32_t& next_leaf_out, uint32_t& max_leaves_out)
    EXCLUSIVE_LOCKS_REQUIRED(!g_xmss_ledger_mutex);

} // namespace PoUWv2

#endif // ASSENTIAN_XMSS_TREE_LEDGER_H
