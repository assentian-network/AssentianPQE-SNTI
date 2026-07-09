// Copyright (c) 2026 The Assentian-PQE developers
// SNTI DRAFT: shared helpers for consensus-level XMSS leaf-reuse dedup.
//
// Used by validation.cpp for both the PoUW mining-leaf check (existing) and
// the XMSS spend-leaf check (draft, gated by nXMSSSpendLeafReuseActivation,
// currently disabled everywhere). Pulled out to its own translation unit so
// it can be exercised directly by unit tests without needing a full
// ConnectBlock()/chainstate fixture.
//
// See xmss_tree_ledger.h for the *local*, per-node, non-consensus leaf-claim
// guard this complements -- that one prevents a single node's mining and
// wallet-spend code from racing each other; this one is the network-wide
// consensus backstop for reuse across separate nodes/wallets (e.g. the same
// wallet.dat copied to two machines).

#ifndef ASSENTIAN_XMSS_LEAF_KEY_H
#define ASSENTIAN_XMSS_LEAF_KEY_H

#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

// DB key for a given (pubkey, leaf_idx) pair. Written/read under a single
// shared DB prefix ('L', DB_POUW_LEAF in validation.cpp) for both PoUW
// mining leaves and XMSS spend-tx leaves -- a tree leaf's secret is the same
// regardless of which context claimed it, so both must land in one table.
uint256 MakePoUWLeafKey(const std::vector<uint8_t>& pubkey64, uint32_t leaf_idx);

// Extract (pubkey, leaf_idx) from a scriptSig spending a P2XMSS/P2XMSSHASH
// output, using the identical chunk-reassembly rule as OP_XMSS_CHECKSIG in
// script/interpreter.cpp: scriptSig is pure pushes; the LAST push is the
// 64-byte pubkey (== stacktop(-1) at OP_XMSS_CHECKSIG time); every push
// before it, in order, is a signature chunk (1-520 bytes) that concatenates
// into the raw XMSS signature, whose first 4 bytes are the leaf index.
//
// Returns false if scriptPubKey isn't P2XMSS/P2XMSSHASH, or the scriptSig
// doesn't match the expected shape (should not happen for a scriptSig that
// already passed CheckInputScripts, since that's the only way
// OP_XMSS_CHECKSIG succeeds -- this re-derives structural data the
// interpreter already parsed, it does not independently verify it).
bool ExtractXMSSLeafUse(const CScript& scriptPubKey, const CScript& scriptSig,
                         std::vector<uint8_t>& pubkey_out, uint32_t& leaf_idx_out);

#endif // ASSENTIAN_XMSS_LEAF_KEY_H
