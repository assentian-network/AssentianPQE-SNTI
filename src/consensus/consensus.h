// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstdlib>
#include <stdint.h>

// SNTI R1: Block capacity fix — XMSS signatures are ~2500 bytes each (vs 72 bytes
// for ECDSA). At Bitcoin's original 4 MB weight limit, a scriptSig-resident XMSS
// signature consumes 4 × 2500 = 10 000 weight units per input, yielding only
// ~400 XMSS transactions per block (~7 tx/s at 60 s blocks).
//
// Solution: increase MAX_BLOCK_WEIGHT 4× to 16 MB at the SNTI genesis.  This
// restores throughput to ~1 600 XMSS tx/block (~27 tx/s), comparable to
// Bitcoin's ECDSA capacity per byte of block space.  All nodes must use this
// limit from genesis — there are no pre-existing blocks to protect.
//
// Future upgrade path: migrate XMSS signatures into the segregated witness field
// (SNTI protocol v3) to get the automatic 4× witness discount without relying on
// the raw block-size increase.  That path will allow reducing MAX_BLOCK_WEIGHT
// back toward 4 MB once XMSS witness encoding is standardised.
/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 16000000;   // SNTI: 16 MB (4× Bitcoin, see above)
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 16000000;            // SNTI: 16 MB weight cap
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

static const int WITNESS_SCALE_FACTOR = 4;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
