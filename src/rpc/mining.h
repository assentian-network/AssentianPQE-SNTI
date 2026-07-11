// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_MINING_H
#define BITCOIN_RPC_MINING_H

#include <cstdint>
#include <memory>

/** Default max iterations to try in RPC generatetodescriptor, generatetoaddress, and generateblock. */
static const uint64_t DEFAULT_MAX_TRIES{1000000};

class ChainstateManager;
class CBlock;

// SNTI: exposed (was file-local `static`) so test infrastructure can mine a
// real PoUW-valid block instead of building one with no XMSS proof at all --
// see TestChain100Setup::CreateBlock() in test/util/setup_common.cpp for the
// only other caller. Behavior is unchanged; this is a linkage-only change.
bool GenerateBlock(ChainstateManager& chainman, CBlock& block, uint64_t& max_tries, std::shared_ptr<const CBlock>& block_out, bool process_new_block);

#endif // BITCOIN_RPC_MINING_H
