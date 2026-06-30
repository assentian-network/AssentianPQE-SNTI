// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_AMOUNT_H
#define BITCOIN_CONSENSUS_AMOUNT_H

#include <cstdint>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

/** The amount of satoshis in one BTC. */
static constexpr CAmount COIN = 100000000;

/** No amount larger than this (in satoshi) is valid.
 *
 * SNTI: Total supply = 210,000,000 SNTI (2,100,000 halving interval × 50 SNTI × 2 geometric sum).
 * This is 10× Bitcoin's 21M due to 60s block time vs 600s, keeping ~4-year halvings.
 * As this sanity check is used by consensus-critical validation code, the exact value
 * of the MAX_MONEY constant is consensus critical.
 * */
static constexpr CAmount MAX_MONEY = 210000000 * COIN;
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#endif // BITCOIN_CONSENSUS_AMOUNT_H
