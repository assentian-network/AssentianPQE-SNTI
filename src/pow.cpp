// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
// SNTI PoUW v2 include
#include <pouw_v2.h>


// SNTI PoUW v2: EMA per-block difficulty adjustment
// Replaces Bitcoin 2016-block retarget with per-block EMA (alpha=0.1)
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    unsigned int nProofOfWorkLimit = pow_limit.GetCompact();

    // Genesis block
    if (pindexLast->pprev == nullptr) return nProofOfWorkLimit;

    // fPowNoRetargeting: regtest
    if (params.fPowNoRetargeting) return pindexLast->nBits;

    // Testnet: allow min difficulty if block is too slow
    if (params.fPowAllowMinDifficultyBlocks) {
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
            return nProofOfWorkLimit;
    }

    return CalculateNextWorkRequired(pindexLast, pindexLast->pprev->GetBlockTime(), params);
}

// SNTI PoUW v2: EMA implementation
// nFirstBlockTime = pindexLast->pprev->GetBlockTime() (previous block time)
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Actual spacing = time between last two blocks
    int64_t actual_spacing = pindexLast->GetBlockTime() - nFirstBlockTime;

    // Get current target
    arith_uint256 old_target;
    old_target.SetCompact(pindexLast->nBits);

    // EMA adjustment via pouw_v2
    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    arith_uint256 new_target = PoUWv2::CalcNextTargetEMA(
        old_target, actual_spacing, params.nPowTargetSpacing, pow_limit);

    return new_target.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// SNTI PoUW v2: root < target check
// 'hash' parameter = XMSS root hash (first 32 bytes of xmss_pk)
// Full XMSS proof verification happens in CheckPoUW() in validation.cpp
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // SNTI PoUW v2: check XMSS root < target
    // root = hash (passed from block header's hashMerkleRoot or dedicated field)
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
