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

    // SNTI M5: 3-block moving average to dampen oscillation on small networks.
    // Computes the average of the last min(3, available) inter-block spacings
    // and back-calculates a virtual nFirstBlockTime so that
    // CalculateNextWorkRequired() sees the smoothed actual_spacing.
    int64_t nFirstBlockTime;
    const CBlockIndex* p2 = pindexLast->pprev->pprev; // 2 blocks back from tip
    if (p2 && p2->pprev) {
        // avg = (t_N - t_{N-3}) / 3
        int64_t avg3 = (pindexLast->GetBlockTime() - p2->pprev->GetBlockTime()) / 3;
        nFirstBlockTime = pindexLast->GetBlockTime() - avg3;
    } else if (p2) {
        // avg = (t_N - t_{N-2}) / 2
        int64_t avg2 = (pindexLast->GetBlockTime() - p2->GetBlockTime()) / 2;
        nFirstBlockTime = pindexLast->GetBlockTime() - avg2;
    } else {
        nFirstBlockTime = pindexLast->pprev->GetBlockTime();
    }

    return CalculateNextWorkRequired(pindexLast, nFirstBlockTime, params);
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

// SNTI PoUW v2: EMA adjusts nBits every block, so any nBits is permitted
// as long as it stays within powLimit. The original Bitcoin 2016-block window
// logic would reject every inter-adjustment EMA change for mainnet.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowNoRetargeting) return old_nbits == new_nbits;

    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    arith_uint256 observed_new_target;
    observed_new_target.SetCompact(new_nbits);

    // New target must not exceed powLimit
    if (observed_new_target > pow_limit) return false;

    // EMA bounds: new target must be within 4x of old target (matches alpha=0.1 max swing)
    arith_uint256 old_target;
    old_target.SetCompact(old_nbits);

    arith_uint256 max_target = old_target * 4;
    if (max_target > pow_limit) max_target = pow_limit;

    arith_uint256 min_target = old_target / 4;
    if (min_target == arith_uint256(0)) min_target = arith_uint256(1); // prevent underflow to 0

    if (observed_new_target > max_target) return false;
    if (observed_new_target < min_target) return false;

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
