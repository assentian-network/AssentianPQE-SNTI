// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    unsigned int expected_nbits = 0x1d00ffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits-1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

// SNTI audit KRITIS #5 (2 Jul 2026): stuck-chain recovery timestamp-exploit fix.
// Builds a small manual CBlockIndex chain (pprev-linked) so GetNextWorkRequired's
// look-back over prior inter-block gaps has real data to walk.
struct StuckRecoveryChain {
    CBlockIndex idx[4]; // idx[0] = pindexLast, idx[1..3] = ancestors
    CBlockHeader candidate;

    // base_height/base_time = pindexLast's own height/time. gap1/gap2/gap3 are
    // the real (already-confirmed) inter-block spacings idx[0]-idx[1],
    // idx[1]-idx[2], idx[2]-idx[3], all in seconds.
    StuckRecoveryChain(int base_height, int64_t base_time, int64_t gap1, int64_t gap2, int64_t gap3)
    {
        idx[0].nHeight = base_height;
        idx[0].nTime = base_time;
        idx[1].nHeight = base_height - 1;
        idx[1].nTime = base_time - gap1;
        idx[2].nHeight = base_height - 2;
        idx[2].nTime = base_time - gap1 - gap2;
        idx[3].nHeight = base_height - 3;
        idx[3].nTime = base_time - gap1 - gap2 - gap3;
        idx[0].pprev = &idx[1];
        idx[1].pprev = &idx[2];
        idx[2].pprev = &idx[3];
        idx[3].pprev = nullptr;
        idx[0].nBits = 0x1f00ffff;
    }
};

BOOST_AUTO_TEST_CASE(stuck_recovery_single_spike_not_confirmed_falls_through)
{
    // Post-activation (testnet activates at height 200): pindexLast's own
    // recent history is completely normal (60s gaps) -- the chain was never
    // actually stuck. A miner sets the CANDIDATE block's timestamp 601s ahead
    // to fake a stuck-chain signal. This must NOT get the full 20x jump.
    // MAIN (not TESTNET): testnet's fPowAllowMinDifficultyBlocks would short-
    // circuit to powLimit before this code path is even reached.
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    Consensus::Params params = chainParams->GetConsensus();
    params.nPoUWStuckRecoveryHardenHeight = 200; // low, test-friendly activation

    StuckRecoveryChain c(250, 1700000000, 60, 60, 60);
    c.candidate.nTime = c.idx[0].nTime + 601; // fake spike, single block only

    unsigned int result = GetNextWorkRequired(&c.idx[0], &c.candidate, params);
    unsigned int forced_20x = CalculateNextWorkRequired(&c.idx[0], c.idx[0].nTime - params.nPowTargetSpacing * 20, params);
    BOOST_CHECK(result != forced_20x);
}

BOOST_AUTO_TEST_CASE(stuck_recovery_genuine_outage_still_gets_full_jump)
{
    // Post-activation, but this time the chain genuinely WAS stuck: the last
    // several real inter-block gaps are all large too. Corroborated by
    // immutable history the attacker (or anyone) cannot rewrite -- must still
    // get the full 20x recovery immediately, so legitimate recovery speed is
    // unaffected by the fix.
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    Consensus::Params params = chainParams->GetConsensus();
    params.nPoUWStuckRecoveryHardenHeight = 200; // low, test-friendly activation

    StuckRecoveryChain c(250, 1700000000, 3600, 3600, 3600); // 1h gaps: real outage
    c.candidate.nTime = c.idx[0].nTime + 700; // this block's own gap also > 600s

    unsigned int result = GetNextWorkRequired(&c.idx[0], &c.candidate, params);
    unsigned int forced_20x = CalculateNextWorkRequired(&c.idx[0], c.idx[0].nTime - params.nPowTargetSpacing * 20, params);
    BOOST_CHECK_EQUAL(result, forced_20x);
}

BOOST_AUTO_TEST_CASE(stuck_recovery_pre_activation_unchanged_behavior)
{
    // Below the activation height, behavior must be byte-for-byte identical
    // to the old code (single-block gap alone is sufficient), so already-mined
    // history stays valid under the new binary.
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    Consensus::Params params = chainParams->GetConsensus();
    params.nPoUWStuckRecoveryHardenHeight = 200;

    StuckRecoveryChain c(50, 1700000000, 60, 60, 60); // well below height 200, normal history
    c.candidate.nTime = c.idx[0].nTime + 601; // single-block spike only

    unsigned int result = GetNextWorkRequired(&c.idx[0], &c.candidate, params);
    unsigned int forced_20x = CalculateNextWorkRequired(&c.idx[0], c.idx[0].nTime - params.nPowTargetSpacing * 20, params);
    BOOST_CHECK_EQUAL(result, forced_20x);
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max{UintToArith256(uint256S("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

BOOST_AUTO_TEST_SUITE_END()
