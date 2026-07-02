// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>

#include <chrono>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /** SNTI: PoUW (Proof-of-Useful-Work) parameters */
    bool fPoUW{false};                    //!< Enable PoUW: blocks must be XMSS-signed
    int nPoUWStartHeight{0};             //!< Block height at which PoUW activates (0 = always)
    int nPoUWv2StartHeight{1};           //!< H8: height at which v1 proofs are rejected (v2 mandatory)
    /** Height at which PoUW v2 preimage switches to include hashMerkleRoot.
     *  Below this height the old preimage (nVersion||hashPrevBlock||nTime||nBits) is used
     *  for backward-compatibility with already-mined blocks.  At and above this height
     *  the preimage is SHA256(nVersion||hashPrevBlock||hashMerkleRoot||nTime||nBits),
     *  which binds the proof to the block's transaction set (fix for audit bug #1). */
    int nPoUWv3StartHeight{std::numeric_limits<int>::max()}; //!< disabled unless set
    /** Height at which leaf-index reuse prevention (SNTI M7) is enforced.
     *  Blocks below this height are exempt — they pre-date the check and may
     *  contain reused leaf indices mined by earlier binary versions. */
    int nPoUWLeafReuseActivation{std::numeric_limits<int>::max()}; //!< disabled unless set
    /** Height at which Failed-Seed-List entries must cryptographically prove
     *  their claimed xmss_root derives from their claimed sk_seed (audit T-1).
     *  Below this height a miner could submit an arbitrary (sk_seed, root)
     *  pair unchecked; blocks below this height are exempt for compatibility
     *  with already-mined history. */
    int nPoUWFSLSeedVerifyHeight{std::numeric_limits<int>::max()}; //!< disabled unless set
    /** Height at which stuck-chain difficulty recovery (GetNextWorkRequired(),
     *  pow.cpp) requires corroboration from prior, already-confirmed
     *  inter-block gaps before granting the full 20x EMA-easing jump on a
     *  single block's self-reported timestamp gap (KRITIS #5, 2 Jul 2026).
     *  Below this height a single miner-chosen timestamp was sufficient to
     *  trigger it, exempted here for compatibility with already-mined
     *  history. Below this height the OLD single-block-gap logic is used
     *  byte-for-byte unchanged. */
    int nPoUWStuckRecoveryHardenHeight{std::numeric_limits<int>::max()}; //!< disabled unless set
    /** Grandfather exemption for the strict nBits ("bad-diffbits") check in
     *  ContextualCheckBlockHeader() (discovered 2 Jul 2026 via the first-ever
     *  fresh IBD sync attempt from genesis). The PoUW v2 difficulty algorithm
     *  (EMA clamp, stuck-chain recovery, 3-block moving average) was tuned
     *  several times early in mainnet's life via direct node restarts rather
     *  than proper activation-height gating, so blocks mined under an older
     *  version of the formula don't recompute to the same nBits under the
     *  current one. Blocks at height <= this value skip the nBits equality
     *  check entirely (no other header/PoW rule is relaxed). Default 0 means
     *  no exemption (strict check always enforced) -- this only needs a
     *  nonzero value on mainnet, whose specific historical mismatches (height
     *  7-273, scanned exhaustively 2 Jul 2026) this exists to grandfather in. */
    int nPoUWDiffbitsGrandfatherHeight{0};
    size_t nPoUWMaxSigSize{4096};        //!< Maximum XMSS signature size in coinbase scriptSig

    /** SNTI: XMSS sighash chain ID — prevents cross-chain tx replay.
     *  Mainnet=1, Testnet=2, Signet/Regtest=3.
     *  Included in sighash_v2 = SHA256(sighash_v1 || leaf_index_BE || chain_id_BE). */
    uint32_t nXMSSChainId{1};

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
