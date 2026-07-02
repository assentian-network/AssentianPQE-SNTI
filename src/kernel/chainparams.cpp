// Copyright (c) 2025 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <kernel/chainparams.h>

#include <qnt_seeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

// Quant genesis: XMSS post-quantum signature scheme
// Genesis output uses P2PK-like script with 64-byte XMSS public key
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Assentian-PQE 22/Jun/2026 XMSS Post Quantum Era - For Sentia";
    // SNTI Genesis XMSS public key (64 bytes root||PUB_SEED)
    // Generated: 2026-06-11
    // Algorithm: XMSS-SHA2_10_256 (NIST SP 800-208)
    const CScript genesisOutputScript = CScript() << ParseHex(
        "8c5c7e72fb9a7b07e7fb5262abc79c6e321ddaaf27e33ebed6b9c3a0648a2d08"
        "d0e704faf31f0a29b53463026e7ed85d0a372135423882c996770c8a974ef153"
    ) << OP_XMSS_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Assentian-PQE Mainnet — Pure Post-Quantum Proof-of-Useful-Work
 *
 * SNTI PoUW v2: Pure XMSS Tree Building
 *   - P2P Port:      9333
 *   - Genesis:       Jun 26, 2026
 *   - Block Time:    ~60 seconds (EMA difficulty adjustment)
 *   - Halving:       Every 2,100,000 blocks (~4 years at 60s/block)
 *   - Max Supply:    210,000,000 SNTI
 *   - Address:       bech32m prefix "snti"
 *   - PoW:           Pure XMSS tree building (NO SHA-256 nonce)
 *
 * PoUW v2 approach:
 *   Miner searches SK_SEED (96 bytes) until XMSS root < target.
 *   Building the full XMSS tree (h=10, 1024 leaves) IS the work.
 *   block.xmssRoot = XMSS root hash, block.nNonce = 0 (unused).
 *   Difficulty adjusted per-block via EMA (alpha=0.1).
 *   powLimit = 2^256/156 (target: 156 attempts per block, 4 cores).
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        // SNTI FIX (18/Jun/2026): was 210,000 (Bitcoin's value, unscaled), which
        // at 60s/block gives ~146 days between halvings, not the "~4 years"
        // the whitepaper promises (and not even the "~2 years" the old
        // comment here claimed -- both were wrong, and disagreed with each
        // other). Bitcoin's 210,000-block halving assumes 600s/block; SNTI
        // blocks are 10x faster (60s), so the interval must be 10x more
        // blocks (2,100,000) to land on the same ~4-year real-world cadence.
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0; // No Segwit in Quant v1 — XMSS keys are 64 bytes
        consensus.MinBIP9WarningHeight = 0;
        // SNTI PoUW v2: powLimit must exactly match what nBits=0x2001a41a encodes.
        // nBits decode: mantissa=0x01a41a, exponent=0x20(32) →
        //   target = 0x01a41a * 256^(32-3) = 0x01a41a followed by 29 zero bytes.
        // The old repeating value "01a41a41a41a..." was larger than the genesis
        // target, making powLimit inconsistent with the genesis nBits (C-2 audit fix).
        consensus.powLimit = uint256S("01a41a0000000000000000000000000000000000000000000000000000000000");
        // SNTI PoUW v2: EMA smoothing over 10 blocks (H-1 audit fix).
        // nPowTargetTimespan=60 gave DifficultyAdjustmentInterval=1 (retarget every
        // block), which caused 4x difficulty swings per block under variable XMSS
        // tree-build times. 10-block smoothing keeps fast response while damping
        // single-block outliers — still much faster than Bitcoin's 2016-block window.
        consensus.nPowTargetTimespan = 600; // 10-block EMA window
        consensus.nPowTargetSpacing = 60;   // 60 seconds target block time
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815;  // ~90% of 2016
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        // Derived from: snti-cli getblockheader $(snti-cli getblockhash 268)
        // Block 268 — 2026-06-29, chainwork 0x38ab4, hash ec5b9b98...
        consensus.nMinimumChainWork = uint256S("000000000000000000000000000000000000000000000000000000000038ab4");
        // Scripts in blocks 0–268 are skipped during IBD (safe: deeply buried).
        consensus.defaultAssumeValid = uint256S("ec5b9b9854e64d0982ea1e1a8046680d328d582d1d922127a34c794dcb4b07c7");

        // SNTI: PoUW — enable on all Quant chains from genesis
        consensus.fPoUW = true;
        consensus.nPoUWStartHeight = 1;
        consensus.nPoUWv2StartHeight = 1;   // v1 proofs never valid on mainnet
        consensus.nPoUWv3StartHeight = 200; // hashMerkleRoot included in preimage from block 200
        consensus.nPoUWLeafReuseActivation = 1000; // M7: leaf-reuse prevention active from block 1000
        consensus.nPoUWFSLSeedVerifyHeight = 3000; // audit T-1: FSL sk_seed must match claimed root from block 3000
        consensus.nPoUWStuckRecoveryHardenHeight = 4400; // audit KRITIS #5 (2 Jul 2026): require corroborated stuck-chain evidence, chain height was 3907 when written
        consensus.nPoUWDiffbitsGrandfatherHeight = 300; // 2 Jul 2026: exhaustive scan of all 3907 blocks found nBits mismatches only at height 7-273 (pre-"Sesi 4" difficulty algorithm churn); grandfathers those in so fresh IBD sync from genesis is possible again
        consensus.nPoUWMaxSigSize = 4096;
        consensus.nXMSSChainId = 1; // mainnet

        // SNTI magic bytes: "SNTI" = 0x534E5449
        pchMessageStart[0] = 0x53;
        pchMessageStart[1] = 0x4E;
        pchMessageStart[2] = 0x54;
        pchMessageStart[3] = 0x49;
        // P2P Port: 9333
        nDefaultPort = 9333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 20;
        m_assumed_chain_state_size = 3;

        // SNTI PoUW v2 mainnet genesis
        // nTime=1782474812 (Fri Jun 26 11:53:32 UTC 2026) — official launch
        // nNonce=0 (unused in PoUW v2 — SK_SEED search replaces nNonce grinding)
        // nBits=0x2001a41a (= powLimit mainnet: 2^256/156)
        // xmssRoot skipped at height=0 (nPoUWStartHeight=1)
        genesis = CreateGenesisBlock(1782474812, 0, 0x2001a41a, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        vSeeds.clear();
        // SNTI DNS seeds — assentian.network
        // seed  → 104.234.26.7 (Main VPS, Indonesia)
        // seed2 → 166.88.227.172 (Seed-US, Kansas City)
        // seed3 → 103.195.190.192 (Seed-APAC, Singapore)
        vSeeds.emplace_back("seed.assentian.network.");
        vSeeds.emplace_back("seed2.assentian.network.");
        vSeeds.emplace_back("seed3.assentian.network.");

        // SNTI mainnet hardcoded seed nodes.
        // TODO(mainnet): add 2+ nodes in EU and APAC before public launch.
        vFixedSeeds = std::vector<uint8_t>(chainparams_seed_main, chainparams_seed_main + sizeof(chainparams_seed_main));

        // Quant address prefixes — different from Bitcoin
        // Q prefix for mainnet P2PKH (whitepaper: quantum-resistant addresses)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 81);  // 'Q' prefix (0x51)
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 86);  // 'V' prefix (0x56)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 128); // WIF
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};        // xpub-like
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};        // xprv-like

        bech32_hrp = "snti";  // SNTI: mainnet address prefix → snti1q...

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Update every ~500 blocks: snti-cli getblockhash <h> then getblockheader <hash>
        checkpointData = {
            {
                {0,  consensus.hashGenesisBlock},
                {90, uint256S("da8569ca75a811dc36ea22849ae53ad95ae643ff764e2960519e236b84952d96")},
            }
        };

        // SNTI PoUW v2: chainTxData
        chainTxData = ChainTxData{
            .nTime    = 1782474812,
            .nTxCount = 1,
            .dTxRate  = 0,
        };
    }
};

/**
 * Quant Testnet — for testing XMSS + PoUW before mainnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 2100000;  // SNTI FIX 18/Jun/2026: scaled 10x for 60s blocks, see mainnet comment
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // TESTNET: minimum difficulty for easy genesis mining during dev
        // TODO: change to 0x1d00ffff before public testnet launch
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // testnet: max
        consensus.nPowTargetTimespan = 60;  // H5 fix: match mainnet EMA per-block
        consensus.nPowTargetSpacing = 60;  // 60 seconds (whitepaper)
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        // SNTI: minimum chain work at testnet block 100 — prevents attacker from
        // creating a fake low-work chain from genesis (51% / long-range reorg defence).
        // Chainwork at block 100: derived from getblockheader <hash_100>.chainwork
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000000000031006");
        // defaultAssumeValid: block 100 — scripts in blocks 0..100 are skipped
        // during IBD to speed up initial sync.
        consensus.defaultAssumeValid = uint256S("6f91d530d998eb317196b655bb7be59f55f1241fdce415df3cbae039aae1ec0c");

        // SNTI: PoUW — enable on all Quant chains from genesis
        consensus.fPoUW = true;
        consensus.nPoUWStartHeight = 1;
        consensus.nPoUWv2StartHeight = 1;   // v1 proofs never valid on testnet
        consensus.nPoUWv3StartHeight = 200; // hashMerkleRoot included in preimage from block 200
        consensus.nPoUWLeafReuseActivation = 200; // M7: enforce from block 200 on testnet
        consensus.nPoUWFSLSeedVerifyHeight = 200; // audit T-1: enforce from block 200 on testnet
        consensus.nPoUWStuckRecoveryHardenHeight = 200; // audit KRITIS #5: enforce from block 200 on testnet
        consensus.nPoUWMaxSigSize = 4096;
        consensus.nXMSSChainId = 2; // testnet

        // Testnet magic: "qTST" = 0x71545354
        pchMessageStart[0] = 0x73;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0x53;
        pchMessageStart[3] = 0x54;
        nDefaultPort = 19333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 10;
        m_assumed_chain_state_size = 2;

        // SNTI PoUW v2: genesis
        // nNonce=0 (unused in PoUW v2), nBits=0x207fffff
        // xmssRoot will be computed by first miner — genesis is special case
        genesis = CreateGenesisBlock(1782275807, 0, 0x207fffff, 1, 50 * COIN);
        // hashGenesisBlock will be updated after first mine
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();

        // SNTI testnet hardcoded seed nodes.
        // Eclipse attack mitigation: maintain at least 3 seed nodes in
        // different AS/regions. Current node: 104.234.26.7 (AS — US).
        // TODO(mainnet): add 2+ nodes in EU and APAC before public launch.
        vFixedSeeds = std::vector<uint8_t>(chainparams_seed_test, chainparams_seed_test + sizeof(chainparams_seed_test));

        // SNTI testnet DNS seeds — assentian.network
        // A record: testnet-seed.assentian.network → 104.234.26.7
        vSeeds.emplace_back("testnet-seed.assentian.network.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tsnti";  // SNTI: testnet/signet address prefix → tsnti1q...

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // SNTI: checkpoints — hardcoded block hashes from testnet (Jun 27 2026).
        // A node that diverges from these hashes at these heights is on a fork.
        // Update every ~500 blocks by running: bitcoin-cli getblockhash <height>
        checkpointData = {
            {
                {0,   consensus.hashGenesisBlock},
                {50,  uint256S("ca854a860b36b8a5bee587304998f94debbd7b20d272a767e0b18a24d994e7d7")},
                {100, uint256S("6f91d530d998eb317196b655bb7be59f55f1241fdce415df3cbae039aae1ec0c")},
            }
        };

        // SNTI PoUW v2: chainTxData
        chainTxData = ChainTxData{
            .nTime    = 1782556387,
            .nTxCount = 1,
            .dTxRate  = 0,
        };
    }
};

/**
 * Quant Signet — for controlled testing
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!options.challenge) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{.nTime = 0, .nTxCount = 0, .dTxRate = 0};
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{.nTime = 0, .nTxCount = 0, .dTxRate = 0};
        }

        // SNTI: PoUW — enable on all Quant chains from genesis
        consensus.fPoUW = true;
        consensus.nPoUWStartHeight = 1;
        consensus.nPoUWv2StartHeight = 1; // v1 proofs never valid on signet
        consensus.nPoUWv3StartHeight = 1; // signet: use new preimage from genesis
        consensus.nPoUWMaxSigSize = 4096;
        consensus.nXMSSChainId = 3; // signet

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 2100000;  // SNTI FIX 18/Jun/2026: scaled 10x for 60s blocks, see mainnet comment
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.nPowTargetTimespan = 60;  // N2 fix: match mainnet EMA per-block (was 14*24*60*60)
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("00000377ae000000000000000000000000000000000000000000000000000000");
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 39333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1781545300, 0, 0x1e0377ae, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tsnti";  // SNTI: testnet/signet address prefix → tsnti1q...

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Quant Regtest — LOCAL TESTING ONLY
 *
 * - 60 second block target (matches mainnet)
 * - No retargeting (instant blocks for testing)
 * - Low difficulty
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        // Fast halving for testing (every 150 blocks)
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60;  // 60 seconds for regtest
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;  // NO retargeting for instant test blocks
        consensus.nRuleChangeActivationThreshold = 108;
        consensus.nMinerConfirmationWindow = 144;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Regtest magic: "qREG" = 0x71524547
        pchMessageStart[0] = 0x73;
        pchMessageStart[1] = 0x52;
        pchMessageStart[2] = 0x45;
        pchMessageStart[3] = 0x47;
        nDefaultPort = 29333;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        // SNTI PoUW v2: genesis
        // nNonce=0 (unused in PoUW v2), nBits=0x207fffff
        // xmssRoot will be computed by first miner — genesis is special case
        genesis = CreateGenesisBlock(1782275807, 0, 0x207fffff, 1, 50 * COIN);
        // hashGenesisBlock will be updated after first mine
        consensus.hashGenesisBlock = genesis.GetHash();

        // SNTI: PoUW — enable on all Quant chains from genesis
        consensus.fPoUW = true;
        consensus.nPoUWStartHeight = 1;
        consensus.nPoUWv2StartHeight = 1; // v1 proofs never valid on regtest
        consensus.nPoUWv3StartHeight = 1; // regtest: use new preimage from genesis
        consensus.nPoUWFSLSeedVerifyHeight = 1; // audit T-1: enforce from genesis on regtest
        consensus.nPoUWStuckRecoveryHardenHeight = 1; // audit KRITIS #5: enforce from genesis on regtest
        consensus.nPoUWMaxSigSize = 4096;
        consensus.nXMSSChainId = 4; // regtest (3=signet, avoid chain_id collision)

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        // SNTI regtest hardcoded seed (104.234.26.7)
        vFixedSeeds = std::vector<uint8_t>(chainparams_seed_reg, chainparams_seed_reg + sizeof(chainparams_seed_reg));

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{.nTime = 0, .nTxCount = 0, .dTxRate = 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "sntirt";  // SNTI: regtest address prefix → sntirt1q...
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}
