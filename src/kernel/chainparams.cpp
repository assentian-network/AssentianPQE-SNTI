// Copyright (c) 2025 The Quant developers
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
    const char* pszTimestamp = "Assentian-PQE Genesis 21/Jun/2026 - NIST SP 800-208 XMSS - Post Quantum Era Begins";
    // QNT Genesis XMSS public key (64 bytes root||PUB_SEED)
    // Generated: 2026-06-11
    // Algorithm: XMSS-SHA2_10_256 (NIST SP 800-208)
    const CScript genesisOutputScript = CScript() << ParseHex(
        "8c5c7e72fb9a7b07e7fb5262abc79c6e321ddaaf27e33ebed6b9c3a0648a2d08"
        "d0e704faf31f0a29b53463026e7ed85d0a372135423882c996770c8a974ef153"
    ) << OP_XMSS_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Quant Mainnet — post-quantum XMSS signatures, SHA-256 PoW
 *
 * Aligned with WHITEPAPER v0.2 Section 9.2 Technical Specifications:
 *   - P2P Port:      9333  (QNT-specific port)
 *   - Genesis:       Dynamic on launch (see nTime below)
 *   - Block Time:    ~60 seconds (target)
 *   - Halving:       Every 210,000 blocks (~2 years at 60s/block)
 *   - Max Supply:    21,000,000 QNT
 *   - Address:       Base58 prefix Q/V, bech32m "qn"
 *   - Magic Bytes:   0x5155414E ("QUAN")
 *   - PoW:           SHA-256 with XMSS-signed blocks (PoUW v1)
 *
 * PoUW v1 approach:
 *   Miners do standard SHA-256 hash grinding (like Bitcoin).
 *   But block template includes XMSS public key, and the valid block
 *   must be signed by the miner's XMSS key. The signing IS the useful
 *   work that produces cryptographic material.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        // QNT FIX (18/Jun/2026): was 210,000 (Bitcoin's value, unscaled), which
        // at 60s/block gives ~146 days between halvings, not the "~4 years"
        // the whitepaper promises (and not even the "~2 years" the old
        // comment here claimed -- both were wrong, and disagreed with each
        // other). Bitcoin's 210,000-block halving assumes 600s/block; QNT
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
        // PoW: Low difficulty for fair launch, will adjust
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // 60 second target (whitepaper section 6.3)
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;  // 60 SECONDS (whitepaper)
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

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // QNT: PoUW — enable on all Quant chains from genesis
        consensus.fPoUW = true;
        consensus.nPoUWStartHeight = 1;
        consensus.nPoUWMaxSigSize = 4096;

        // Quant magic bytes: "QUAN" = 0x5155414E
        pchMessageStart[0] = 0x53;
        pchMessageStart[1] = 0x4E;
        pchMessageStart[2] = 0x54;
        pchMessageStart[3] = 0x49;
        // P2P Port: 9333
        nDefaultPort = 9333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 20;
        m_assumed_chain_state_size = 3;

        // Genesis: Set to 0 — will be dynamically set on first launch
        // For now, use a recent timestamp placeholder
        // REAL GENESIS TIMESTAMP will be set at official launch (Q4 2026)
        // This is a PLACEHOLDER — do not use for mainnet launch
        genesis = CreateGenesisBlock(1781545300, 0, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = uint256S("743c2849738436a7c96451e5bbe51be98fb676fde212abf56c9d7a7a727f1efc");

        vSeeds.clear();
        // QNT DNS seeds (to be registered at launch)
        // vSeeds.emplace_back("seed.qnt.io.");
        // vSeeds.emplace_back("testnet-seed.qnt.io.");

        // QNT hardcoded seed nodes (104.234.26.7)
        vFixedSeeds = std::vector<uint8_t>(chainparams_seed_main, chainparams_seed_main + sizeof(chainparams_seed_main));

        // Quant address prefixes — different from Bitcoin
        // Q prefix for mainnet P2PKH (whitepaper: quantum-resistant addresses)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 81);  // 'Q' prefix (0x51)
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 86);  // 'V' prefix (0x56)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 128); // WIF
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};        // xpub-like
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};        // xprv-like

        bech32_hrp = "qn";  // whitepaper: native segwit-style addresses

        vFixedSeeds.clear();
        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{
            .nTime    = 1781545300,
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
        consensus.nSubsidyHalvingInterval = 2100000;  // QNT FIX 18/Jun/2026: scaled 10x for 60s blocks, see mainnet comment
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // TESTNET: minimum difficulty for easy genesis mining during dev
        // TODO: change to 0x1d00ffff before public testnet launch
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
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

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // QNT: PoUW — enable on all Quant chains from genesis
        consensus.fPoUW = true;
        consensus.nPoUWStartHeight = 1;
        consensus.nPoUWMaxSigSize = 4096;

        // Testnet magic: "qTST" = 0x71545354
        pchMessageStart[0] = 0x73;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0x53;
        pchMessageStart[3] = 0x54;
        nDefaultPort = 19333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 10;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(1782026818, 1, 0x207fffff, 1, 50 * COIN);
        // TEMP-GENESIS-SEARCH: hapus setelah dapat nonce valid
        {
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
            while (UintToArith256(genesis.GetHash()) > hashTarget) {
                ++genesis.nNonce;
            }
            LogPrintf("QNT-GENESIS-FOUND: nNonce=%u hash=%s\n", genesis.nNonce, genesis.GetHash().ToString());
        }
        consensus.hashGenesisBlock = uint256S("2d858f51fc4af7926bee59c82d06d58a3f260647145aaf6f89263bcb3643b66d");

        vFixedSeeds.clear();
        vSeeds.clear();

        // QNT testnet hardcoded seed nodes (104.234.26.7)
        vFixedSeeds = std::vector<uint8_t>(chainparams_seed_test, chainparams_seed_test + sizeof(chainparams_seed_test));

        // QNT testnet DNS seeds (to be registered)
        // vSeeds.emplace_back("testnet-seed.qnt.io.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tq";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{
            .nTime    = 1781545300,
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

        // QNT: PoUW — enable on all Quant chains from genesis
        consensus.fPoUW = true;
        consensus.nPoUWStartHeight = 1;
        consensus.nPoUWMaxSigSize = 4096;

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 2100000;  // QNT FIX 18/Jun/2026: scaled 10x for 60s blocks, see mainnet comment
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
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
        consensus.hashGenesisBlock = uint256S("743c2849738436a7c96451e5bbe51be98fb676fde212abf56c9d7a7a727f1efc");

        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tq";

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

        genesis = CreateGenesisBlock(1782026818, 1, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = uint256S("2d858f51fc4af7926bee59c82d06d58a3f260647145aaf6f89263bcb3643b66d");

        // QNT: PoUW — enable on all Quant chains from genesis
        consensus.fPoUW = true;
        consensus.nPoUWStartHeight = 1;
        consensus.nPoUWMaxSigSize = 4096;

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        // QNT regtest hardcoded seed (104.234.26.7)
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

        bech32_hrp = "qnr";
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
