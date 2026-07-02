// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chain.h>
#include <hash.h>
#include <chainparams.h>
#include <common/system.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <key_io.h>
#include <net.h>
#include <node/context.h>
#include <node/miner.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <xmss_tree_ledger.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>

// SNTI: PoUW mining
// SNTI PoUW v2 include
#include <pouw_v2.h>
#include <pouw_v2_keyder.h>
#include <xmss_bridge.h>
#include <xmss_miner_state.h>
#include <logging.h>
#include <util/fs.h>

#include <memory>
#include <stdint.h>

using node::BlockAssembler;
using node::CBlockTemplate;
using node::NodeContext;
using node::RegenerateCommitments;
using node::UpdateTime;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is -1.
 * If 'height' is -1, compute the estimate from current chain tip.
 * If 'height' is a valid block height, compute the estimate at the time when a given block was found.
 */
static UniValue GetNetworkHashPS(int lookup, int height, const CChain& active_chain) {
    if (lookup < -1 || lookup == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid nblocks. Must be a positive number or -1.");
    }

    if (height < -1 || height > active_chain.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block does not exist at specified height");
    }

    const CBlockIndex* pb = active_chain.Tip();

    if (height >= 0) {
        pb = active_chain[height];
    }

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup == -1)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    const CBlockIndex* pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

static RPCHelpMan getnetworkhashps()
{
    return RPCHelpMan{"getnetworkhashps",
                "\nReturns the estimated network hashes per second based on the last n blocks.\n"
                "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
                "Pass in [height] to estimate the network speed at the time when a certain block was found.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::Default{120}, "The number of previous blocks to calculate estimate from, or -1 for blocks since last difficulty change."},
                    {"height", RPCArg::Type::NUM, RPCArg::Default{-1}, "To estimate at the time of the given height."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Hashes per second estimated"},
                RPCExamples{
                    HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetNetworkHashPS(self.Arg<int>(0), self.Arg<int>(1), chainman.ActiveChain());
},
    };
}

static bool GenerateBlock(ChainstateManager& chainman, CBlock& block, uint64_t& max_tries, std::shared_ptr<const CBlock>& block_out, bool process_new_block)
{
    block_out.reset();
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // SNTI PoUW v2: Stateful XMSS mining loop
    // - Reuse SK across blocks (1 tree = 1024 blocks)
    // - leafIndex tracked persistently to prevent WOTS+ key reuse
    // - New tree built only when current tree exhausted
    {
        // Load or build XMSS miner state
        fs::path datadir = gArgs.GetDataDirNet();
        PoUWv2::XMSSMinerStateManager state_mgr(datadir);
        PoUWv2::XMSSMinerState state;

        // SNTI PoUW v2: collect failed seeds for key derivation
        PoUWv2KeyDer::FailedSeedList failed_seeds;
        {
            LOCK(cs_main);
            const CBlockIndex* tip = chainman.ActiveChain().Tip();
            failed_seeds.block_height = tip ? (uint32_t)(tip->nHeight + 1) : 1;
        }

        if (!state_mgr.Load(state)) {
            LogPrintf("PoUW v2: building new XMSS tree...\n");
            if (!PoUWv2::BuildNewTree(state)) {
                LogPrintf("PoUW v2: BuildNewTree failed!\n");
                return false;
            }
            if (!state_mgr.Save(state)) {
                LogPrintf("PoUW v2: failed to save initial state\n");
                return false;
            }
            // SNTI fix (1 Jul 2026): register this tree in the unified
            // leaf ledger so wallet spend-signing can later claim leaves
            // from it safely, coordinated with mining via the same file
            // and lock (see xmss_tree_ledger.h for the bug this closes).
            if (!PoUWv2::XMSSTreeLedgerInit(datadir, state)) {
                LogPrintf("PoUW v2: failed to init unified ledger for new tree\n");
                return false;
            }
        } else if (!PoUWv2::XMSSTreeLedgerExists(datadir, state.xmssRoot)) {
            // Tree predates the unified ledger. Adopt its current (miner-
            // authoritative) leaf position as-is; no-ops if a ledger
            // already exists so this never clobbers real progress.
            PoUWv2::XMSSTreeLedgerSeedFromActive(datadir, state);
        }

        // Preimage signed by miner must match CheckPoUW in validation.cpp.
        // From nPoUWv3StartHeight the preimage includes hashMerkleRoot so the
        // proof binds to the block's transaction set (audit fix #1).
        int next_height;
        {
            LOCK(cs_main);
            const CBlockIndex* tip = chainman.ActiveChain().Tip();
            next_height = tip ? tip->nHeight + 1 : 1;
        }
        const Consensus::Params& cp = chainman.GetParams().GetConsensus();
        uint256 preimage_hash;
        {
            HashWriter hw{};
            if (next_height >= cp.nPoUWv3StartHeight) {
                // v3 preimage: explicitly compute the "base" merkle root by
                // stripping any PW2/FSL OP_RETURN outputs that may already be
                // in the coinbase. This mirrors ComputePoUWBaseMerkleRoot() in
                // validation.cpp and is order-independent: the same value is
                // produced whether proof/FSL are in the coinbase or not.
                CMutableTransaction base_cb(*block.vtx[0]);
                base_cb.vout.erase(
                    std::remove_if(base_cb.vout.begin(), base_cb.vout.end(),
                        [](const CTxOut& out) -> bool {
                            const CScript& s = out.scriptPubKey;
                            if (s.empty() || s[0] != OP_RETURN) return false;
                            CScript::const_iterator pc = s.begin() + 1;
                            opcodetype opc;
                            std::vector<unsigned char> d;
                            if (!s.GetOp(pc, opc, d) || d.size() < 4) return false;
                            return (d[0]=='P' && d[1]=='W' && d[2]=='2' && d[3]==0x02) ||
                                   (d[0]=='F' && d[1]=='S' && d[2]=='L' && d[3]==0x01);
                        }),
                    base_cb.vout.end());
                std::vector<uint256> leaves;
                leaves.push_back(MakeTransactionRef(std::move(base_cb))->GetHash());
                for (size_t i = 1; i < block.vtx.size(); i++)
                    leaves.push_back(block.vtx[i]->GetHash());
                uint256 base_merkle = ComputeMerkleRoot(std::move(leaves));
                hw << block.nVersion << block.hashPrevBlock
                   << base_merkle << block.nTime << block.nBits;
            } else {
                hw << block.nVersion << block.hashPrevBlock
                   << block.nTime << block.nBits;
            }
            preimage_hash = hw.GetHash();
        }

        arith_uint256 target;
        target.SetCompact(block.nBits);
        LogPrintf("PoUW v2: block.nBits=%08x target=%s\n", block.nBits, ArithToUint256(target).GetHex().substr(0,16));

        LogPrintf("PoUW v2: mining with leaf %u/1024, root=%s\n",
                  state.nextLeafIndex,
                  state.xmssRoot.GetHex().substr(0, 16));

        // PoUW v2: satu sign attempt per leaf
        // Jika root tidak < target, build tree baru (search SK_SEED baru)
        // Tapi kita reuse tree yang ada dulu — sign dengan leaf berikutnya
        // Jika root tree aktif tidak pernah < target, perlu tree baru
        // Strategy: coba sign dengan state saat ini, cek root < target
        // Root adalah properti tree (fixed per tree), bukan per-leaf
        // Jadi: jika root tree aktif > target → perlu tree baru

        bool found = false;
        auto proof_ptr = std::make_unique<PoUWv2::PoUWv2Proof>();
        PoUWv2::PoUWv2Proof& proof = *proof_ptr;

        // Hard limit on XMSS tree builds per RPC call (~2.5s each → ~50s max).
        // Prevents the HTTP worker thread from being permanently blocked while
        // the RPC work queue fills up and all other calls get rejected.
        // The external miner loop (snti-miner.sh) retries immediately on false return.
        static constexpr uint64_t POUW_MAX_TREES_PER_CALL = 20;
        uint64_t trees_this_call = 0;

        while (max_tries > 0 && !chainman.m_interrupt) {
            // Cek apakah root tree aktif < target
            if (UintToArith256(state.xmssRoot) <= target) {
                // Root valid! Sign block dengan leaf berikutnya
                if (state.IsExhausted()) {
                    LogPrintf("PoUW v2: tree exhausted, building new tree\n");
                    if (!PoUWv2::BuildNewTree(state)) break;
                    if (!state_mgr.Save(state)) break;
                    if (!PoUWv2::XMSSTreeLedgerInit(datadir, state)) break;
                    continue;
                }

                // SNTI fix (1 Jul 2026): sign through the unified ledger
                // instead of this function's local `state` copy directly.
                // This is the ONE claim path shared with wallet spend-
                // signing (wallet/xmss_signer.cpp SignXMSS), so a leaf can
                // never be double-claimed by mining and a wallet spend
                // racing each other. Fsyncs to disk before returning.
                std::vector<uint8_t> hash32(preimage_hash.begin(), preimage_hash.end());
                std::vector<uint8_t> raw_sig;
                uint32_t leaf_used = 0;
                if (!PoUWv2::XMSSTreeLedgerClaimAndSign(datadir, state.xmssRoot, hash32, raw_sig, leaf_used)) {
                    LogPrintf("PoUW v2: unified ledger sign refused for root=%s (exhausted, "
                              "blacklisted, or I/O error) -- rotating to a new tree\n",
                              state.xmssRoot.GetHex().substr(0, 16));
                    if (!PoUWv2::BuildNewTree(state)) break;
                    if (!state_mgr.Save(state)) break;
                    if (!PoUWv2::XMSSTreeLedgerInit(datadir, state)) break;
                    continue;
                }

                // raw_sig format: [idx(4) | R(32) | WOTS_sig(2144) | auth_path(320)]
                {
                    size_t off = 4; // skip leaf index prefix
                    memcpy(proof.r,         raw_sig.data() + off, PoUWv2::R_BYTES);        off += PoUWv2::R_BYTES;
                    memcpy(proof.wots_sig,  raw_sig.data() + off, PoUWv2::WOTS_SIG_BYTES); off += PoUWv2::WOTS_SIG_BYTES;
                    memcpy(proof.auth_path, raw_sig.data() + off, PoUWv2::AUTH_PATH_BYTES);

                    // PUB_SEED/root are static for a tree's whole lifetime
                    // (only the leaf/BDS-traversal state changes per sign),
                    // so reading them from this call's locally-held `state`
                    // copy is still valid even though the ledger -- not this
                    // copy -- was the one that actually advanced the leaf.
                    xmss_params params;
                    xmss_parse_oid(&params, PoUWv2::XMSS_OID);
                    size_t sk_pubseed_off = 4 + params.index_bytes + params.n + params.n + params.n;
                    memcpy(proof.xmss_pk,      state.xmssRoot.begin(), 32);
                    memcpy(proof.xmss_pk + 32, state.sk.data() + sk_pubseed_off, params.n);
                }

                // Keep the local pointer file's leaf counter in sync too, for
                // this loop's own exhaustion/logging checks -- the ledger
                // file, not this copy, remains the safety-critical source of
                // truth for whether a leaf may be claimed.
                state.nextLeafIndex = leaf_used + 1;
                state_mgr.Save(state);

                // Set block fields
                block.xmssRoot   = state.xmssRoot;
                block.nLeafIndex = leaf_used;
                block.nNonce     = 0;

                // Embed proof ke coinbase OP_RETURN
                std::vector<uint8_t> proof_bytes = proof.Serialize();
                CMutableTransaction coinbase(*block.vtx[0]);
                CScript proof_script;
                proof_script << OP_RETURN << proof_bytes;
                coinbase.vout.push_back(CTxOut(0, proof_script));
                block.vtx[0] = MakeTransactionRef(std::move(coinbase));
                block.hashMerkleRoot = BlockMerkleRoot(block);

                LogPrintf("PoUW v2: found valid block! root=%s leaf=%u\n",
                          state.xmssRoot.GetHex().substr(0, 16), leaf_used);
                // SNTI PoUW v2: embed failed seeds + commitmentsRoot
                if (failed_seeds.entries.size() >= PoUWv2KeyDer::MIN_FAILED_SEEDS) {
                    block.commitmentsRoot = failed_seeds.ComputeMerkleRoot();
                    std::vector<uint8_t> seeds_bytes = failed_seeds.Serialize();
                    CMutableTransaction cb_seeds(*block.vtx[0]);
                    CScript seeds_script;
                    seeds_script << OP_RETURN << seeds_bytes;
                    cb_seeds.vout.push_back(CTxOut(0, seeds_script));
                    block.vtx[0] = MakeTransactionRef(std::move(cb_seeds));
                    block.hashMerkleRoot = BlockMerkleRoot(block);
                    LogPrintf("PoUW v2: %zu seeds embedded, commitmentsRoot=%s\n",
                              failed_seeds.entries.size(),
                              block.commitmentsRoot.GetHex().substr(0, 16));
                }
                found = true;
                break;
            } else {
                // Root tree aktif > target — perlu tree baru
                if (trees_this_call >= POUW_MAX_TREES_PER_CALL) {
                    LogPrintf("PoUW v2: yielding after %llu trees (RPC throttle), will retry\n",
                              (unsigned long long)trees_this_call);
                    break; // return false → miner script loops immediately
                }
                LogPrintf("PoUW v2: root > target, building new tree (attempt %llu)\n",
                          (unsigned long long)(DEFAULT_MAX_TRIES - max_tries));
                // SNTI PoUW v2: collect failed seed
                // SK layout: OID(4)+idx(4)+SK_SEED(32)+SK_PRF(32)+root(32)+PUB_SEED(32)+BDS(...)
                // SEED_BYTES = SK_SEED(32)+SK_PRF(32)+PUB_SEED(32) = 96 bytes (non-contiguous in SK)
                if (failed_seeds.entries.size() < PoUWv2KeyDer::MAX_FAILED_SEEDS) {
                    uint8_t fsl_seed[PoUWv2KeyDer::SEED_BYTES];
                    memcpy(fsl_seed,      state.sk.data() + 8,   64); // SK_SEED + SK_PRF
                    memcpy(fsl_seed + 64, state.sk.data() + 104, 32); // PUB_SEED (skip root at 72)
                    failed_seeds.AddFailedSeed(
                        fsl_seed,
                        state.xmssRoot.begin(),
                        failed_seeds.block_height);
                }
                if (!PoUWv2::BuildNewTree(state)) {
                    LogPrintf("PoUW v2: BuildNewTree failed\n");
                    break;
                }
                if (!state_mgr.Save(state)) break;
                if (!PoUWv2::XMSSTreeLedgerInit(datadir, state)) break;
                --max_tries;
                ++trees_this_call;
            }
        }

        if (!found) {
            return false;
        }
    }

    block_out = std::make_shared<const CBlock>(block);

    if (!process_new_block) return true;

    if (!chainman.ProcessNewBlock(block_out, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
    }

    return true;
}

static UniValue generateBlocks(ChainstateManager& chainman, const CTxMemPool& mempool, const CScript& coinbase_script, int nGenerate, uint64_t nMaxTries)
{
    UniValue blockHashes(UniValue::VARR);
    while (nGenerate > 0 && !chainman.m_interrupt) {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler{chainman.ActiveChainstate(), &mempool}.CreateNewBlock(coinbase_script));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");

        std::shared_ptr<const CBlock> block_out;
        if (!GenerateBlock(chainman, pblocktemplate->block, nMaxTries, block_out, /*process_new_block=*/true)) {
            break;
        }

        if (block_out) {
            --nGenerate;
            blockHashes.push_back(block_out->GetHash().GetHex());
        }
    }
    return blockHashes;
}

static bool getScriptFromDescriptor(const std::string& descriptor, CScript& script, std::string& error)
{
    FlatSigningProvider key_provider;
    const auto desc = Parse(descriptor, key_provider, error, /* require_checksum = */ false);
    if (desc) {
        if (desc->IsRange()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?");
        }

        FlatSigningProvider provider;
        std::vector<CScript> scripts;
        if (!desc->Expand(0, key_provider, scripts, provider)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot derive script without private keys");
        }

        // Combo descriptors can have 2 or 4 scripts, so we can't just check scripts.size() == 1
        CHECK_NONFATAL(scripts.size() > 0 && scripts.size() <= 4);

        if (scripts.size() == 1) {
            script = scripts.at(0);
        } else if (scripts.size() == 4) {
            // For uncompressed keys, take the 3rd script, since it is p2wpkh
            script = scripts.at(2);
        } else {
            // Else take the 2nd script, since it is p2pkh
            script = scripts.at(1);
        }

        return true;
    } else {
        return false;
    }
}

static RPCHelpMan generatetodescriptor()
{
    return RPCHelpMan{
        "generatetodescriptor",
        "Mine to a specified descriptor and return the block hashes.",
        {
            {"num_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor to send the newly generated bitcoin to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "hashes of blocks generated",
            {
                {RPCResult::Type::STR_HEX, "", "blockhash"},
            }
        },
        RPCExamples{
            "\nGenerate 11 blocks to mydesc\n" + HelpExampleCli("generatetodescriptor", "11 \"mydesc\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto num_blocks{self.Arg<int>(0)};
    const auto max_tries{self.Arg<uint64_t>(2)};

    CScript coinbase_script;
    std::string error;
    if (!getScriptFromDescriptor(self.Arg<std::string>(1), coinbase_script, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);
    ChainstateManager& chainman = EnsureChainman(node);

    return generateBlocks(chainman, mempool, coinbase_script, num_blocks, max_tries);
},
    };
}

static RPCHelpMan generate()
{
    return RPCHelpMan{"generate", "has been replaced by the -generate cli option. Refer to -help for more information.", {}, {}, RPCExamples{""}, [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, self.ToString());
    }};
}

static RPCHelpMan generatetoaddress()
{
    return RPCHelpMan{"generatetoaddress",
        "Mine to a specified address and return the block hashes.",
         {
             {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
             {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated bitcoin to."},
             {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
         },
         RPCResult{
             RPCResult::Type::ARR, "", "hashes of blocks generated",
             {
                 {RPCResult::Type::STR_HEX, "", "blockhash"},
             }},
         RPCExamples{
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
            + "If you are using the " PACKAGE_NAME " wallet, you can get a new address to send the newly generated bitcoin to with:\n"
            + HelpExampleCli("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int num_blocks{request.params[0].getInt<int>()};
    const uint64_t max_tries{request.params[2].isNull() ? DEFAULT_MAX_TRIES : request.params[2].getInt<int>()};

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);
    ChainstateManager& chainman = EnsureChainman(node);

    CScript coinbase_script = GetScriptForDestination(destination);

    return generateBlocks(chainman, mempool, coinbase_script, num_blocks, max_tries);
},
    };
}

static RPCHelpMan generateblock()
{
    return RPCHelpMan{"generateblock",
        "Mine a set of ordered transactions to a specified address or descriptor and return the block hash.",
        {
            {"output", RPCArg::Type::STR, RPCArg::Optional::NO, "The address or descriptor to send the newly generated bitcoin to."},
            {"transactions", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of hex strings which are either txids or raw transactions.\n"
                "Txids must reference transactions currently in the mempool.\n"
                "All transactions must be valid and in valid order, otherwise the block will be rejected.",
                {
                    {"rawtx/txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"submit", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to submit the block before the RPC call returns or to return it as hex."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "hash of generated block"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "hex of generated block, only present when submit=false"},
            }
        },
        RPCExamples{
            "\nGenerate a block to myaddress, with txs rawtx and mempool_txid\n"
            + HelpExampleCli("generateblock", R"("myaddress" '["rawtx", "mempool_txid"]')")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto address_or_descriptor = request.params[0].get_str();
    CScript coinbase_script;
    std::string error;

    if (!getScriptFromDescriptor(address_or_descriptor, coinbase_script, error)) {
        const auto destination = DecodeDestination(address_or_descriptor);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address or descriptor");
        }

        coinbase_script = GetScriptForDestination(destination);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);

    std::vector<CTransactionRef> txs;
    const auto raw_txs_or_txids = request.params[1].get_array();
    for (size_t i = 0; i < raw_txs_or_txids.size(); i++) {
        const auto str(raw_txs_or_txids[i].get_str());

        uint256 hash;
        CMutableTransaction mtx;
        if (ParseHashStr(str, hash)) {

            const auto tx = mempool.get(hash);
            if (!tx) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Transaction %s not in mempool.", str));
            }

            txs.emplace_back(tx);

        } else if (DecodeHexTx(mtx, str)) {
            txs.push_back(MakeTransactionRef(std::move(mtx)));

        } else {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Transaction decode failed for %s. Make sure the tx has at least one input.", str));
        }
    }

    const bool process_new_block{request.params[2].isNull() ? true : request.params[2].get_bool()};
    CBlock block;

    ChainstateManager& chainman = EnsureChainman(node);
    {
        LOCK(cs_main);

        std::unique_ptr<CBlockTemplate> blocktemplate(BlockAssembler{chainman.ActiveChainstate(), nullptr}.CreateNewBlock(coinbase_script));
        if (!blocktemplate) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        }
        block = blocktemplate->block;
    }

    CHECK_NONFATAL(block.vtx.size() == 1);

    // Add transactions
    block.vtx.insert(block.vtx.end(), txs.begin(), txs.end());
    RegenerateCommitments(block, chainman);

    {
        LOCK(cs_main);

        BlockValidationState state;
        if (!TestBlockValidity(state, chainman.GetParams(), chainman.ActiveChainstate(), block, chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock), false, false)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("TestBlockValidity failed: %s", state.ToString()));
        }
    }

    std::shared_ptr<const CBlock> block_out;
    uint64_t max_tries{DEFAULT_MAX_TRIES};

    if (!GenerateBlock(chainman, block, max_tries, block_out, process_new_block) || !block_out) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to make block.");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("hash", block_out->GetHash().GetHex());
    if (!process_new_block) {
        DataStream block_ser;
        block_ser << TX_WITH_WITNESS(*block_out);
        obj.pushKV("hex", HexStr(block_ser));
    }
    return obj;
},
    };
}

static RPCHelpMan getmininginfo()
{
    return RPCHelpMan{"getmininginfo",
                "\nReturns a json object containing mining-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "blocks", "The current block"},
                        {RPCResult::Type::NUM, "currentblockweight", /*optional=*/true, "The block weight of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblocktx", /*optional=*/true, "The number of block transactions of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                        {RPCResult::Type::NUM, "networkhashps", "The network hashes per second"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (main, test, signet, regtest)"},
                        {RPCResult::Type::STR, "warnings", "any network and blockchain warnings"},
                    }},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           active_chain.Height());
    if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
    obj.pushKV("difficulty", GetDifficulty(*CHECK_NONFATAL(active_chain.Tip())));
    obj.pushKV("networkhashps",    getnetworkhashps().HandleRequest(request));
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    obj.pushKV("warnings",         GetWarnings(false).original);
    // SNTI: PoUW status
    obj.pushKV("pouw_enabled",     chainman.GetConsensus().fPoUW);
    return obj;
},
    };
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
static RPCHelpMan prioritisetransaction()
{
    return RPCHelpMan{"prioritisetransaction",
                "Accepts the transaction into mined blocks at a higher (or lower) priority\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id."},
                    {"dummy", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "API-Compatibility for previous API. Must be zero or null.\n"
            "                  DEPRECATED. For forward compatibility use named arguments and omit this parameter."},
                    {"fee_delta", RPCArg::Type::NUM, RPCArg::Optional::NO, "The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  Note, that this value is not a fee rate. It is a value to modify absolute fee of the TX.\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Returns true"},
                RPCExamples{
                    HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    const auto dummy{self.MaybeArg<double>(1)};
    CAmount nAmount = request.params[2].getInt<int64_t>();

    if (dummy && *dummy != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.");
    }

    EnsureAnyMemPool(request.context).PrioritiseTransaction(hash, nAmount);
    return true;
},
    };
}

static RPCHelpMan getprioritisedtransactions()
{
    return RPCHelpMan{"getprioritisedtransactions",
        "Returns a map of all user-created (see prioritisetransaction) fee deltas by txid, and whether the tx is present in mempool.",
        {},
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "prioritisation keyed by txid",
            {
                {RPCResult::Type::OBJ, "<transactionid>", "", {
                    {RPCResult::Type::NUM, "fee_delta", "transaction fee delta in satoshis"},
                    {RPCResult::Type::BOOL, "in_mempool", "whether this transaction is currently in mempool"},
                    {RPCResult::Type::NUM, "modified_fee", /*optional=*/true, "modified fee in satoshis. Only returned if in_mempool=true"},
                }}
            },
        },
        RPCExamples{
            HelpExampleCli("getprioritisedtransactions", "")
            + HelpExampleRpc("getprioritisedtransactions", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            CTxMemPool& mempool = EnsureMemPool(node);
            UniValue rpc_result{UniValue::VOBJ};
            for (const auto& delta_info : mempool.GetPrioritisedTransactions()) {
                UniValue result_inner{UniValue::VOBJ};
                result_inner.pushKV("fee_delta", delta_info.delta);
                result_inner.pushKV("in_mempool", delta_info.in_mempool);
                if (delta_info.in_mempool) {
                    result_inner.pushKV("modified_fee", *delta_info.modified_fee);
                }
                rpc_result.pushKV(delta_info.txid.GetHex(), result_inner);
            }
            return rpc_result;
        },
    };
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const BlockValidationState& state)
{
    if (state.IsValid())
        return UniValue::VNULL;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

static std::string gbt_vb_name(const Consensus::DeploymentPos pos) {
    const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
    std::string s = vbinfo.name;
    if (!vbinfo.gbt_force) {
        s.insert(s.begin(), '!');
    }
    return s;
}

static RPCHelpMan getblocktemplate()
{
    return RPCHelpMan{"getblocktemplate",
        "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
        "It returns data needed to construct a block to work on.\n"
        "For full specification, see BIPs 22, 23, 9, and 145:\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki\n",
        {
            {"template_request", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Format of the template",
            {
                {"mode", RPCArg::Type::STR, /* treat as named arg */ RPCArg::Optional::OMITTED, "This must be set to \"template\", \"proposal\" (see BIP 23), or omitted"},
                {"capabilities", RPCArg::Type::ARR, /* treat as named arg */ RPCArg::Optional::OMITTED, "A list of strings",
                {
                    {"str", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported feature, 'longpoll', 'coinbasevalue', 'proposal', 'serverlist', 'workid'"},
                }},
                {"rules", RPCArg::Type::ARR, RPCArg::Optional::NO, "A list of strings",
                {
                    {"segwit", RPCArg::Type::STR, RPCArg::Optional::NO, "(literal) indicates client side segwit support"},
                    {"str", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "other client side supported softfork deployment"},
                }},
                {"longpollid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "delay processing request until the result would vary significantly from the \"longpollid\" of a prior template"},
                {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "proposed block data to check, encoded in hexadecimal; valid only for mode=\"proposal\""},
            },
            },
        },
        {
            RPCResult{"If the proposal was accepted with mode=='proposal'", RPCResult::Type::NONE, "", ""},
            RPCResult{"If the proposal was not accepted with mode=='proposal'", RPCResult::Type::STR, "", "According to BIP22"},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "version", "The preferred block version"},
                {RPCResult::Type::ARR, "rules", "specific block rules that are to be enforced",
                {
                    {RPCResult::Type::STR, "", "name of a rule the client must understand to some extent; see BIP 9 for format"},
                }},
                {RPCResult::Type::OBJ_DYN, "vbavailable", "set of pending, supported versionbit (BIP 9) softfork deployments",
                {
                    {RPCResult::Type::NUM, "rulename", "identifies the bit number as indicating acceptance and readiness for the named softfork rule"},
                }},
                {RPCResult::Type::ARR, "capabilities", "",
                {
                    {RPCResult::Type::STR, "value", "A supported feature, for example 'proposal'"},
                }},
                {RPCResult::Type::NUM, "vbrequired", "bit mask of versionbits the server requires set in submissions"},
                {RPCResult::Type::STR, "previousblockhash", "The hash of current highest block"},
                {RPCResult::Type::ARR, "transactions", "contents of non-coinbase transactions that should be included in the next block",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "data", "transaction data encoded in hexadecimal (byte-for-byte)"},
                        {RPCResult::Type::STR_HEX, "txid", "transaction id encoded in little-endian hexadecimal"},
                        {RPCResult::Type::STR_HEX, "hash", "hash encoded in little-endian hexadecimal (including witness data)"},
                        {RPCResult::Type::ARR, "depends", "array of numbers",
                        {
                            {RPCResult::Type::NUM, "", "transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is"},
                        }},
                        {RPCResult::Type::NUM, "fee", "difference in value between transaction inputs and outputs (in satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one"},
                        {RPCResult::Type::NUM, "sigops", "total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero"},
                        {RPCResult::Type::NUM, "weight", "total transaction weight, as counted for purposes of block limits"},
                    }},
                }},
                {RPCResult::Type::OBJ_DYN, "coinbaseaux", "data that should be included in the coinbase's scriptSig content",
                {
                    {RPCResult::Type::STR_HEX, "key", "values must be in the coinbase (keys may be ignored)"},
                }},
                {RPCResult::Type::NUM, "coinbasevalue", "maximum allowable input to coinbase transaction, including the generation award and transaction fees (in satoshis)"},
                {RPCResult::Type::STR, "longpollid", "an id to include with a request to longpoll on an update to this template"},
                {RPCResult::Type::STR, "target", "The hash target"},
                {RPCResult::Type::NUM_TIME, "mintime", "The minimum timestamp appropriate for the next block time, expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::ARR, "mutable", "list of ways the block template may be changed",
                {
                    {RPCResult::Type::STR, "value", "A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'"},
                }},
                {RPCResult::Type::STR_HEX, "noncerange", "A range of valid nonces"},
                {RPCResult::Type::NUM, "sigoplimit", "limit of sigops in blocks"},
                {RPCResult::Type::NUM, "sizelimit", "limit of block size"},
                {RPCResult::Type::NUM, "weightlimit", /*optional=*/true, "limit of block weight"},
                {RPCResult::Type::NUM_TIME, "curtime", "current timestamp in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::STR, "bits", "compressed target of next block"},
                {RPCResult::Type::NUM, "height", "The height of the next block"},
                {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "Only on signet"},
                {RPCResult::Type::STR_HEX, "default_witness_commitment", /*optional=*/true, "a valid witness commitment for the unmodified block template"},
            }},
        },
        RPCExamples{
                    HelpExampleCli("getblocktemplate", "'{\"rules\": [\"segwit\"]}'")
            + HelpExampleRpc("getblocktemplate", "{\"rules\": [\"segwit\"]}")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CChain& active_chain = active_chainstate.m_chain;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = oparam.find_value("mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = oparam.find_value("longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = oparam.find_value("data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
            if (pindex) {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = active_chain.Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            BlockValidationState state;
            TestBlockValidity(state, chainman.GetParams(), active_chainstate, block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = oparam.find_value("rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (!chainman.GetParams().IsTestChain()) {
        const CConnman& connman = EnsureConnman(node);
        if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, PACKAGE_NAME " is not connected!");
        }

        if (chainman.IsInitialBlockDownload()) {
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME " is in initial sync and waiting for blocks...");
        }
    }

    static unsigned int nTransactionsUpdatedLast;
    const CTxMemPool& mempool = EnsureMemPool(node);

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        std::chrono::steady_clock::time_point checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            const std::string& lpstr = lpval.get_str();

            hashWatchedChain = ParseHashV(lpstr.substr(0, 64), "longpollid");
            nTransactionsUpdatedLastLP = LocaleIndependentAtoi<int64_t>(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = active_chain.Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = std::chrono::steady_clock::now() + std::chrono::minutes(1);

            WAIT_LOCK(g_best_block_mutex, lock);
            while (g_best_block == hashWatchedChain && IsRPCRunning())
            {
                if (g_best_block_cv.wait_until(lock, checktxtime) == std::cv_status::timeout)
                {
                    // Timeout: Check transactions for update
                    // without holding the mempool lock to avoid deadlocks
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += std::chrono::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    const Consensus::Params& consensusParams = chainman.GetParams().GetConsensus();

    // GBT must be called with 'signet' set in the rules for signet chains
    if (consensusParams.signet_blocks && setClientRules.count("signet") != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the signet rule set (call with {\"rules\": [\"segwit\", \"signet\"]})");
    }

    // GBT must be called with 'segwit' set in the rules
    if (setClientRules.count("segwit") != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})");
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t time_start;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;
    if (pindexPrev != active_chain.Tip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - time_start > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = active_chain.Tip();
        time_start = GetTime();

        // Create new block
        CScript scriptDummy = CScript() << OP_TRUE;
        pblocktemplate = BlockAssembler{active_chainstate, &mempool}.CreateNewBlock(scriptDummy);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CHECK_NONFATAL(pindexPrev);
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Update nTime
    UpdateTime(pblock, consensusParams, pindexPrev);
    pblock->nNonce = 0;

    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs to take segwit support into consideration
    const bool fPreSegWit = !DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_SEGWIT);

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.pushKV("data", EncodeHexTx(tx));
        entry.pushKV("txid", txHash.GetHex());
        entry.pushKV("hash", tx.GetWitnessHash().GetHex());

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.pushKV("depends", deps);

        int index_in_template = i - 1;
        entry.pushKV("fee", pblocktemplate->vTxFees[index_in_template]);
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        if (fPreSegWit) {
            CHECK_NONFATAL(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.pushKV("sigops", nTxSigOps);
        entry.pushKV("weight", GetTransactionWeight(tx));

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.pushKV("capabilities", aCaps);

    UniValue aRules(UniValue::VARR);
    aRules.push_back("csv");
    if (!fPreSegWit) aRules.push_back("!segwit");
    if (consensusParams.signet_blocks) {
        // indicate to miner that they must understand signet rules
        // when attempting to mine with this template
        aRules.push_back("!signet");
    }

    UniValue vbavailable(UniValue::VOBJ);
    for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(j);
        ThresholdState state = chainman.m_versionbitscache.State(pindexPrev, consensusParams, pos);
        switch (state) {
            case ThresholdState::DEFINED:
            case ThresholdState::FAILED:
                // Not exposed to GBT at all
                break;
            case ThresholdState::LOCKED_IN:
                // Ensure bit is set in block version
                pblock->nVersion |= chainman.m_versionbitscache.Mask(consensusParams, pos);
                [[fallthrough]];
            case ThresholdState::STARTED:
            {
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                vbavailable.pushKV(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit);
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    if (!vbinfo.gbt_force) {
                        // If the client doesn't support this, don't indicate it in the [default] version
                        pblock->nVersion &= ~chainman.m_versionbitscache.Mask(consensusParams, pos);
                    }
                }
                break;
            }
            case ThresholdState::ACTIVE:
            {
                // Add to rules only
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                aRules.push_back(gbt_vb_name(pos));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    // Not supported by the client; make sure it's safe to proceed
                    if (!vbinfo.gbt_force) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Support for '%s' rule requires explicit client support", vbinfo.name));
                    }
                }
                break;
            }
        }
    }
    result.pushKV("version", pblock->nVersion);
    result.pushKV("rules", aRules);
    result.pushKV("vbavailable", vbavailable);
    result.pushKV("vbrequired", int(0));

    result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
    result.pushKV("transactions", transactions);
    result.pushKV("coinbaseaux", aux);
    result.pushKV("coinbasevalue", (int64_t)pblock->vtx[0]->vout[0].nValue);
    result.pushKV("longpollid", active_chain.Tip()->GetBlockHash().GetHex() + ToString(nTransactionsUpdatedLast));
    result.pushKV("target", hashTarget.GetHex());
    result.pushKV("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1);
    result.pushKV("mutable", aMutable);
    result.pushKV("noncerange", "00000000ffffffff");
    int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
    int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;
    if (fPreSegWit) {
        CHECK_NONFATAL(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
        CHECK_NONFATAL(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
        nSizeLimit /= WITNESS_SCALE_FACTOR;
    }
    result.pushKV("sigoplimit", nSigOpLimit);
    result.pushKV("sizelimit", nSizeLimit);
    if (!fPreSegWit) {
        result.pushKV("weightlimit", (int64_t)MAX_BLOCK_WEIGHT);
    }
    result.pushKV("curtime", pblock->GetBlockTime());
    result.pushKV("bits", strprintf("%08x", pblock->nBits));
    result.pushKV("height", (int64_t)(pindexPrev->nHeight+1));

    if (consensusParams.signet_blocks) {
        result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
    }

    if (!pblocktemplate->vchCoinbaseCommitment.empty()) {
        result.pushKV("default_witness_commitment", HexStr(pblocktemplate->vchCoinbaseCommitment));
    }

    // SNTI R4: PoUW v2 extension fields for mining software.
    // These fields describe what a miner must produce to construct a valid SNTI block.
    if (consensusParams.fPoUW) {
        int64_t next_height = (int64_t)(pindexPrev->nHeight + 1);
        bool pouw_v2_active = (next_height >= consensusParams.nPoUWv2StartHeight);

        // xmss_target: the nBits target expressed as a 32-byte big-endian hex integer.
        // The miner's XMSS tree root (first 32 bytes of xmss_pk) must be numerically
        // less than this value.
        arith_uint256 xmss_target;
        xmss_target.SetCompact(pblock->nBits);

        UniValue pouw(UniValue::VOBJ);
        pouw.pushKV("active",            true);
        pouw.pushKV("version",           pouw_v2_active ? 2 : 1);
        pouw.pushKV("xmss_target",       xmss_target.GetHex());
        pouw.pushKV("xmss_chain_id",     (int64_t)consensusParams.nXMSSChainId);
        pouw.pushKV("coinbase_magic_v2", "50573202"); // "PW2\x02" hex — required OP_RETURN prefix
        pouw.pushKV("fsl_magic",         "46534c01"); // "FSL\x01" hex — required FSL OP_RETURN prefix
        pouw.pushKV("proof_size_bytes",  (int64_t)2564); // magic(4)+xmss_pk(64)+auth_path(320)+wots_sig(2144)+r(32)
        result.pushKV("pouw",            pouw);
    }

    return result;
},
    };
}

class submitblock_StateCatcher final : public CValidationInterface
{
public:
    uint256 hash;
    bool found{false};
    BlockValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), state() {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

static RPCHelpMan submitblock()
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    return RPCHelpMan{"submitblock",
        "\nAttempts to submit new block to network.\n"
        "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n",
        {
            {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data to submit"},
            {"dummy", RPCArg::Type::STR, RPCArg::DefaultHint{"ignored"}, "dummy value, for compatibility with BIP22. This value is ignored."},
        },
        {
            RPCResult{"If the block was accepted", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::STR, "", "According to BIP22"},
        },
        RPCExamples{
                    HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash = block.GetHash();
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
        }
    }

    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
        if (pindex) {
            chainman.UpdateUncommittedBlockStructures(block, pindex);
        }
    }

    bool new_block;
    auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
    RegisterSharedValidationInterface(sc);
    bool accepted = chainman.ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);
    UnregisterSharedValidationInterface(sc);
    if (!new_block && accepted) {
        return "duplicate";
    }
    if (!sc->found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc->state);
},
    };
}

static RPCHelpMan submitheader()
{
    return RPCHelpMan{"submitheader",
                "\nDecode the given hexdata as a header and submit it as a candidate chain tip if valid."
                "\nThrows when the header is invalid.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block header data"},
                },
                RPCResult{
                    RPCResult::Type::NONE, "", "None"},
                RPCExamples{
                    HelpExampleCli("submitheader", "\"aabbcc\"") +
                    HelpExampleRpc("submitheader", "\"aabbcc\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CBlockHeader h;
    if (!DecodeHexBlockHeader(h, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block header decode failed");
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        if (!chainman.m_blockman.LookupBlockIndex(h.hashPrevBlock)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Must submit previous header (" + h.hashPrevBlock.GetHex() + ") first");
        }
    }

    BlockValidationState state;
    chainman.ProcessNewBlockHeaders({h}, /*min_pow_checked=*/true, state);
    if (state.IsValid()) return UniValue::VNULL;
    if (state.IsError()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    }
    throw JSONRPCError(RPC_VERIFY_ERROR, state.GetRejectReason());
},
    };
}

void RegisterMiningRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &getnetworkhashps},
        {"mining", &getmininginfo},
        {"mining", &prioritisetransaction},
        {"mining", &getprioritisedtransactions},
        {"mining", &getblocktemplate},
        {"mining", &submitblock},
        {"mining", &submitheader},

        {"hidden", &generatetoaddress},
        {"hidden", &generatetodescriptor},
        {"hidden", &generateblock},
        {"hidden", &generate},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
