// Copyright (c) 2026 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SNTI DRAFT: integration tests for the structural XMSS spend-leaf dedup
// (draft/xmss-spend-leaf-dedup) exercised through a REAL ConnectBlock/
// DisconnectBlock fixture -- not the mocked BaseSignatureChecker used in
// xmss_leaf_capture_tests.cpp. Those tests prove the interpreter-level
// capture wiring in isolation; these prove the whole consensus path (real
// XMSS signature, real CheckInputScripts, real block_tree_db read/write)
// actually behaves as designed once wired together end to end.
//
// Uses the new -testactivationheight=xmssspendleafreuse@N regtest hook
// (see consensus/params.h / kernel/chainparams.cpp, commit 9fe0d40) to turn
// the feature on inside TestChain100Setup's regtest chain, which by default
// disables it (nXMSSSpendLeafReuseActivation == max()).
//
// SCOPE (skeleton, see xmss_spend_leaf_dedup_bypass_gap memory for the
// full plan): covers the mark-on-connect / unmark-on-disconnect /
// leaf-reusable-after-disconnect round trip for DB_POUW_LEAF and
// DB_POUW_LEAF_LIST, using a spend key this test fully controls (built via
// PoUWv2::BuildNewTree(), same "imported/mining-style" multi-use path as
// xmss_signer_tests.cpp's imported_key_multi_use_unaffected). NOT covered
// yet: same-block coinbase-mining-leaf-vs-spend-leaf collision. That needs
// the coinbase's own winning (pubkey, leaf) pair, which GenerateBlock()
// (rpc/mining.cpp) currently generates from a fresh internal random tree
// with no hook to inject or retrieve the SK_SEED it picked -- a real
// signature for that exact pubkey can't be produced from outside without
// one. Left as a follow-up (would need a small, separate test-only
// exposure hook on GenerateBlock/BuildNewTree, analogous to how
// GenerateBlock itself was exposed non-static in commit 69b7a84).

#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <test/util/setup_common.h>
#include <util/rbf.h>
#include <validation.h>
#include <wallet/xmss_signer.h>
#include <xmss_bridge.h>
#include <xmss_leaf_key.h>
#include <xmss_miner_state.h>
#include <xmss_tree_ledger.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

// Activation height chosen relative to TestChain100Setup's fixed 100-block
// setup chain (tip height 100 after construction): height 101 is used to
// fund the P2XMSS output (spend-leaf check not active yet, doesn't matter
// either way since that block has no XMSS spend), height 102 is where the
// actual XMSS spend is connected, with the check active for it.
static constexpr int ACTIVATION_HEIGHT = 102;

struct XMSSLeafDedupIntegrationSetup : public TestChain100Setup {
    XMSSLeafDedupIntegrationSetup()
        : TestChain100Setup(ChainType::REGTEST, {"-testactivationheight=xmssspendleafreuse@102"}) {}
};

BOOST_FIXTURE_TEST_SUITE(xmss_leaf_dedup_integration_tests, XMSSLeafDedupIntegrationSetup)

BOOST_AUTO_TEST_CASE(spend_leaf_marks_on_connect_unmarks_on_disconnect_and_is_reusable_after)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);

    // 1) A spend key this test fully controls -- real tree, real WOTS+/XMSS
    // material, multi-use ("imported"-style, not the wallet one-time-use
    // ledger path) so CXMSSSigner will happily sign more than once if this
    // test needs it to.
    PoUWv2::XMSSMinerState mstate;
    BOOST_REQUIRE(PoUWv2::BuildNewTree(mstate));
    // Imported (non-wallet-native) keys are refused by SignXMSS() unless
    // ledger-backed -- see AddXMSSKey()'s `imported` flag and
    // xmss_signer_tests.cpp's imported_key_multi_use_unaffected, which this
    // mirrors -- so this must happen before AddXMSSKey().
    BOOST_REQUIRE(PoUWv2::XMSSTreeLedgerInit(gArgs.GetDataDirNet(), mstate));
    XMSS::CXMSSKey xkey;
    BOOST_REQUIRE(xkey.Load(mstate.sk));
    std::vector<uint8_t> pubkey = xkey.GetPubKey();
    BOOST_REQUIRE_EQUAL(pubkey.size(), 64U);

    CXMSSSigner signer;
    BOOST_REQUIRE(signer.AddXMSSKey(pubkey, mstate.sk));
    CScript p2xmss = GetXMSSScriptForPubkey(pubkey);
    BOOST_REQUIRE(!p2xmss.empty());

    // 2) Fund the P2XMSS output: a normal ECDSA-signed spend of a mature
    // coinbase (m_coinbase_txns[0]), paying into p2xmss. Mined at height
    // 101 -- below ACTIVATION_HEIGHT, so the spend-leaf check isn't even
    // consulted for this block regardless of its content.
    auto [funding_tx, fee] = CreateValidTransaction(
        {m_coinbase_txns[0]},
        {COutPoint(m_coinbase_txns[0]->GetHash(), 0)},
        /*input_height=*/1,
        {coinbaseKey},
        {CTxOut(49 * COIN, p2xmss)},
        std::nullopt, std::nullopt);
    CBlock fund_block = CreateAndProcessBlock({funding_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(chainman.ActiveChain().Tip()->nHeight, 101);
        BOOST_REQUIRE(chainman.ActiveChain().Tip()->GetBlockHash() == fund_block.GetHash());
    }

    // 3) Build the real spend: sign via the production SignStep path
    // (script/sign.cpp's CreateXMSSSig), which computes the real sighash_v2
    // (leaf_index + chain_id bound in) and chunks the real WOTS+/XMSS
    // signature into <=520-byte scriptSig pushes -- not the mocked
    // BaseSignatureChecker used in xmss_leaf_capture_tests.cpp.
    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint(funding_tx.GetHash(), 0), CScript(), MAX_BIP125_RBF_SEQUENCE);
    spend_tx.vout.emplace_back(48 * COIN, CScript() << OP_TRUE);

    std::map<COutPoint, Coin> input_coins;
    input_coins.emplace(COutPoint(funding_tx.GetHash(), 0),
                        Coin(CTxOut(49 * COIN, p2xmss), /*nHeightIn=*/101, /*fCoinBaseIn=*/false));
    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE(SignTransaction(spend_tx, &signer, input_coins, SIGHASH_ALL, input_errors));

    // Sanity: this is genuinely leaf 0 of a fresh key -- the very case the
    // structural capture fix (a50707e) exists for, now driven through a
    // real CheckInputScripts/ConnectBlock instead of a mock.
    BOOST_REQUIRE_EQUAL(signer.GetLeafIndex(pubkey), 1U); // advanced past leaf 0 after signing
    uint256 leaf_key = MakePoUWLeafKey(pubkey, 0);

    // 4) Connect at height 102 -- ACTIVATION_HEIGHT, spend-leaf check active.
    CBlock spend_block = CreateAndProcessBlock({spend_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    uint256 spend_block_hash = spend_block.GetHash();
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(chainman.ActiveChain().Tip()->nHeight, ACTIVATION_HEIGHT);
        BOOST_REQUIRE(chainman.ActiveChain().Tip()->GetBlockHash() == spend_block_hash);
    }

    // 5) DB_POUW_LEAF must now be marked, pointing at this block; and
    // DB_POUW_LEAF_LIST for this block must record exactly that one key --
    // proving both halves of the ConnectBlock tail (a50707e) actually ran
    // for a real, non-mocked script evaluation.
    {
        LOCK(::cs_main);
        uint256 marked_by;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF, leaf_key), marked_by));
        BOOST_CHECK(marked_by == spend_block_hash);

        std::vector<uint256> leaf_list;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF_LIST, spend_block_hash), leaf_list));
        BOOST_REQUIRE_EQUAL(leaf_list.size(), 1U);
        BOOST_CHECK(leaf_list[0] == leaf_key);
    }

    // 6) Disconnect (reorg simulation): DB_POUW_LEAF_LIST-driven unmark
    // (a50707e's answer to "DisconnectBlock can't re-run the interpreter")
    // must erase both the leaf mark and the list entry itself.
    {
        BlockValidationState invalidate_state;
        chainman.ActiveChainstate().InvalidateBlock(invalidate_state, chainman.m_blockman.LookupBlockIndex(spend_block_hash));
    }
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(chainman.ActiveChain().Tip()->nHeight, 101);

        uint256 marked_by;
        BOOST_CHECK(!chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF, leaf_key), marked_by));
        std::vector<uint256> leaf_list;
        BOOST_CHECK(!chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF_LIST, spend_block_hash), leaf_list));
    }

    // 7) Round-trip proof, not just "the DB rows are gone": re-mine the
    // *exact same* spend_tx (same leaf-0 signature) into a brand new block
    // on top of the now-101 tip. The funding UTXO is unspent again post-
    // disconnect; if the unmark in step 6 had silently failed (e.g. wrong
    // key, or DisconnectBlock's read-back finding nothing due to a bug),
    // this would incorrectly fail with "xmss-spend-leaf-reuse" even though
    // no other block is on the active chain claiming that leaf anymore.
    CBlock spend_block2 = CreateAndProcessBlock({spend_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(chainman.ActiveChain().Tip()->nHeight, ACTIVATION_HEIGHT);
        BOOST_CHECK(chainman.ActiveChain().Tip()->GetBlockHash() == spend_block2.GetHash());

        uint256 marked_by;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF, leaf_key), marked_by));
        BOOST_CHECK(marked_by == spend_block2.GetHash());
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
