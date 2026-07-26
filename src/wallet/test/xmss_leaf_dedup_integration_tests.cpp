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

#include <algorithm>

#include <arith_uint256.h>
#include <chainparams.h>
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

// SNTI DRAFT: test-only SigningProvider that signs directly off a raw XMSS
// SK copy via CXMSSKey::Sign(), completely bypassing xmss_tree_ledger.h's
// XMSSTreeLedgerClaimAndSign() -- i.e. every production signing path
// (CXMSSSigner::SignXMSS, mining.cpp's GenerateBlock()) is deliberately not
// used here. This stands in for the threat model the consensus-level dedup
// exists for (see xmss_spend_leaf_dedup_bypass_gap memory): an attacker who
// already holds raw WOTS+/XMSS seed material for a leaf signs a second,
// different message at that same leaf without going through -- and without
// being stopped by -- the local unified ledger that every honest caller in
// this codebase is routed through. Always signs at leaf 0 with the fixed
// regtest chain ID, matching the one-shot fresh tree this test builds.
class BypassLedgerXMSSProvider : public SigningProvider
{
public:
    explicit BypassLedgerXMSSProvider(std::vector<uint8_t> sk) : m_sk(std::move(sk)) {}

    bool SignXMSS(const uint256& hash, const std::vector<uint8_t>& pubkey, std::vector<uint8_t>& sig) const override
    {
        XMSS::CXMSSKey key;
        if (!key.Load(m_sk)) return false;
        std::vector<uint8_t> hash_vec(hash.begin(), hash.end());
        return key.Sign(hash_vec, sig);
    }
    uint32_t GetXMSSLeafIndex(const std::vector<uint8_t>& pubkey) const override { return 0; }
    uint32_t GetXMSSChainId() const override { return Params().GetConsensus().nXMSSChainId; }

private:
    std::vector<uint8_t> m_sk;
};

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

// SNTI DRAFT: the same-block coinbase-mining-leaf-vs-spend-leaf collision
// case explicitly left as a follow-up by the skeleton test above (see the
// file-level comment) and by xmss_spend_leaf_dedup_bypass_gap memory's "NEXT"
// entry. Proves the seen_this_block seeding in ConnectBlock (a50707e, see
// validation.cpp around ParseCoinbasePoUWLeaf/MakePoUWLeafKey) actually
// rejects a block whose own coinbase PoUW proof and a spend transaction in
// the SAME block claim the same (pubkey, leaf) pair -- not just reuse
// detected across separate blocks (already covered above).
BOOST_AUTO_TEST_CASE(coinbase_and_spend_leaf_collision_in_same_block_is_rejected)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path datadir = gArgs.GetDataDirNet();

    // 1) Build a tree this test fully controls, retrying until its root
    // clears the mining target -- regtest sets fPowNoRetargeting with
    // powLimit ~= half of the max 256-bit value (see kernel/chainparams.cpp),
    // so nBits is constant for the whole chain and roughly half of freshly
    // built trees pass on the first attempt.
    PoUWv2::XMSSMinerState coinbase_tree;
    const arith_uint256 target = UintToArith256(chainman.GetParams().GetConsensus().powLimit);
    for (int attempt = 0;; ++attempt) {
        BOOST_REQUIRE_MESSAGE(attempt < 50, "50 freshly built trees in a row all failed the (constant, ~50%-pass) regtest PoUW target -- something is wrong beyond bad luck");
        BOOST_REQUIRE(PoUWv2::BuildNewTree(coinbase_tree));
        if (UintToArith256(coinbase_tree.xmssRoot) <= target) break;
    }

    // Independent copy of the fresh (leaf-0) SK material, taken before this
    // tree is ever registered with the unified ledger below -- see
    // BypassLedgerXMSSProvider's comment for why this stands in for an
    // attacker with raw key material rather than a ledger-mediated signer.
    const std::vector<uint8_t> attacker_sk = coinbase_tree.sk;

    XMSS::CXMSSKey pk_reader;
    BOOST_REQUIRE(pk_reader.Load(attacker_sk));
    std::vector<uint8_t> pubkey = pk_reader.GetPubKey();
    BOOST_REQUIRE_EQUAL(pubkey.size(), 64U);
    CScript p2xmss = GetXMSSScriptForPubkey(pubkey);
    BOOST_REQUIRE(!p2xmss.empty());

    // 2) Fund a P2XMSS output for this pubkey at height 101, below
    // ACTIVATION_HEIGHT and using whichever tree TestChain100Setup's own
    // 100-block chain is already mining with -- coinbase_tree is not
    // registered with the datadir yet, so this block cannot touch it.
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

    // 3) NOW register coinbase_tree as the datadir's active mining tree --
    // GenerateBlock() (rpc/mining.cpp) will Load() this exact state on the
    // very next block it mines and claim its leaf 0 for the coinbase PoUW
    // proof, since nothing has claimed from it yet.
    {
        PoUWv2::XMSSMinerStateManager state_mgr(datadir);
        BOOST_REQUIRE(state_mgr.Save(coinbase_tree));
        BOOST_REQUIRE(PoUWv2::XMSSTreeLedgerInit(datadir, coinbase_tree));
    }

    // 4) Independently sign a spend of the funding UTXO at leaf 0 of the
    // SAME tree/pubkey the coinbase above is about to claim -- via the raw,
    // ledger-bypassing provider, exactly the signature an attacker holding
    // this leaf's raw key material could produce without the coinbase
    // mining side ever knowing. Real sighash_v2 (leaf_index + chain_id) and
    // real chunking through the production SignStep/CreateXMSSSig path.
    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint(funding_tx.GetHash(), 0), CScript(), MAX_BIP125_RBF_SEQUENCE);
    spend_tx.vout.emplace_back(48 * COIN, CScript() << OP_TRUE);

    std::map<COutPoint, Coin> input_coins;
    input_coins.emplace(COutPoint(funding_tx.GetHash(), 0),
                        Coin(CTxOut(49 * COIN, p2xmss), /*nHeightIn=*/101, /*fCoinBaseIn=*/false));
    std::map<int, bilingual_str> input_errors;
    BypassLedgerXMSSProvider attacker_provider(attacker_sk);
    BOOST_REQUIRE(SignTransaction(spend_tx, &attacker_provider, input_coins, SIGHASH_ALL, input_errors));

    uint256 leaf_key = MakePoUWLeafKey(pubkey, 0);

    // 5) Mine height 102 (ACTIVATION_HEIGHT) with this spend included.
    // GenerateBlock() claims coinbase_tree's leaf 0 for the block's own
    // coinbase PoUW proof -- the exact same (pubkey, leaf) pair spend_tx's
    // signature already commits to. CreateAndProcessBlock() does not assert
    // ProcessNewBlock()'s result (see CreateBlock()'s comment on the
    // pre-69b7a84 bug this differs from), so an invalid block here is
    // silently not connected rather than crashing the test -- checked below.
    CBlock collide_block = CreateAndProcessBlock({spend_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    // 6) Must be rejected: tip stays at the funding block (height 101), and
    // DB_POUW_LEAF has no entry for the colliding key -- ConnectBlock's
    // writes are gated behind the whole function succeeding, so a rejected
    // block must leave nothing behind, not even the coinbase's own claim.
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman.ActiveChain().Tip()->nHeight, 101);
        BOOST_CHECK(chainman.ActiveChain().Tip()->GetBlockHash() == fund_block.GetHash());
        BOOST_CHECK(chainman.ActiveChain().Tip()->GetBlockHash() != collide_block.GetHash());

        uint256 marked_by;
        BOOST_CHECK(!chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF, leaf_key), marked_by));
    }
}

// SNTI DRAFT: reorg *stress* test, requested as a follow-up to the single
// connect/disconnect/reconnect round trip above -- that test proves the
// mark/unmark path works once; this one proves it doesn't accumulate stale
// state across repeated cycles. Each round mines a brand-new block (distinct
// hash, since CreateAndProcessBlock() re-derives a fresh PoUW proof/coinbase
// each call even for byte-identical spend_tx content) claiming the exact
// same (pubkey, leaf 0) pair, then immediately disconnects it via
// InvalidateBlock(), repeated several times. Two things a single round trip
// can't catch but repetition can: (1) a DB_POUW_LEAF_LIST entry keyed by a
// *previous* round's block hash silently surviving disconnect and leaking
// into a later round's collision check; (2) any accumulation in the current
// round's own list (e.g. an off-by-one that appends instead of overwriting)
// that would only show up as leaf_list.size() > 1 after enough rounds.
BOOST_AUTO_TEST_CASE(spend_leaf_survives_repeated_reorg_cycles)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);

    // 1) Same setup shape as the single-round-trip test above: one spend key
    // this test fully controls, multi-use ("imported"-style) so signing more
    // than once across rounds is allowed.
    PoUWv2::XMSSMinerState mstate;
    BOOST_REQUIRE(PoUWv2::BuildNewTree(mstate));
    BOOST_REQUIRE(PoUWv2::XMSSTreeLedgerInit(gArgs.GetDataDirNet(), mstate));
    XMSS::CXMSSKey xkey;
    BOOST_REQUIRE(xkey.Load(mstate.sk));
    std::vector<uint8_t> pubkey = xkey.GetPubKey();
    BOOST_REQUIRE_EQUAL(pubkey.size(), 64U);

    CXMSSSigner signer;
    BOOST_REQUIRE(signer.AddXMSSKey(pubkey, mstate.sk));
    CScript p2xmss = GetXMSSScriptForPubkey(pubkey);
    BOOST_REQUIRE(!p2xmss.empty());

    // 2) Fund the P2XMSS output at height 101, below ACTIVATION_HEIGHT.
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

    // 3) Sign leaf 0 once -- the same signed spend_tx is re-mined into a
    // fresh block every round below. Signing again per round is deliberately
    // avoided: this test targets DisconnectBlock/ConnectBlock's DB
    // bookkeeping, not CXMSSSigner's leaf-advancement bookkeeping (already
    // covered by xmss_signer_tests.cpp).
    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint(funding_tx.GetHash(), 0), CScript(), MAX_BIP125_RBF_SEQUENCE);
    spend_tx.vout.emplace_back(48 * COIN, CScript() << OP_TRUE);

    std::map<COutPoint, Coin> input_coins;
    input_coins.emplace(COutPoint(funding_tx.GetHash(), 0),
                        Coin(CTxOut(49 * COIN, p2xmss), /*nHeightIn=*/101, /*fCoinBaseIn=*/false));
    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE(SignTransaction(spend_tx, &signer, input_coins, SIGHASH_ALL, input_errors));

    uint256 leaf_key = MakePoUWLeafKey(pubkey, 0);
    constexpr int NUM_ROUNDS = 4;
    std::vector<uint256> prior_block_hashes;

    for (int round = 0; round < NUM_ROUNDS; ++round) {
        // Connect at height 102: fresh block, same spend_tx/leaf every round.
        CBlock spend_block = CreateAndProcessBlock({spend_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        uint256 spend_block_hash = spend_block.GetHash();
        {
            LOCK(::cs_main);
            BOOST_REQUIRE_EQUAL(chainman.ActiveChain().Tip()->nHeight, ACTIVATION_HEIGHT);
            BOOST_REQUIRE(chainman.ActiveChain().Tip()->GetBlockHash() == spend_block_hash);
        }
        // Each round must mine a genuinely distinct block -- if a round ever
        // collided with a previous round's hash, the checks below would be
        // vacuously trivially true rather than actually re-exercising the
        // mark/unmark path.
        BOOST_REQUIRE(std::find(prior_block_hashes.begin(), prior_block_hashes.end(), spend_block_hash) == prior_block_hashes.end());
        prior_block_hashes.push_back(spend_block_hash);

        // DB_POUW_LEAF must point at *this* round's block hash, and this
        // round's own DB_POUW_LEAF_LIST entry must contain exactly one leaf
        // -- not accumulated leftovers from any earlier round.
        {
            LOCK(::cs_main);
            uint256 marked_by;
            BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF, leaf_key), marked_by));
            BOOST_CHECK_MESSAGE(marked_by == spend_block_hash, "round " << round << ": DB_POUW_LEAF points at a stale block hash");

            std::vector<uint256> leaf_list;
            BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF_LIST, spend_block_hash), leaf_list));
            BOOST_REQUIRE_MESSAGE(leaf_list.size() == 1U, "round " << round << ": DB_POUW_LEAF_LIST accumulated " << leaf_list.size() << " entries instead of 1");
            BOOST_CHECK(leaf_list[0] == leaf_key);
        }

        // Disconnect (reorg simulation) back to the funding-only tip.
        {
            BlockValidationState invalidate_state;
            chainman.ActiveChainstate().InvalidateBlock(invalidate_state, chainman.m_blockman.LookupBlockIndex(spend_block_hash));
        }
        {
            LOCK(::cs_main);
            BOOST_REQUIRE_EQUAL(chainman.ActiveChain().Tip()->nHeight, 101);

            // The leaf itself must be fully unmarked -- reusable again next
            // round, exactly like the single-round-trip test's step 6/7.
            uint256 marked_by;
            BOOST_CHECK_MESSAGE(!chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF, leaf_key), marked_by),
                                 "round " << round << ": leaf still marked after disconnect");

            // This round's own list entry must be gone too...
            std::vector<uint256> leaf_list;
            BOOST_CHECK_MESSAGE(!chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF_LIST, spend_block_hash), leaf_list),
                                 "round " << round << ": DB_POUW_LEAF_LIST entry for this round's block hash survived disconnect");

            // ...and so must every *previous* round's, keyed by their own
            // (necessarily different) block hashes -- the leak this whole
            // test exists to catch: an old round's list entry silently
            // surviving because unmark only ever looked at the current tip's
            // block hash instead of the specific hash passed to
            // DisconnectBlock.
            for (const uint256& old_hash : prior_block_hashes) {
                std::vector<uint256> old_leaf_list;
                BOOST_CHECK_MESSAGE(!chainman.m_blockman.m_block_tree_db->Read(std::make_pair(DB_POUW_LEAF_LIST, old_hash), old_leaf_list),
                                     "round " << round << ": a prior round's DB_POUW_LEAF_LIST entry (block " << old_hash.ToString() << ") is still present");
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
