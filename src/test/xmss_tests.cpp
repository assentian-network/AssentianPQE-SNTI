// Copyright (c) 2026 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SNTI M4: XMSS unit tests
// Covers: sign/verify round-trip, key persistence, EMA difficulty adjustment,
// and sighash_v2 chain-ID domain separation.

#include <arith_uint256.h>
#include <pouw_v2.h>
#include <xmss_bridge.h>
#include <xmss_miner_state.h>
#include <xmss_tree_ledger.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

BOOST_AUTO_TEST_SUITE(xmss_tests)

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::vector<uint8_t> FakeHash(uint8_t fill = 0xAB)
{
    return std::vector<uint8_t>(32, fill);
}

// ── EMA difficulty tests (no key generation required, fast) ──────────────────

BOOST_AUTO_TEST_CASE(ema_on_target)
{
    // When actual_spacing == target_spacing, new_target == old_target.
    // Formula: new = old * (900*T + 100*T) / (1000*T) = old * 1000/1000 = old
    arith_uint256 old_target;
    old_target.SetCompact(0x1d00ffff); // typical regtest/testnet difficulty
    const arith_uint256 pow_limit = old_target << 4;
    int64_t T = 60;

    arith_uint256 new_target = PoUWv2::CalcNextTargetEMA(old_target, T, T, pow_limit);
    BOOST_CHECK_EQUAL(new_target.GetCompact(), old_target.GetCompact());
}

BOOST_AUTO_TEST_CASE(ema_blocks_fast)
{
    // When blocks arrive faster than target (actual_spacing < target),
    // new_target < old_target (difficulty increases).
    arith_uint256 old_target;
    old_target.SetCompact(0x1d00ffff);
    const arith_uint256 pow_limit = old_target << 4;
    int64_t T = 60;
    int64_t A = 10; // very fast block

    arith_uint256 new_target = PoUWv2::CalcNextTargetEMA(old_target, A, T, pow_limit);
    BOOST_CHECK(new_target < old_target);
}

BOOST_AUTO_TEST_CASE(ema_blocks_slow)
{
    // When blocks arrive slower, difficulty drops (new_target > old_target).
    arith_uint256 old_target;
    old_target.SetCompact(0x1d00ffff);
    const arith_uint256 pow_limit = old_target << 4;
    int64_t T = 60;
    int64_t A = 200; // slow block

    arith_uint256 new_target = PoUWv2::CalcNextTargetEMA(old_target, A, T, pow_limit);
    BOOST_CHECK(new_target > old_target);
}

BOOST_AUTO_TEST_CASE(ema_clamp_lower)
{
    // Actual spacing clamped to T/4 — max difficulty increase per block.
    arith_uint256 old_target;
    old_target.SetCompact(0x1d00ffff);
    const arith_uint256 pow_limit = old_target << 4;
    int64_t T = 60;

    // actual=0 and actual=T/4 should produce the same new_target.
    arith_uint256 t0 = PoUWv2::CalcNextTargetEMA(old_target, 0,   T, pow_limit);
    arith_uint256 t1 = PoUWv2::CalcNextTargetEMA(old_target, T/4, T, pow_limit);
    BOOST_CHECK_EQUAL(t0.GetCompact(), t1.GetCompact());
}

BOOST_AUTO_TEST_CASE(ema_clamp_upper)
{
    // Actual spacing clamped to T*4 — max difficulty drop per block.
    arith_uint256 old_target;
    old_target.SetCompact(0x1d00ffff);
    const arith_uint256 pow_limit = old_target << 4;
    int64_t T = 60;

    arith_uint256 t4x  = PoUWv2::CalcNextTargetEMA(old_target, T*4,   T, pow_limit);
    arith_uint256 t10x = PoUWv2::CalcNextTargetEMA(old_target, T*10,  T, pow_limit);
    BOOST_CHECK_EQUAL(t4x.GetCompact(), t10x.GetCompact());
}

BOOST_AUTO_TEST_CASE(ema_never_exceeds_pow_limit)
{
    // Even at maximum slowdown starting near the limit, stays within pow_limit.
    arith_uint256 pow_limit;
    pow_limit.SetCompact(0x1d00ffff);
    arith_uint256 old_target = pow_limit - 1;
    int64_t T = 60;

    arith_uint256 new_target = PoUWv2::CalcNextTargetEMA(old_target, T*4, T, pow_limit);
    BOOST_CHECK(new_target <= pow_limit);
}

// ── XMSS key sign/verify tests (slow — require tree generation) ───────────────

BOOST_AUTO_TEST_CASE(xmss_generate_and_verify)
{
    XMSS::CXMSSKey key;
    BOOST_REQUIRE(key.Generate());
    BOOST_REQUIRE(key.IsValid());

    std::vector<uint8_t> pk = key.GetPubKey();
    BOOST_REQUIRE_EQUAL(pk.size(), 64U);

    std::vector<uint8_t> hash = FakeHash(0x01);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    BOOST_CHECK(!sig.empty());

    // Verify against the correct public key.
    XMSS::CXMSSKey verifier;
    BOOST_CHECK(verifier.Verify(hash, sig, pk));
}

BOOST_AUTO_TEST_CASE(xmss_wrong_message_rejected)
{
    XMSS::CXMSSKey key;
    BOOST_REQUIRE(key.Generate());
    std::vector<uint8_t> pk = key.GetPubKey();

    std::vector<uint8_t> hash1 = FakeHash(0x01);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(key.Sign(hash1, sig));

    // Different message — same sig must fail.
    std::vector<uint8_t> hash2 = FakeHash(0x02);
    XMSS::CXMSSKey verifier;
    BOOST_CHECK(!verifier.Verify(hash2, sig, pk));
}

BOOST_AUTO_TEST_CASE(xmss_wrong_pubkey_rejected)
{
    XMSS::CXMSSKey key1;
    BOOST_REQUIRE(key1.Generate());
    XMSS::CXMSSKey key2;
    BOOST_REQUIRE(key2.Generate());

    std::vector<uint8_t> pk2 = key2.GetPubKey();
    std::vector<uint8_t> hash = FakeHash(0x03);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(key1.Sign(hash, sig));

    // Verify key1's sig against key2's pk — must fail.
    XMSS::CXMSSKey verifier;
    BOOST_CHECK(!verifier.Verify(hash, sig, pk2));
}

// ── Unified tree ledger: ownership-stamp cross-datadir protection (KRITIS #6) ──

// Joins path segments by building one plain string first, sidestepping the
// ambiguous operator/(fs::path, fs::path) overload resolution between
// std::filesystem's own hidden-friend operator and util/fs.h's version.
static fs::path JoinPath(const fs::path& base, const std::string& child)
{
    return fs::PathFromString(fs::PathToString(base) + "/" + child);
}

BOOST_AUTO_TEST_CASE(ledger_same_datadir_roundtrip_unaffected)
{
    // Sanity check: the new ownership-stamp logic must not break the normal,
    // single-datadir case that already worked before this fix.
    fs::path dir = JoinPath(fs::temp_directory_path(), "snti_ledger_test_same");
    fs::remove_all(dir);
    fs::create_directories(dir);

    PoUWv2::XMSSMinerState state;
    BOOST_REQUIRE(PoUWv2::BuildNewTree(state));
    BOOST_REQUIRE(PoUWv2::XMSSTreeLedgerInit(dir, state));

    std::vector<uint8_t> hash(32, 0xAB), sig;
    uint32_t leaf_used = 999;
    BOOST_CHECK(PoUWv2::XMSSTreeLedgerClaimAndSign(dir, state.xmssRoot, hash, sig, leaf_used));
    BOOST_CHECK_EQUAL(leaf_used, 0U);

    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(ledger_cross_datadir_stamp_mismatch_refused)
{
    // Reproduces the actual July 1 bug pattern one level up: a tree's ledger
    // file gets copied to a SECOND datadir (backup restore, VPS migration
    // where the original was never shut down, etc.) without the original
    // being retired. The second datadir must refuse to sign until the
    // operator explicitly overrides.
    fs::path dirA = JoinPath(fs::temp_directory_path(), "snti_ledger_test_A");
    fs::path dirB = JoinPath(fs::temp_directory_path(), "snti_ledger_test_B");
    fs::remove_all(dirA);
    fs::remove_all(dirB);
    fs::create_directories(dirA);
    fs::create_directories(dirB);

    PoUWv2::XMSSMinerState state;
    BOOST_REQUIRE(PoUWv2::BuildNewTree(state));
    BOOST_REQUIRE(PoUWv2::XMSSTreeLedgerInit(dirA, state)); // stamped with dirA's instance id

    // Copy just the ledger .dat file into dirB, which has its OWN, different
    // instance id -- simulates the accidental-copy scenario.
    std::string ledgerName = state.xmssRoot.GetHex() + ".dat";
    fs::path treesB = JoinPath(dirB, "xmss_trees");
    fs::create_directories(treesB);
    fs::copy_file(JoinPath(JoinPath(dirA, "xmss_trees"), ledgerName), JoinPath(treesB, ledgerName), fs::copy_options::none);

    std::vector<uint8_t> hash(32, 0xCD), sig;
    uint32_t leaf_used = 999;
    BOOST_CHECK(!PoUWv2::XMSSTreeLedgerClaimAndSign(dirB, state.xmssRoot, hash, sig, leaf_used));

    // Explicit operator override: acknowledge the risk, let dirB take over.
    fs::path sentinel = JoinPath(treesB, state.xmssRoot.GetHex() + ".forceclaim");
    { std::ofstream f(fs::PathToString(sentinel)); }
    BOOST_REQUIRE(fs::exists(sentinel));
    BOOST_CHECK(PoUWv2::XMSSTreeLedgerClaimAndSign(dirB, state.xmssRoot, hash, sig, leaf_used));
    BOOST_CHECK_EQUAL(leaf_used, 0U);

    // One-shot: the override file must be consumed, not reusable.
    BOOST_CHECK(!fs::exists(sentinel));

    fs::remove_all(dirA);
    fs::remove_all(dirB);
}

BOOST_AUTO_TEST_CASE(xmss_key_persistence)
{
    // Round-trip: Generate → GetPrivKey → Load → Sign → Verify
    std::vector<uint8_t> saved_sk;
    std::vector<uint8_t> pk;
    {
        XMSS::CXMSSKey key;
        BOOST_REQUIRE(key.Generate());
        pk = key.GetPubKey();
        saved_sk = key.GetPrivKey();
        BOOST_CHECK(!saved_sk.empty());
    }

    // Reload and sign.
    XMSS::CXMSSKey restored;
    BOOST_REQUIRE(restored.Load(saved_sk));
    BOOST_REQUIRE(restored.IsValid());
    bool pubkey_preserved = (restored.GetPubKey() == pk);
    BOOST_CHECK(pubkey_preserved);

    std::vector<uint8_t> hash = FakeHash(0x04);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(restored.Sign(hash, sig));

    XMSS::CXMSSKey verifier;
    BOOST_CHECK(verifier.Verify(hash, sig, pk));
}

BOOST_AUTO_TEST_CASE(xmss_corrupted_sig_rejected)
{
    XMSS::CXMSSKey key;
    BOOST_REQUIRE(key.Generate());
    std::vector<uint8_t> pk = key.GetPubKey();

    std::vector<uint8_t> hash = FakeHash(0x05);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    BOOST_REQUIRE(!sig.empty());

    // Flip a byte in the middle of the signature.
    sig[sig.size() / 2] ^= 0xFF;

    XMSS::CXMSSKey verifier;
    BOOST_CHECK(!verifier.Verify(hash, sig, pk));
}

// Audit T-1: FSL entries claim a (sk_seed, xmss_root) pair. Consensus must
// rebuild the root from the seed and confirm it matches — otherwise a miner
// could submit an arbitrary root with no real seed behind it.
BOOST_AUTO_TEST_CASE(xmss_fsl_seed_root_matches)
{
    XMSS::CXMSSKey key;
    BOOST_REQUIRE(key.Generate());

    std::vector<uint8_t> pk = key.GetPubKey(); // [root(32) | PUB_SEED(32)]
    std::vector<uint8_t> expected_root(pk.begin(), pk.begin() + 32);

    std::vector<uint8_t> sk = key.GetPrivKey(); // [OID(4)|idx(4)|SK_SEED(32)|SK_PRF(32)|root(32)|PUB_SEED(32)|BDS...]
    BOOST_REQUIRE(sk.size() >= 136);
    std::vector<uint8_t> seed96;
    seed96.insert(seed96.end(), sk.begin() + 8, sk.begin() + 72);    // SK_SEED + SK_PRF
    seed96.insert(seed96.end(), sk.begin() + 104, sk.begin() + 136); // PUB_SEED
    BOOST_REQUIRE_EQUAL(seed96.size(), 96U);

    std::vector<uint8_t> rebuilt_root;
    BOOST_REQUIRE(XMSS::ComputeRootFromSeed(seed96, rebuilt_root));
    bool roots_match = (rebuilt_root == expected_root);
    BOOST_CHECK(roots_match);
}

BOOST_AUTO_TEST_CASE(xmss_fsl_tampered_seed_mismatch_detected)
{
    XMSS::CXMSSKey key;
    BOOST_REQUIRE(key.Generate());

    std::vector<uint8_t> pk = key.GetPubKey();
    std::vector<uint8_t> claimed_root(pk.begin(), pk.begin() + 32);

    std::vector<uint8_t> sk = key.GetPrivKey();
    std::vector<uint8_t> seed96;
    seed96.insert(seed96.end(), sk.begin() + 8, sk.begin() + 72);
    seed96.insert(seed96.end(), sk.begin() + 104, sk.begin() + 136);

    // Simulate a dishonest miner: flip a byte of SK_SEED so the seed no
    // longer produces the claimed root (e.g. attacker made up a root).
    seed96[0] ^= 0xFF;

    std::vector<uint8_t> rebuilt_root;
    BOOST_REQUIRE(XMSS::ComputeRootFromSeed(seed96, rebuilt_root));
    // This is exactly the mismatch validation.cpp's pouw-fsl-seed-mismatch
    // check must catch — rebuilt root must NOT equal the claimed root.
    bool roots_mismatch = (rebuilt_root != claimed_root);
    BOOST_CHECK(roots_mismatch);
}

BOOST_AUTO_TEST_SUITE_END()
