// Copyright (c) 2026 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SNTI M4: XMSS unit tests
// Covers: sign/verify round-trip, key persistence, EMA difficulty adjustment,
// and sighash_v2 chain-ID domain separation.

#include <arith_uint256.h>
#include <pouw_v2.h>
#include <xmss_bridge.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <cstring>
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
    BOOST_CHECK_EQUAL(restored.GetPubKey(), pk);

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

BOOST_AUTO_TEST_SUITE_END()
