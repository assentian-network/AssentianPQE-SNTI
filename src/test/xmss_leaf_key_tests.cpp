// Copyright (c) 2026 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SNTI DRAFT: unit tests for xmss_leaf_key.h -- the consensus-level XMSS
// leaf-reuse dedup helpers used by validation.cpp (gated behind
// nXMSSSpendLeafReuseActivation, currently disabled on every network; see
// draft/xmss-spend-leaf-dedup). Exercises ExtractXMSSLeafUse() against both
// P2XMSS (bare) and P2XMSSHASH scriptSig shapes -- these differ in where the
// pubkey comes from (scriptPubKey vs. scriptSig, see script/sign.cpp
// SignStep()), which is the bug this test suite was written to catch after
// the first draft got it wrong for bare P2XMSS.

#include <hash.h>
#include <script/script.h>
#include <uint256.h>
#include <xmss_bridge.h>
#include <xmss_leaf_key.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

BOOST_AUTO_TEST_SUITE(xmss_leaf_key_tests)

namespace {

// Mirrors script/sign.cpp SignStep()'s XMSS_SIG_CHUNK_SIZE exactly -- tests
// must chunk the same way real signing code does, or they'd only prove
// ExtractXMSSLeafUse() agrees with itself.
constexpr size_t XMSS_SIG_CHUNK_SIZE = 500;

std::vector<std::vector<uint8_t>> ChunkSig(const std::vector<uint8_t>& sig)
{
    std::vector<std::vector<uint8_t>> chunks;
    for (size_t off = 0; off < sig.size(); off += XMSS_SIG_CHUNK_SIZE) {
        size_t len = std::min(XMSS_SIG_CHUNK_SIZE, sig.size() - off);
        chunks.emplace_back(sig.begin() + off, sig.begin() + off + len);
    }
    return chunks;
}

CScript PushAll(const std::vector<std::vector<uint8_t>>& pushes)
{
    CScript s;
    for (const auto& p : pushes) s << p;
    return s;
}

CScript BareP2XMSSScriptPubKey(const std::vector<uint8_t>& pubkey)
{
    return CScript() << pubkey << OP_XMSS_CHECKSIG;
}

CScript P2XMSSHashScriptPubKey(const std::vector<uint8_t>& pubkey)
{
    uint160 hash;
    CHash160().Write(pubkey).Finalize(hash);
    return CScript() << OP_DUP << OP_HASH160 << ToByteVector(hash) << OP_EQUALVERIFY << OP_XMSS_CHECKSIG;
}

// A synthetic "signature" -- not real XMSS crypto, just deterministic bytes
// with a known leaf index in the first 4 bytes -- for tests that only care
// about ExtractXMSSLeafUse()'s parsing/shape logic.
std::vector<uint8_t> FakeSig(uint32_t leaf_idx, size_t total_len)
{
    std::vector<uint8_t> sig(total_len, 0x42);
    sig[0] = (leaf_idx >> 24) & 0xFF;
    sig[1] = (leaf_idx >> 16) & 0xFF;
    sig[2] = (leaf_idx >> 8) & 0xFF;
    sig[3] = leaf_idx & 0xFF;
    return sig;
}

std::vector<uint8_t> FakePubkey(uint8_t fill)
{
    return std::vector<uint8_t>(64, fill);
}

uint32_t LeafIdxFromSig(const std::vector<uint8_t>& sig)
{
    return ((uint32_t)sig[0] << 24) | ((uint32_t)sig[1] << 16) |
           ((uint32_t)sig[2] << 8) | (uint32_t)sig[3];
}

} // namespace

// ── Real XMSS sign/verify round trip ────────────────────────────────────────

BOOST_AUTO_TEST_CASE(extract_roundtrip_bare_p2xmss_real_signature)
{
    XMSS::CXMSSKey key;
    BOOST_REQUIRE(key.Generate());
    std::vector<uint8_t> pubkey = key.GetPubKey();

    std::vector<uint8_t> hash(32, 0xAB);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    BOOST_REQUIRE(sig.size() >= 4);

    CScript scriptPubKey = BareP2XMSSScriptPubKey(pubkey);
    CScript scriptSig = PushAll(ChunkSig(sig));

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_REQUIRE(ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
    BOOST_CHECK(pk_out == pubkey);
    BOOST_CHECK_EQUAL(leaf_out, LeafIdxFromSig(sig));
}

BOOST_AUTO_TEST_CASE(extract_roundtrip_p2xmsshash_real_signature)
{
    XMSS::CXMSSKey key;
    BOOST_REQUIRE(key.Generate());
    std::vector<uint8_t> pubkey = key.GetPubKey();

    std::vector<uint8_t> hash(32, 0xCD);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));

    CScript scriptPubKey = P2XMSSHashScriptPubKey(pubkey);
    auto chunks = ChunkSig(sig);
    chunks.push_back(pubkey); // P2XMSSHASH: pubkey pushed last, per script/sign.cpp
    CScript scriptSig = PushAll(chunks);

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_REQUIRE(ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
    BOOST_CHECK(pk_out == pubkey);
    BOOST_CHECK_EQUAL(leaf_out, LeafIdxFromSig(sig));
}

// CXMSSKey is stateful -- successive Sign() calls must advance to different
// leaves. Sanity check that extraction reflects a real, changing leaf index
// rather than coincidentally echoing a constant.
BOOST_AUTO_TEST_CASE(extract_leaf_index_advances_across_signatures)
{
    XMSS::CXMSSKey key;
    BOOST_REQUIRE(key.Generate());
    std::vector<uint8_t> pubkey = key.GetPubKey();
    CScript scriptPubKey = BareP2XMSSScriptPubKey(pubkey);

    std::vector<uint8_t> hash1(32, 0x01), hash2(32, 0x02);
    std::vector<uint8_t> sig1, sig2;
    BOOST_REQUIRE(key.Sign(hash1, sig1));
    BOOST_REQUIRE(key.Sign(hash2, sig2));

    std::vector<uint8_t> pk1, pk2;
    uint32_t leaf1, leaf2;
    BOOST_REQUIRE(ExtractXMSSLeafUse(scriptPubKey, PushAll(ChunkSig(sig1)), pk1, leaf1));
    BOOST_REQUIRE(ExtractXMSSLeafUse(scriptPubKey, PushAll(ChunkSig(sig2)), pk2, leaf2));
    BOOST_CHECK(leaf1 != leaf2);
}

// ── Synthetic-signature parsing edge cases (fast, no key generation) ───────

BOOST_AUTO_TEST_CASE(extract_leaf_index_is_big_endian_first_four_bytes)
{
    std::vector<uint8_t> pubkey = FakePubkey(0x11);
    CScript scriptPubKey = BareP2XMSSScriptPubKey(pubkey);

    for (uint32_t leaf : {0u, 1u, 255u, 256u, 1023u, 0xDEADBEEFu}) {
        std::vector<uint8_t> sig = FakeSig(leaf, 600); // 2 chunks: 500 + 100
        CScript scriptSig = PushAll(ChunkSig(sig));

        std::vector<uint8_t> pk_out;
        uint32_t leaf_out;
        BOOST_REQUIRE(ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
        BOOST_CHECK_EQUAL(leaf_out, leaf);
        BOOST_CHECK(pk_out == pubkey);
    }
}

BOOST_AUTO_TEST_CASE(extract_handles_exact_chunk_multiple)
{
    // 1000 bytes = exactly two 500-byte chunks, no short final chunk --
    // guards against an off-by-one in the chunk loop's stop condition.
    std::vector<uint8_t> pubkey = FakePubkey(0x22);
    CScript scriptPubKey = BareP2XMSSScriptPubKey(pubkey);
    std::vector<uint8_t> sig = FakeSig(42, 1000);
    auto chunks = ChunkSig(sig);
    BOOST_REQUIRE_EQUAL(chunks.size(), 2u);
    BOOST_REQUIRE_EQUAL(chunks[0].size(), 500u);
    BOOST_REQUIRE_EQUAL(chunks[1].size(), 500u);

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_REQUIRE(ExtractXMSSLeafUse(scriptPubKey, PushAll(chunks), pk_out, leaf_out));
    BOOST_CHECK_EQUAL(leaf_out, 42u);
}

BOOST_AUTO_TEST_CASE(extract_rejects_non_xmss_scriptpubkey)
{
    // Plain P2PKH-shaped script -- not P2XMSS/P2XMSSHASH -- must be
    // rejected regardless of what's in scriptSig.
    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0x01) << OP_EQUALVERIFY << OP_CHECKSIG;
    CScript scriptSig = PushAll(ChunkSig(FakeSig(7, 600)));

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_CHECK(!ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
}

BOOST_AUTO_TEST_CASE(extract_rejects_empty_scriptsig)
{
    CScript scriptPubKey = BareP2XMSSScriptPubKey(FakePubkey(0x33));
    CScript emptyScriptSig;

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_CHECK(!ExtractXMSSLeafUse(scriptPubKey, emptyScriptSig, pk_out, leaf_out));
}

BOOST_AUTO_TEST_CASE(extract_rejects_non_push_scriptsig)
{
    // A scriptSig that isn't pure pushes doesn't match any shape
    // CheckInputScripts would ever have accepted for OP_XMSS_CHECKSIG, so
    // extraction must refuse it rather than guess.
    CScript scriptPubKey = BareP2XMSSScriptPubKey(FakePubkey(0x44));
    CScript scriptSig;
    scriptSig << std::vector<uint8_t>(500, 0x01) << OP_CHECKSIG;

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_CHECK(!ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
}

BOOST_AUTO_TEST_CASE(extract_rejects_signature_too_short_for_leaf_index)
{
    // Fewer than 4 reassembled bytes can't contain a leaf index.
    CScript scriptPubKey = BareP2XMSSScriptPubKey(FakePubkey(0x55));
    CScript scriptSig;
    scriptSig << std::vector<uint8_t>{0x01, 0x02};

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_CHECK(!ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
}

BOOST_AUTO_TEST_CASE(extract_rejects_wrong_size_pubkey_p2xmsshash)
{
    // P2XMSSHASH scriptSig whose last push isn't 64 bytes is malformed and
    // must be rejected rather than mis-parsed as a pubkey.
    std::vector<uint8_t> realPubkey = FakePubkey(0x66);
    CScript scriptPubKey = P2XMSSHashScriptPubKey(realPubkey);

    CScript scriptSig;
    scriptSig << std::vector<uint8_t>(500, 0x01) << std::vector<uint8_t>(63, 0x02); // 63, not 64

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_CHECK(!ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
}

BOOST_AUTO_TEST_CASE(extract_rejects_oversized_chunk)
{
    // A push >520 bytes can't be a valid chunk (MAX_SCRIPT_ELEMENT_SIZE),
    // so this shape could never have come from real signing code.
    CScript scriptPubKey = BareP2XMSSScriptPubKey(FakePubkey(0x77));
    CScript scriptSig;
    scriptSig << std::vector<uint8_t>(521, 0x01);

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_CHECK(!ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
}

// The bug this test suite exists to catch: the first draft of
// ExtractXMSSLeafUse() assumed the pubkey was always the last scriptSig
// push, which is only true for P2XMSSHASH. For bare P2XMSS the pubkey lives
// in scriptPubKey (see script/sign.cpp SignStep()) and scriptSig is chunks
// only -- treating the last chunk as a 64-byte pubkey silently failed
// extraction for every bare-P2XMSS spend (a real, commonly-used script
// shape -- see same-wallet-node transfers in project notes).
BOOST_AUTO_TEST_CASE(extract_bare_p2xmss_scriptsig_has_no_pubkey_push)
{
    std::vector<uint8_t> pubkey = FakePubkey(0x88);
    CScript scriptPubKey = BareP2XMSSScriptPubKey(pubkey);
    // Signature chunked such that the LAST chunk is exactly 64 bytes --
    // the exact shape that would fool a "last push == pubkey" assumption.
    std::vector<uint8_t> sig = FakeSig(99, 564); // 500 + 64
    auto chunks = ChunkSig(sig);
    BOOST_REQUIRE_EQUAL(chunks.back().size(), 64u);
    CScript scriptSig = PushAll(chunks);

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_REQUIRE(ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));
    BOOST_CHECK(pk_out == pubkey); // must come from scriptPubKey, not the 64-byte last chunk
    BOOST_CHECK_EQUAL(leaf_out, 99u);
}

// ── MakePoUWLeafKey() properties ────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(leaf_key_deterministic)
{
    std::vector<uint8_t> pk = FakePubkey(0x99);
    BOOST_CHECK(MakePoUWLeafKey(pk, 5) == MakePoUWLeafKey(pk, 5));
}

BOOST_AUTO_TEST_CASE(leaf_key_differs_by_leaf_index)
{
    std::vector<uint8_t> pk = FakePubkey(0xAA);
    BOOST_CHECK(MakePoUWLeafKey(pk, 5) != MakePoUWLeafKey(pk, 6));
}

BOOST_AUTO_TEST_CASE(leaf_key_differs_by_pubkey)
{
    uint32_t leaf = 5;
    BOOST_CHECK(MakePoUWLeafKey(FakePubkey(0xBB), leaf) != MakePoUWLeafKey(FakePubkey(0xCC), leaf));
}

BOOST_AUTO_TEST_SUITE_END()
