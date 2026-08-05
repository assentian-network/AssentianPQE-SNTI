// Copyright (c) 2026 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SNTI DRAFT: unit tests for the structural XMSS leaf-use capture mechanism
// (ScriptExecutionData::m_xmss_leaf_uses, populated in interpreter.cpp's
// OP_XMSS_CHECKSIG(VERIFY) case, surfaced via VerifyScriptXMSSCapture() in
// interpreter.h/.cpp). This is the fix for the bypass gap found reviewing
// draft/xmss-spend-leaf-dedup: the OLD detection (ExtractXMSSLeafUse(), see
// xmss_leaf_key_tests.cpp) only recognizes the two Solver()-template shapes
// (P2XMSS/P2XMSSHASH), so a script that reaches OP_XMSS_CHECKSIG through any
// OTHER shape passed undetected even though the signature check itself
// succeeded. The tests below use a mock BaseSignatureChecker (real XMSS
// crypto is already covered by xmss_leaf_key_tests.cpp's round-trip tests;
// what's under test here is purely the interpreter-level wiring) to prove:
// capture fires for non-template scripts where the old static extraction
// does not, capture never fires on a failed check (false-positive-DoS
// guard, see job_queue memory), and multiple checks in one script all
// accumulate rather than overwrite.
//
// NOT covered here (needs a full chainstate/ConnectBlock fixture, deferred
// -- see xmss_spend_leaf_dedup_bypass_gap memory): same-block coinbase-vs-
// spend collision, DB_POUW_LEAF_LIST reorg round-trip, activation height
// gating end-to-end. draft/xmss-spend-leaf-dedup has no regtest-controllable
// activation-height hook yet (unlike e.g. -testactivationheight=dersig@N),
// so those need either that hook added or a heavier custom fixture -- left
// for when this feature is closer to actually being scheduled.

#include <script/interpreter.h>
#include <script/script.h>
#include <xmss_leaf_key.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

BOOST_AUTO_TEST_SUITE(xmss_leaf_capture_tests)

namespace {

// Always returns a fixed result for CheckXMSSSignature, regardless of the
// actual signature bytes -- isolates these tests to the capture WIRING
// (does m_xmss_leaf_uses get populated correctly from real script
// execution?) rather than re-testing XMSS crypto correctness, which
// xmss_leaf_key_tests.cpp's real-signature round-trip tests already cover.
class MockXMSSChecker : public BaseSignatureChecker
{
public:
    explicit MockXMSSChecker(bool result) : m_result(result) {}
    bool CheckXMSSSignature(const std::vector<unsigned char>& /*sig*/, const std::vector<unsigned char>& /*pubkey*/,
                             const CScript& /*scriptCode*/, SigVersion /*sigversion*/) const override
    {
        return m_result;
    }

private:
    bool m_result;
};

// Like MockXMSSChecker, but returns a different canned result on each
// successive call -- for scripts with more than one OP_XMSS_CHECKSIG where
// the checks need to have different outcomes (e.g. first succeeds, second
// fails).
class SequencedXMSSChecker : public BaseSignatureChecker
{
public:
    explicit SequencedXMSSChecker(std::vector<bool> results) : m_results(std::move(results)) {}
    bool CheckXMSSSignature(const std::vector<unsigned char>& /*sig*/, const std::vector<unsigned char>& /*pubkey*/,
                             const CScript& /*scriptCode*/, SigVersion /*sigversion*/) const override
    {
        BOOST_REQUIRE(m_next < m_results.size());
        return m_results[m_next++];
    }

private:
    std::vector<bool> m_results;
    mutable size_t m_next = 0;
};

std::vector<uint8_t> FakePubkey(uint8_t fill)
{
    return std::vector<uint8_t>(64, fill);
}

// A "chunk" pushed via scriptSig/scriptPubKey standing in for a signature
// piece -- content is irrelevant to MockXMSSChecker, but the first 4 bytes
// are what capture extracts as the leaf index (mirrors the real XMSS wire
// format, see xmss_leaf_key.cpp).
std::vector<uint8_t> FakeChunk(uint32_t leaf_idx, size_t total_len = 8)
{
    std::vector<uint8_t> c(total_len, 0x99);
    c[0] = (leaf_idx >> 24) & 0xFF;
    c[1] = (leaf_idx >> 16) & 0xFF;
    c[2] = (leaf_idx >> 8) & 0xFF;
    c[3] = leaf_idx & 0xFF;
    return c;
}

} // namespace

BOOST_AUTO_TEST_CASE(capture_fires_for_bare_p2xmss_template)
{
    // Positive control: the blessed template also goes through capture now
    // (not just the old ExtractXMSSLeafUse() path) -- sanity-checks the
    // wiring before testing the non-template case below.
    std::vector<uint8_t> pubkey = FakePubkey(0x11);
    CScript scriptPubKey = CScript() << pubkey << OP_XMSS_CHECKSIG;
    CScript scriptSig = CScript() << FakeChunk(1234);

    MockXMSSChecker checker(/*result=*/true);
    XMSSLeafUses captured;
    ScriptError err;
    bool ok = VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
    BOOST_REQUIRE(ok);
    BOOST_REQUIRE_EQUAL(captured.size(), 1u);
    BOOST_CHECK(captured[0].first == pubkey);
    BOOST_CHECK_EQUAL(captured[0].second, 1234u);
}

BOOST_AUTO_TEST_CASE(capture_fires_for_non_template_script_that_bypasses_static_extraction)
{
    // THE key regression test for the bypass gap: this scriptPubKey still
    // reaches and successfully verifies OP_XMSS_CHECKSIGVERIFY, but its
    // shape (<pubkey> OP_XMSS_CHECKSIGVERIFY OP_TRUE) is neither the bare
    // P2XMSS nor the P2XMSSHASH Solver() template (solver.cpp requires
    // exactly OP_XMSS_CHECKSIG, not the VERIFY variant, as the second op).
    std::vector<uint8_t> pubkey = FakePubkey(0x22);
    CScript scriptPubKey = CScript() << pubkey << OP_XMSS_CHECKSIGVERIFY << OP_TRUE;
    CScript scriptSig = CScript() << FakeChunk(777);

    // Old, static, Solver()-template-based detection: must NOT see this.
    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_CHECK(!ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));

    // New, structural, execution-based detection: MUST see this.
    MockXMSSChecker checker(/*result=*/true);
    XMSSLeafUses captured;
    ScriptError err;
    bool ok = VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
    BOOST_REQUIRE(ok);
    BOOST_REQUIRE_EQUAL(captured.size(), 1u);
    BOOST_CHECK(captured[0].first == pubkey);
    BOOST_CHECK_EQUAL(captured[0].second, 777u);
}

BOOST_AUTO_TEST_CASE(capture_empty_when_signature_check_fails)
{
    // False-positive-DoS guard (see job_queue / xmss_spend_leaf_dedup_bypass_gap
    // memory): a failed check must never mark a leaf as used.
    std::vector<uint8_t> pubkey = FakePubkey(0x33);
    CScript scriptPubKey = CScript() << pubkey << OP_XMSS_CHECKSIG;
    CScript scriptSig = CScript() << FakeChunk(555);

    MockXMSSChecker checker(/*result=*/false);
    XMSSLeafUses captured;
    ScriptError err;
    bool ok = VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK(captured.empty());
}

BOOST_AUTO_TEST_CASE(capture_accumulates_across_multiple_checks_in_one_script)
{
    // Two independent OP_XMSS_CHECKSIG spends chained in a single script
    // (e.g. an AND-of-two-keys style script) must produce TWO captured
    // entries, not one overwriting the other. The second chunk+pubkey are
    // pushed directly by scriptPubKey (not scriptSig) so the first check's
    // dynamic chunk-count scan can't accidentally slurp them up too.
    std::vector<uint8_t> pubkey1 = FakePubkey(0x44);
    std::vector<uint8_t> pubkey2 = FakePubkey(0x55);
    CScript scriptPubKey = CScript() << pubkey1 << OP_XMSS_CHECKSIG << OP_VERIFY
                                      << FakeChunk(11) << pubkey2 << OP_XMSS_CHECKSIG;
    CScript scriptSig = CScript() << FakeChunk(22);

    MockXMSSChecker checker(/*result=*/true);
    XMSSLeafUses captured;
    ScriptError err;
    bool ok = VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
    BOOST_REQUIRE(ok);
    BOOST_REQUIRE_EQUAL(captured.size(), 2u);
    BOOST_CHECK(captured[0].first == pubkey1);
    BOOST_CHECK_EQUAL(captured[0].second, 22u);
    BOOST_CHECK(captured[1].first == pubkey2);
    BOOST_CHECK_EQUAL(captured[1].second, 11u);
}

BOOST_AUTO_TEST_CASE(plain_verifyscript_unaffected_by_capture_refactor)
{
    // Regression check for the VerifyScript() rewrite itself (splitting the
    // old single-EvalScript-per-call-site pattern into per-call-site local
    // ScriptExecutionData objects, see interpreter.cpp): plain VerifyScript()
    // -- no capture requested -- must still behave identically for both the
    // template and non-template shapes above.
    std::vector<uint8_t> pubkey = FakePubkey(0x66);
    CScript scriptPubKey = CScript() << pubkey << OP_XMSS_CHECKSIGVERIFY << OP_TRUE;
    CScript scriptSig = CScript() << FakeChunk(999);

    MockXMSSChecker okChecker(/*result=*/true);
    ScriptError err;
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, nullptr, /*flags=*/0, okChecker, &err));

    MockXMSSChecker failChecker(/*result=*/false);
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, nullptr, /*flags=*/0, failChecker, &err));
}

// ── Additional edge cases (requested in self-review, 25 Jul 2026) ─────────

BOOST_AUTO_TEST_CASE(capture_stays_empty_for_untaken_op_if_branch)
{
    // OP_XMSS_CHECKSIG sitting in the not-taken branch of an OP_IF must
    // never execute at all -- the interpreter's vfExec branch tracking
    // skips it structurally, so this is true "by construction" rather than
    // by any special-casing in the capture logic itself. This test proves
    // it rather than just asserting it in a comment.
    std::vector<uint8_t> pubkey = FakePubkey(0x77);
    CScript scriptPubKey = CScript() << OP_0 << OP_IF
                                          << pubkey << OP_XMSS_CHECKSIG
                                      << OP_ELSE
                                          << OP_TRUE
                                      << OP_ENDIF;
    CScript scriptSig; // nothing needed -- the IF branch (which would want
                        // chunk data below the pubkey) never runs.

    MockXMSSChecker checker(/*result=*/true); // must not even be consulted
    XMSSLeafUses captured;
    ScriptError err;
    bool ok = VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
    BOOST_CHECK(ok); // OP_ELSE branch (OP_TRUE) is what determines success
    BOOST_CHECK(captured.empty());
}

BOOST_AUTO_TEST_CASE(capture_only_the_succeeding_check_when_one_of_two_fails)
{
    // Same two-independent-checks script shape as
    // capture_accumulates_across_multiple_checks_in_one_script, but the
    // second check fails this time. Must capture exactly the first
    // (successful) leaf use, and the script must fail overall -- both
    // things have to be true simultaneously, since a failed second check
    // must not erase what the first, genuinely successful, check already
    // proved.
    std::vector<uint8_t> pubkey1 = FakePubkey(0x88);
    std::vector<uint8_t> pubkey2 = FakePubkey(0x99);
    CScript scriptPubKey = CScript() << pubkey1 << OP_XMSS_CHECKSIG << OP_VERIFY
                                      << FakeChunk(44) << pubkey2 << OP_XMSS_CHECKSIG;
    CScript scriptSig = CScript() << FakeChunk(33);

    SequencedXMSSChecker checker({/*check1=*/true, /*check2=*/false});
    XMSSLeafUses captured;
    ScriptError err;
    bool ok = VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
    BOOST_CHECK(!ok); // second check's false ends up as the final stack value
    BOOST_REQUIRE_EQUAL(captured.size(), 1u);
    BOOST_CHECK(captured[0].first == pubkey1);
    BOOST_CHECK_EQUAL(captured[0].second, 33u);
}

BOOST_AUTO_TEST_CASE(capture_fires_through_extra_opcodes_around_non_template_script)
{
    // Another non-template shape, this time with an opcode wrapped AROUND
    // the check rather than replacing OP_XMSS_CHECKSIG with the VERIFY
    // variant (see capture_fires_for_non_template_script_that_bypasses_
    // static_extraction for that one). The wrapper opcode goes BEFORE the
    // pubkey push, not after: OP_XMSS_CHECKSIG's dynamic chunk-count scan
    // greedily consumes every eligible (1-520 byte) item below the pubkey,
    // so anything pushed AFTER the pubkey but still below it on the stack
    // (e.g. a naive OP_DUP of the pubkey) gets slurped up as if it were
    // part of the signature -- a real interaction worth knowing about, not
    // something this test needs to fight.
    std::vector<uint8_t> pubkey = FakePubkey(0xAA);
    CScript scriptPubKey = CScript() << OP_NOP << pubkey << OP_XMSS_CHECKSIGVERIFY << OP_TRUE;
    CScript scriptSig = CScript() << FakeChunk(66);

    std::vector<uint8_t> pk_out;
    uint32_t leaf_out;
    BOOST_CHECK(!ExtractXMSSLeafUse(scriptPubKey, scriptSig, pk_out, leaf_out));

    MockXMSSChecker checker(/*result=*/true);
    XMSSLeafUses captured;
    ScriptError err;
    bool ok = VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
    BOOST_REQUIRE(ok);
    BOOST_REQUIRE_EQUAL(captured.size(), 1u);
    BOOST_CHECK(captured[0].first == pubkey);
    BOOST_CHECK_EQUAL(captured[0].second, 66u);
}

BOOST_AUTO_TEST_CASE(capture_stays_empty_for_malformed_stack_and_empty_script)
{
    // OP_XMSS_CHECKSIG with nothing on the stack to check -- must fail
    // before ever reaching CheckXMSSSignature, let alone capturing.
    {
        CScript scriptPubKey = CScript() << OP_XMSS_CHECKSIG;
        CScript scriptSig; // empty -- stack.size() < 2 when the opcode runs

        MockXMSSChecker checker(/*result=*/true);
        XMSSLeafUses captured;
        ScriptError err;
        bool ok = VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
        BOOST_CHECK(!ok);
        BOOST_CHECK(captured.empty());
    }

    // Completely empty scriptPubKey -- nothing XMSS-related can possibly
    // run, capture must stay empty regardless of scriptSig/overall result.
    {
        CScript scriptPubKey;
        CScript scriptSig = CScript() << std::vector<uint8_t>{0x01};

        MockXMSSChecker checker(/*result=*/true);
        XMSSLeafUses captured;
        ScriptError err;
        VerifyScriptXMSSCapture(scriptSig, scriptPubKey, nullptr, /*flags=*/0, checker, &captured, &err);
        BOOST_CHECK(captured.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
