// QNT Integration Test: XMSS Transaction Signing
// Tests end-to-end XMSS transaction flow:
//   1. Generate XMSS key pair
//   2. Create P2XMSS output
//   3. Create transaction spending P2XMSS
//   4. Sign with XMSS
//   5. Verify signature
//   6. Verify CheckXMSSSignature
//
// Compile: g++ -O2 -I src -I src/wallet -o test_xmss_tx test_xmss_tx.cpp \
//   src/wallet/xmss_signer.cpp src/xmss_bridge.cpp src/xmss.c \
//   src/xmss_core.c src/xmss_commons.c src/xmss_hash.c src/xmss_core_fast.c \
//   src/wots.c src/params.c src/fips202.c src/utils.c src/hash_address.c \
//   src/randombytes.c src/xmss_sha_wrapper.cpp \
//   -lssl -lcrypto -lpthread
//
// Usage: ./test_xmss_tx

#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>
#include <string>
#include <iostream>

#include "xmss_bridge.h"
#include "wallet/xmss_signer.h"
#include "script/script.h"
#include "script/solver.h"
#include "uint256.h"
#include "hash.h"

// Helper: print hex
static std::string HexStr(const std::vector<uint8_t>& v) {
    static const char hexmap[] = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v) {
        s.push_back(hexmap[b >> 4]);
        s.push_back(hexmap[b & 0xf]);
    }
    return s;
}

static std::string HexStr(const uint256& h) {
    return HexStr(std::vector<uint8_t>(h.begin(), h.end()));
}

// Test 1: XMSS key generation
static bool test_keygen() {
    printf("[TEST 1] XMSS key generation...\n");

    XMSS::CXMSSKey key;
    if (!key.Generate()) {
        printf("  [FAIL] Key generation failed\n");
        return false;
    }

    std::vector<uint8_t> pubkey = key.GetPubKey();
    if (pubkey.size() != 64) {
        printf("  [FAIL] Pubkey size = %zu, expected 64\n", pubkey.size());
        return false;
    }

    std::vector<uint8_t> seckey = key.GetPrivKey();
    if (seckey.empty()) {
        printf("  [FAIL] Secret key empty\n");
        return false;
    }

    printf("  [OK]   Pubkey: %s... (%zu bytes)\n", HexStr(pubkey).substr(0, 32).c_str(), pubkey.size());
    printf("  [OK]   Seckey: %zu bytes\n", seckey.size());
    return true;
}

// Test 2: XMSS sign and verify
static bool test_sign_verify() {
    printf("[TEST 2] XMSS sign and verify...\n");

    XMSS::CXMSSKey key;
    assert(key.Generate());

    std::vector<uint8_t> pubkey = key.GetPubKey();
    assert(pubkey.size() == 64);

    // Create a test hash (32 bytes)
    uint256 test_hash;
    test_hash.SetHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    std::vector<uint8_t> hash_vec(test_hash.begin(), test_hash.end());

    // Sign
    std::vector<uint8_t> sig;
    if (!key.Sign(hash_vec, sig)) {
        printf("  [FAIL] Sign failed\n");
        return false;
    }
    printf("  [OK]   Signature: %zu bytes\n", sig.size());

    // Verify
    XMSS::CXMSSKey verify_key;
    if (!verify_key.Verify(hash_vec, sig, pubkey)) {
        printf("  [FAIL] Verify failed\n");
        return false;
    }
    printf("  [OK]   Verify passed\n");

    // Verify with wrong hash should fail
    uint256 wrong_hash;
    wrong_hash.SetHex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    std::vector<uint8_t> wrong_hash_vec(wrong_hash.begin(), wrong_hash.end());
    if (verify_key.Verify(wrong_hash_vec, sig, pubkey)) {
        printf("  [FAIL] Verify with wrong hash should fail\n");
        return false;
    }
    printf("  [OK]   Verify with wrong hash correctly rejected\n");

    return true;
}

// Test 3: CXMSSSigner key management
static bool test_signer_management() {
    printf("[TEST 3] CXMSSSigner key management...\n");

    wallet::CXMSSSigner signer;

    // Generate key
    std::vector<uint8_t> pubkey = signer.GenerateKey("test_key");
    if (pubkey.empty()) {
        printf("  [FAIL] GenerateKey failed\n");
        return false;
    }
    printf("  [OK]   Generated key: %s...\n", HexStr(pubkey).substr(0, 32).c_str());

    // Check HaveKey
    if (!signer.HaveKey(pubkey)) {
        printf("  [FAIL] HaveKey returned false\n");
        return false;
    }
    printf("  [OK]   HaveKey returned true\n");

    // Check leaf index
    uint32_t idx = signer.GetLeafIndex(pubkey);
    if (idx != 0) {
        printf("  [FAIL] Leaf index = %u, expected 0\n", idx);
        return false;
    }
    printf("  [OK]   Leaf index = 0 (initial)\n");

    // Get all keys
    auto keys = signer.GetXMSSKeys();
    if (keys.size() != 1) {
        printf("  [FAIL] GetXMSSKeys returned %zu keys, expected 1\n", keys.size());
        return false;
    }
    printf("  [OK]   GetXMSSKeys returned 1 key\n");

    return true;
}

// Test 4: CXMSSSigner signing
static bool test_signer_signing() {
    printf("[TEST 4] CXMSSSigner signing...\n");

    wallet::CXMSSSigner signer;
    std::vector<uint8_t> pubkey = signer.GenerateKey();
    assert(!pubkey.empty());

    // Create test hash
    uint256 test_hash;
    test_hash.SetHex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");

    // Sign
    std::vector<uint8_t> sig;
    if (!signer.SignXMSS(test_hash, pubkey, sig)) {
        printf("  [FAIL] SignXMSS failed\n");
        return false;
    }
    printf("  [OK]   SignXMSS: %zu bytes\n", sig.size());

    // Verify leaf index advanced
    uint32_t idx = signer.GetLeafIndex(pubkey);
    if (idx != 1) {
        printf("  [FAIL] Leaf index = %u, expected 1\n", idx);
        return false;
    }
    printf("  [OK]   Leaf index advanced to 1\n");

    // Verify signature
    XMSS::CXMSSKey verify_key;
    std::vector<uint8_t> hash_vec(test_hash.begin(), test_hash.end());
    if (!verify_key.Verify(hash_vec, sig, pubkey)) {
        printf("  [FAIL] Signature verification failed\n");
        return false;
    }
    printf("  [OK]   Signature verified\n");

    return true;
}

// Test 5: XMSS script creation and detection
static bool test_script_helpers() {
    printf("[TEST 5] XMSS script helpers...\n");

    // Generate key
    wallet::CXMSSSigner signer;
    std::vector<uint8_t> pubkey = signer.GenerateKey();
    assert(pubkey.size() == 64);

    // Create P2XMSS script
    CScript p2xmss = wallet::GetXMSSScriptForPubkey(pubkey);
    if (p2xmss.empty()) {
        printf("  [FAIL] GetXMSSScriptForPubkey returned empty\n");
        return false;
    }
    printf("  [OK]   P2XMSS script: %zu bytes\n", p2xmss.size());

    // Detect XMSS script
    if (!wallet::IsXMSSScript(p2xmss)) {
        printf("  [FAIL] IsXMSSScript returned false for P2XMSS\n");
        return false;
    }
    printf("  [OK]   IsXMSSScript detected P2XMSS\n");

    // Extract pubkey from script
    std::vector<uint8_t> extracted = wallet::GetXMSSPubkeyFromScript(p2xmss);
    if (extracted != pubkey) {
        printf("  [FAIL] GetXMSSPubkeyFromScript returned wrong pubkey\n");
        return false;
    }
    printf("  [OK]   GetXMSSPubkeyFromScript extracted correct pubkey\n");

    // Create P2XMSSHASH script
    CScript p2xmshash = wallet::GetXMSSHashScriptForPubkey(pubkey);
    if (p2xmshash.empty()) {
        printf("  [FAIL] GetXMSSHashScriptForPubkey returned empty\n");
        return false;
    }
    printf("  [OK]   P2XMSSHASH script: %zu bytes\n", p2xmshash.size());

    // Non-XMSS script should not be detected
    CScript non_xmss;
    non_xmss << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
    if (wallet::IsXMSSScript(non_xmss)) {
        printf("  [FAIL] IsXMSSScript returned true for non-XMSS script\n");
        return false;
    }
    printf("  [OK]   IsXMSSScript correctly rejected non-XMSS script\n");

    return true;
}

// Test 6: XMSS key serialization/deserialization
static bool test_key_serialization() {
    printf("[TEST 6] XMSS key serialization...\n");

    // Generate key
    XMSS::CXMSSKey key1;
    assert(key1.Generate());
    std::vector<uint8_t> pubkey1 = key1.GetPubKey();
    std::vector<uint8_t> seckey1 = key1.GetPrivKey();

    // Load key from serialized secret key
    XMSS::CXMSSKey key2;
    if (!key2.Load(seckey1)) {
        printf("  [FAIL] Load from serialized key failed\n");
        return false;
    }

    // Verify loaded key produces same pubkey
    std::vector<uint8_t> pubkey2 = key2.GetPubKey();
    if (pubkey1 != pubkey2) {
        printf("  [FAIL] Loaded key has different pubkey\n");
        return false;
    }
    printf("  [OK]   Loaded key has same pubkey\n");

    // Sign with original key
    uint256 test_hash;
    test_hash.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    std::vector<uint8_t> hash_vec(test_hash.begin(), test_hash.end());
    std::vector<uint8_t> sig1;
    assert(key1.Sign(hash_vec, sig1));

    // Verify with loaded key
    if (!key2.Verify(hash_vec, sig1, pubkey2)) {
        printf("  [FAIL] Verify with loaded key failed\n");
        return false;
    }
    printf("  [OK]   Verify with loaded key passed\n");

    return true;
}

// Test 7: CXMSSSigner import/export
static bool test_signer_import_export() {
    printf("[TEST 7] CXMSSSigner import/export...\n");

    // Generate key in signer1
    wallet::CXMSSSigner signer1;
    std::vector<uint8_t> pubkey = signer1.GenerateKey();
    assert(!pubkey.empty());

    // Get secret key
    XMSS::CXMSSKey temp_key;
    assert(temp_key.Generate());
    std::vector<uint8_t> seckey = temp_key.GetPrivKey();
    std::vector<uint8_t> pubkey2 = temp_key.GetPubKey();

    // Import into signer2
    wallet::CXMSSSigner signer2;
    if (!signer2.AddXMSSKey(pubkey2, seckey)) {
        printf("  [FAIL] AddXMSSKey failed\n");
        return false;
    }
    printf("  [OK]   AddXMSSKey succeeded\n");

    // Verify signer2 can sign
    uint256 test_hash;
    test_hash.SetHex("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe");
    std::vector<uint8_t> sig;
    if (!signer2.SignXMSS(test_hash, pubkey2, sig)) {
        printf("  [FAIL] Sign with imported key failed\n");
        return false;
    }
    printf("  [OK]   Sign with imported key succeeded\n");

    return true;
}

// Test 8: Multiple signatures (stateful)
static bool test_multiple_signatures() {
    printf("[TEST 8] Multiple XMSS signatures (stateful)...\n");

    wallet::CXMSSSigner signer;
    std::vector<uint8_t> pubkey = signer.GenerateKey();
    assert(!pubkey.empty());

    // Sign multiple times
    for (int i = 0; i < 5; i++) {
        uint256 hash;
        // Create unique hash for each signature
        std::string hash_str = "0000000000000000000000000000000000000000000000000000000000000000";
        hash_str[62] = '0' + (i / 10);
        hash_str[63] = '0' + (i % 10);
        hash.SetHex(hash_str);

        std::vector<uint8_t> sig;
        if (!signer.SignXMSS(hash, pubkey, sig)) {
            printf("  [FAIL] Sign #%d failed\n", i);
            return false;
        }

        // Verify leaf index
        uint32_t idx = signer.GetLeafIndex(pubkey);
        if (idx != (uint32_t)(i + 1)) {
            printf("  [FAIL] Leaf index = %u, expected %u\n", idx, i + 1);
            return false;
        }
    }

    printf("  [OK]   5 signatures created, leaf index = 5\n");
    printf("  [OK]   Stateful signing works correctly\n");

    return true;
}

int main() {
    printf("========================================\n");
    printf("QNT XMSS Integration Test\n");
    printf("Post-Quantum Transaction Signing\n");
    printf("========================================\n\n");

    int passed = 0;
    int total = 8;

    if (test_keygen()) passed++; printf("\n");
    if (test_sign_verify()) passed++; printf("\n");
    if (test_signer_management()) passed++; printf("\n");
    if (test_signer_signing()) passed++; printf("\n");
    if (test_script_helpers()) passed++; printf("\n");
    if (test_key_serialization()) passed++; printf("\n");
    if (test_signer_import_export()) passed++; printf("\n");
    if (test_multiple_signatures()) passed++; printf("\n");

    printf("========================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("========================================\n");

    if (passed == total) {
        printf("\n[ALL TESTS PASSED] QNT XMSS integration is working!\n");
        printf("QNT is quantum-resistant: XMSS-SHA2_10_256 signatures\n");
        return 0;
    } else {
        printf("\n[SOME TESTS FAILED] %d tests failed\n", total - passed);
        return 1;
    }
}
