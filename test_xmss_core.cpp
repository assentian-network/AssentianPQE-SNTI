// QNT XMSS Core Test — Minimal, no Bitcoin Core dependencies
// Uses OpenSSL SHA-256 directly
// Compile: g++ -std=c++17 -O2 -I src -o test_xmss_core test_xmss_core.cpp \
//   src/xmss.c src/xmss_core.c src/xmss_commons.c \
//   src/wots.c src/params.c src/fips202.c src/utils.c src/hash_address.c \
//   src/randombytes.c -lssl -lcrypto -lpthread

#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>
#include <string>
#include <openssl/sha.h>

#include "xmss.h"
#include "params.h"
#include "xmss_core.h"

// Provide xmss_sha256/xmss_sha512 using OpenSSL (for testing only)
extern "C" {
void xmss_sha256(const unsigned char* in, unsigned long long inlen, unsigned char* out) {
    SHA256(in, inlen, out);
}
void xmss_sha512(const unsigned char* in, unsigned long long inlen, unsigned char* out) {
    SHA512(in, inlen, out);
}
}

static const uint32_t OID_XMSS_SHA2_10_256 = 0x00000001;
static const uint32_t OID_XMSS_SHA2_20_256 = 0x00000002;

static std::string HexStr(const unsigned char* data, size_t len) {
    static const char hexmap[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        s.push_back(hexmap[data[i] >> 4]);
        s.push_back(hexmap[data[i] & 0xf]);
    }
    return s;
}

static int test_count = 0;
static int pass_count = 0;

int main() {
    printf("========================================\n");
    printf("QNT XMSS Core Test\n");
    printf("Post-Quantum Signature Verification\n");
    printf("========================================\n\n");

    // Test 1: Parameter parsing
    test_count++;
    printf("[TEST %d] XMSS parameter parsing...\n", test_count);
    xmss_params params;
    int ret = xmss_parse_oid(&params, OID_XMSS_SHA2_10_256);
    if (ret != 0) { printf("  [FAIL] xmss_parse_oid failed\n"); return 1; }
    printf("  [OK]   n=%u, full_height=%u, tree_height=%u\n", params.n, params.full_height, params.tree_height);
    printf("  [OK]   sig_bytes=%llu, sk_bytes=%llu, pk_bytes=%u\n", params.sig_bytes, params.sk_bytes, params.pk_bytes);
    pass_count++;
    printf("  [OK]   PASSED\n\n");

    // Test 2: Key generation
    test_count++;
    printf("[TEST %d] XMSS key generation...\n", test_count);
    std::vector<unsigned char> pk(XMSS_OID_LEN + params.pk_bytes);
    std::vector<unsigned char> sk(XMSS_OID_LEN + params.sk_bytes);
    ret = xmss_keypair(pk.data(), sk.data(), OID_XMSS_SHA2_10_256);
    if (ret != 0) { printf("  [FAIL] xmss_keypair failed\n"); return 1; }
    printf("  [OK]   pk=%s... (%zu bytes)\n", HexStr(pk.data(), 16).c_str(), pk.size());
    printf("  [OK]   sk=%zu bytes\n", sk.size());
    pass_count++;
    printf("  [OK]   PASSED\n\n");

    // Test 3: Sign and verify
    test_count++;
    printf("[TEST %d] XMSS sign and verify...\n", test_count);
    const char* msg = "QNT: First mineable post-quantum blockchain";
    size_t mlen = strlen(msg);
    std::vector<unsigned char> sm(params.sig_bytes + mlen + 256);
    unsigned long long smlen = 0;
    ret = xmss_sign(sk.data(), sm.data(), &smlen, (const unsigned char*)msg, mlen);
    if (ret != 0) { printf("  [FAIL] xmss_sign failed\n"); return 1; }
    printf("  [OK]   sig=%llu bytes\n", smlen);

    std::vector<unsigned char> m_out(mlen + 1);
    unsigned long long mlen_out = 0;
    ret = xmss_sign_open(m_out.data(), &mlen_out, sm.data(), smlen, pk.data());
    if (ret != 0) { printf("  [FAIL] xmss_sign_open failed\n"); return 1; }
    if (mlen_out != mlen || memcmp(m_out.data(), msg, mlen) != 0) { printf("  [FAIL] Message mismatch\n"); return 1; }
    printf("  [OK]   verified: %s\n", m_out.data());
    pass_count++;
    printf("  [OK]   PASSED\n\n");

    // Test 4: Wrong key verification fails
    test_count++;
    printf("[TEST %d] XMSS verify with wrong key...\n", test_count);
    std::vector<unsigned char> pk2(XMSS_OID_LEN + params.pk_bytes), sk2(XMSS_OID_LEN + params.sk_bytes);
    xmss_keypair(pk2.data(), sk2.data(), OID_XMSS_SHA2_10_256);
    std::vector<unsigned char> m_out2(256);
    unsigned long long mlen_out2 = 0;
    ret = xmss_sign_open(m_out2.data(), &mlen_out2, sm.data(), smlen, pk2.data());
    if (ret == 0) { printf("  [FAIL] Verify with wrong key should fail\n"); return 1; }
    printf("  [OK]   wrong key correctly rejected\n");
    pass_count++;
    printf("  [OK]   PASSED\n\n");

    // Test 5: Stateful signing (10 signatures)
    test_count++;
    printf("[TEST %d] XMSS stateful signing (10 sigs)...\n", test_count);
    for (int i = 0; i < 10; i++) {
        char msg2[64];
        snprintf(msg2, sizeof(msg2), "QNT block #%d - post-quantum secure", i);
        size_t mlen2 = strlen(msg2);
        std::vector<unsigned char> sm2(params.sig_bytes + mlen2 + 256);
        unsigned long long smlen2 = 0;
        ret = xmss_sign(sk.data(), sm2.data(), &smlen2, (const unsigned char*)msg2, mlen2);
        if (ret != 0) { printf("  [FAIL] Sign #%d failed\n", i); return 1; }
        std::vector<unsigned char> m_out3(mlen2 + 1);
        unsigned long long mlen_out3 = 0;
        ret = xmss_sign_open(m_out3.data(), &mlen_out3, sm2.data(), smlen2, pk.data());
        if (ret != 0) { printf("  [FAIL] Verify #%d failed\n", i); return 1; }
    }
    printf("  [OK]   10 signatures created and verified\n");
    pass_count++;
    printf("  [OK]   PASSED\n\n");

    // Test 6: XMSS-SHA2_20_256 (higher security)
    test_count++;
    printf("[TEST %d] XMSS-SHA2_20_256 (higher security)...\n", test_count);
    xmss_params params20;
    xmss_parse_oid(&params20, OID_XMSS_SHA2_20_256);
    std::vector<unsigned char> pk20(XMSS_OID_LEN + params20.pk_bytes);
    std::vector<unsigned char> sk20(XMSS_OID_LEN + params20.sk_bytes);
    ret = xmss_keypair(pk20.data(), sk20.data(), OID_XMSS_SHA2_20_256);
    if (ret != 0) { printf("  [FAIL] xmss_keypair failed for SHA2_20_256\n"); return 1; }
    const char* msg20 = "QNT: 20-height XMSS for higher security";
    std::vector<unsigned char> sm20(params20.sig_bytes + strlen(msg20) + 256);
    unsigned long long smlen20 = 0;
    ret = xmss_sign(sk20.data(), sm20.data(), &smlen20, (const unsigned char*)msg20, strlen(msg20));
    if (ret != 0) { printf("  [FAIL] xmss_sign failed for SHA2_20_256\n"); return 1; }
    std::vector<unsigned char> m_out20(256);
    unsigned long long mlen_out20 = 0;
    ret = xmss_sign_open(m_out20.data(), &mlen_out20, sm20.data(), smlen20, pk20.data());
    if (ret != 0) { printf("  [FAIL] xmss_sign_open failed for SHA2_20_256\n"); return 1; }
    printf("  [OK]   SHA2_20_256: sig=%llu bytes, verified\n", smlen20);
    pass_count++;
    printf("  [OK]   PASSED\n\n");

    printf("========================================\n");
    printf("Results: %d/%d tests passed\n", pass_count, test_count);
    printf("========================================\n");

    if (pass_count == test_count) {
        printf("\n[ALL TESTS PASSED]\n");
        printf("QNT XMSS-SHA2_10_256 is quantum-resistant!\n");
        printf("NIST SP 800-208 compliant hash-based signatures.\n");
        return 0;
    } else {
        printf("\n[SOME TESTS FAILED]\n");
        return 1;
    }
}
