/* Test updated C++ bridge + XMSS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include "xmss_bridge.h"

int main(void) {
    int failures = 0;
    printf("=== Testing updated C++ XMSS Bridge ===\n\n");
    fflush(stdout);

    /* Test 1: Generate, Sign, Verify */
    printf("Test 1: Generate + Sign + Verify\n");
    fflush(stdout);

    XMSS::CXMSSKey key;
    if (!key.Generate()) {
        printf("FAIL: Generate\n");
        return 1;
    }
    printf("  Generate OK\n");
    fflush(stdout);

    std::vector<uint8_t> hash(32);
    for (int i = 0; i < 32; i++) hash[i] = (unsigned char)i;

    std::vector<uint8_t> sig;
    if (!key.Sign(hash, sig)) {
        printf("FAIL: Sign\n");
        return 1;
    }
    printf("  Sign OK (sig size=%zu)\n", sig.size());
    fflush(stdout);

    std::vector<uint8_t> pubkey = key.GetPubKey();
    printf("  PubKey size=%zu\n", pubkey.size());
    fflush(stdout);

    if (!key.Verify(hash, sig, pubkey)) {
        printf("FAIL: Verify\n");
        return 1;
    }
    printf("  Verify OK\n");
    fflush(stdout);

    /* Test 2: Sign #2 (stateful) */
    printf("\nTest 2: Stateful Sign #2\n");
    fflush(stdout);

    std::vector<uint8_t> sig2;
    if (!key.Sign(hash, sig2)) {
        printf("FAIL: Sign #2\n");
        return 1;
    }
    if (!key.Verify(hash, sig2, pubkey)) {
        printf("FAIL: Verify #2\n");
        return 1;
    }
    printf("  Sign #2 + Verify OK\n");
    fflush(stdout);

    /* Test 3: Wrong hash should fail */
    printf("\nTest 3: Wrong hash rejection\n");
    fflush(stdout);

    std::vector<uint8_t> wrong_hash(32, 0xFF);
    if (key.Verify(wrong_hash, sig, pubkey)) {
        printf("FAIL: wrong hash should NOT verify\n");
        return 1;
    }
    printf("  Wrong hash correctly rejected\n");
    fflush(stdout);

    /* Test 4: Dynamic sizes (no C-level calls) */
    printf("\nTest 4: Dynamic sizes used by bridge\n");
    printf("  sig size from Sign() = %zu (old hardcoded was 2452)\n", sig.size());
    printf("  pk size from GetPubKey() = %zu\n", pubkey.size());
    if (sig.size() != 2500) {
        printf("  FAIL: expected sig=2500, got %zu\n", sig.size());
        failures++;
    } else {
        printf("  CONFIRMED: dynamic sig size = %zu (old 2452 was wrong!)\n", sig.size());
    }
    if (pubkey.size() != 64) {
        printf("  FAIL: expected pk=64, got %zu\n", pubkey.size());
        failures++;
    }

    /* Test 5: GetPrivKey returns non-empty */
    printf("\nTest 5: GetPrivKey serialization\n");
    std::vector<uint8_t> sk_bytes = key.GetPrivKey();
    printf("  sk size = %zu\n", sk_bytes.size());
    if (sk_bytes.empty()) {
        printf("  FAIL: empty sk\n");
        failures++;
    } else {
        printf("  OK: sk serialized\n");
    }

    if (failures == 0) {
        printf("\n=== All C++ Bridge Tests PASSED ===\n");
    } else {
        printf("\n=== %d failures ===\n", failures);
    }
    return failures;
}
