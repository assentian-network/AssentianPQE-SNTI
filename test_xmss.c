/*
 * XMSS Test - verify keygen, sign, sign_open for all parameter sets
 * Compile: gcc -O2 -I src -o test_xmss test_xmss.c \
 *   src/xmss.c src/xmss_core.c src/xmss_commons.c src/xmss_hash.c \
 *   src/wots.c src/params.c src/fips202.c src/utils.c src/hash_address.c \
 *   src/randombytes.c -lcrypto
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "xmss.h"
#include "params.h"
#include "xmss_core.h"

static int test_params(const char *name, uint32_t oid) {
    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        printf("[FAIL] %s: xmss_parse_oid failed\n", name);
        return 1;
    }

    unsigned char pk[params.pk_bytes];
    unsigned char sk[params.sk_bytes];
    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));

    /* Keygen */
    int ret = xmss_keypair(pk, sk, oid);
    if (ret != 0) {
        printf("[FAIL] %s: xmss_keypair returned %d\n", name, ret);
        return 1;
    }
    printf("[OK]   %s: keygen done (pk=%u bytes, sk=%llu bytes)\n",
           name, params.pk_bytes, params.sk_bytes);

    /* Sign */
    const char *msg = "Hello XMSS post-quantum world!";
    unsigned long long mlen = strlen(msg);
    unsigned long long smlen = params.sig_bytes + mlen;
    unsigned char *sm = (unsigned char *)malloc(smlen);
    if (!sm) {
        printf("[FAIL] %s: malloc sm failed\n", name);
        return 1;
    }

    ret = xmss_sign(sk, sm, &smlen, (const unsigned char *)msg, mlen);
    if (ret != 0) {
        printf("[FAIL] %s: xmss_sign returned %d\n", name, ret);
        free(sm);
        return 1;
    }
    printf("[OK]   %s: sign done (%llu bytes)\n", name, smlen);

    /* Verify */
    unsigned char *m_out = (unsigned char *)malloc(mlen + 1);
    unsigned long long mlen_out = 0;
    memset(m_out, 0, mlen + 1);

    ret = xmss_sign_open(m_out, &mlen_out, sm, smlen, pk);
    if (ret != 0) {
        printf("[FAIL] %s: xmss_sign_open returned %d\n", name, ret);
        free(sm);
        free(m_out);
        return 1;
    }
    if (mlen_out != mlen || memcmp(m_out, msg, mlen) != 0) {
        printf("[FAIL] %s: message mismatch after verify\n", name);
        free(sm);
        free(m_out);
        return 1;
    }
    printf("[OK]   %s: verify OK, message matches\n", name);

    /* Test sign with wrong key (tampered signature) */
    sm[0] ^= 0xFF;
    memset(m_out, 0, mlen + 1);
    mlen_out = 0;
    ret = xmss_sign_open(m_out, &mlen_out, sm, smlen, pk);
    if (ret == 0) {
        printf("[FAIL] %s: tampered sig should NOT verify!\n", name);
        free(sm);
        free(m_out);
        return 1;
    }
    printf("[OK]   %s: tampered sig correctly rejected\n", name);

    free(sm);
    free(m_out);
    return 0;
}

static int test_mt_params(const char *name, uint32_t oid) {
    xmss_params params;
    if (xmssmt_parse_oid(&params, oid) != 0) {
        printf("[FAIL] %s: xmssmt_parse_oid failed\n", name);
        return 1;
    }

    unsigned char pk[params.pk_bytes];
    unsigned char sk[params.sk_bytes];
    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));

    int ret = xmssmt_keypair(pk, sk, oid);
    if (ret != 0) {
        printf("[FAIL] %s: xmssmt_keypair returned %d\n", name, ret);
        return 1;
    }
    printf("[OK]   %s: keygen done (pk=%u bytes, sk=%llu bytes)\n",
           name, params.pk_bytes, params.sk_bytes);

    const char *msg = "Hello XMSSMT post-quantum world!";
    unsigned long long mlen = strlen(msg);
    unsigned long long smlen = params.sig_bytes + mlen;
    unsigned char *sm = (unsigned char *)malloc(smlen);
    if (!sm) {
        printf("[FAIL] %s: malloc sm failed\n", name);
        return 1;
    }

    ret = xmssmt_sign(sk, sm, &smlen, (const unsigned char *)msg, mlen);
    if (ret != 0) {
        printf("[FAIL] %s: xmssmt_sign returned %d\n", name, ret);
        free(sm);
        return 1;
    }
    printf("[OK]   %s: sign done (%llu bytes)\n", name, smlen);

    unsigned char *m_out = (unsigned char *)malloc(mlen + 1);
    unsigned long long mlen_out = 0;
    memset(m_out, 0, mlen + 1);

    ret = xmssmt_sign_open(m_out, &mlen_out, sm, smlen, pk);
    if (ret != 0) {
        printf("[FAIL] %s: xmssmt_sign_open returned %d\n", name, ret);
        free(sm);
        free(m_out);
        return 1;
    }
    if (mlen_out != mlen || memcmp(m_out, msg, mlen) != 0) {
        printf("[FAIL] %s: message mismatch after verify\n", name);
        free(sm);
        free(m_out);
        return 1;
    }
    printf("[OK]   %s: verify OK, message matches\n", name);

    /* Tampered test */
    sm[0] ^= 0xFF;
    memset(m_out, 0, mlen + 1);
    mlen_out = 0;
    ret = xmssmt_sign_open(m_out, &mlen_out, sm, smlen, pk);
    if (ret == 0) {
        printf("[FAIL] %s: tampered sig should NOT verify!\n", name);
        free(sm);
        free(m_out);
        return 1;
    }
    printf("[OK]   %s: tampered sig correctly rejected\n", name);

    free(sm);
    free(m_out);
    return 0;
}

int main(void) {
    int failures = 0;

    printf("=== XMSS Single-Tree Tests ===\n");
    failures += test_params("XMSS-SHA2_10_256", 0x00000001);
    failures += test_params("XMSS-SHA2_16_256", 0x00000002);
    failures += test_params("XMSS-SHA2_20_256", 0x00000003);
    failures += test_params("XMSS-SHA2_10_512", 0x00000004);
    failures += test_params("XMSS-SHA2_16_512", 0x00000005);
    failures += test_params("XMSS-SHA2_20_512", 0x00000006);
    failures += test_params("XMSS-SHAKE_10_256", 0x00000007);
    failures += test_params("XMSS-SHAKE_16_256", 0x00000008);
    failures += test_params("XMSS-SHAKE_20_256", 0x00000009);
    failures += test_params("XMSS-SHAKE_10_512", 0x0000000a);
    failures += test_params("XMSS-SHAKE_16_512", 0x0000000b);
    failures += test_params("XMSS-SHAKE_20_512", 0x0000000c);
    failures += test_params("XMSS-SHA2_10_192", 0x0000000d);
    failures += test_params("XMSS-SHA2_16_192", 0x0000000e);
    failures += test_params("XMSS-SHA2_20_192", 0x0000000f);
    failures += test_params("XMSS-SHAKE256_10_256", 0x00000010);
    failures += test_params("XMSS-SHAKE256_16_256", 0x00000011);
    failures += test_params("XMSS-SHAKE256_20_256", 0x00000012);
    failures += test_params("XMSS-SHAKE256_10_192", 0x00000013);
    failures += test_params("XMSS-SHAKE256_16_192", 0x00000014);
    failures += test_params("XMSS-SHAKE256_20_192", 0x00000015);

    printf("\n=== XMSSMT Multi-Tree Tests ===\n");
    failures += test_mt_params("XMSSMT-SHA2_20/2_256", 0x00000001);
    failures += test_mt_params("XMSSMT-SHA2_40/4_256", 0x00000004);
    failures += test_mt_params("XMSSMT-SHA2_60/3_256", 0x00000006);
    failures += test_mt_params("XMSSMT-SHAKE_20/2_256", 0x00000011);
    failures += test_mt_params("XMSSMT-SHAKE256_20/2_256", 0x00000029);

    printf("\n=== Results: %d failures ===\n", failures);
    return failures;
}
