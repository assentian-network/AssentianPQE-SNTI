/* Quick XMSS sanity test - just one parameter set */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "xmss.h"
#include "params.h"

int main(void) {
    printf("Testing XMSS-SHA2_10_256 (simplest)...\n");
    fflush(stdout);

    uint32_t oid = 0x00000001;
    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        printf("FAIL: xmss_parse_oid\n");
        return 1;
    }
    printf("  n=%u, h=%u, d=%u, w=%u, sig_bytes=%u, pk_bytes=%u, sk_bytes=%llu\n",
           params.n, params.full_height, params.d, params.wots_w,
           params.sig_bytes, params.pk_bytes, params.sk_bytes);
    fflush(stdout);

    unsigned char *pk = calloc(params.pk_bytes, 1);
    unsigned char *sk = calloc(params.sk_bytes, 1);

    printf("  Keygen...\n"); fflush(stdout);
    int ret = xmss_keypair(pk, sk, oid);
    if (ret != 0) { printf("FAIL: keypair %d\n", ret); return 1; }
    printf("  OK\n"); fflush(stdout);

    const char *msg = "test";
    unsigned long long mlen = 4;
    unsigned long long smlen = params.sig_bytes + mlen;
    unsigned char *sm = calloc(smlen, 1);

    printf("  Sign...\n"); fflush(stdout);
    ret = xmss_sign(sk, sm, &smlen, (unsigned char *)msg, mlen);
    if (ret != 0) { printf("FAIL: sign %d\n", ret); return 1; }
    printf("  OK (smlen=%llu)\n", smlen); fflush(stdout);

    unsigned char *m_out = calloc(mlen + 1, 1);
    unsigned long long mlen_out = 0;

    printf("  Verify...\n"); fflush(stdout);
    ret = xmss_sign_open(m_out, &mlen_out, sm, smlen, pk);
    if (ret != 0) { printf("FAIL: verify %d\n", ret); return 1; }
    if (mlen_out != mlen || memcmp(m_out, msg, mlen) != 0) {
        printf("FAIL: msg mismatch\n"); return 1;
    }
    printf("  OK\n"); fflush(stdout);

    /* Quick tamper test */
    sm[0] ^= 0xFF;
    ret = xmss_sign_open(m_out, &mlen_out, sm, smlen, pk);
    if (ret == 0) { printf("FAIL: tampered accepted\n"); return 1; }
    printf("  Tamper reject OK\n");

    /* Sign again with updated sk (stateful) */
    printf("  Sign #2...\n"); fflush(stdout);
    ret = xmss_sign(sk, sm, &smlen, (unsigned char *)msg, mlen);
    if (ret != 0) { printf("FAIL: sign2 %d\n", ret); return 1; }

    printf("  Verify #2...\n"); fflush(stdout);
    ret = xmss_sign_open(m_out, &mlen_out, sm, smlen, pk);
    if (ret != 0) { printf("FAIL: verify2 %d\n", ret); return 1; }
    printf("  OK - stateful signing works!\n");

    free(pk); free(sk); free(sm); free(m_out);
    printf("\nAll tests PASSED\n");
    return 0;
}
