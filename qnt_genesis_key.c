/* QNT Genesis Key Generator
 * Generates XMSS key pair for genesis block
 * Usage: ./qnt_genesis_key
 *
 * Compile: gcc -O2 -I src -o qnt_genesis_key qnt_genesis_key.c \
 *   src/xmss.c src/xmss_core_fast.c src/xmss_commons.c src/xmss_hash.c \
 *   src/wots.c src/params.c src/fips202.c src/utils.c src/hash_address.c \
 *   src/randombytes.c -lssl -lcrypto -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "xmss.h"
#include "params.h"
#include "xmss_core.h"

static const uint32_t OID_XMSS_SHA2_10_256 = 0x00000001;

/* Provide xmss_sha256/xmss_sha512 using OpenSSL */
void xmss_sha256(const unsigned char* in, unsigned long long inlen, unsigned char* out) {
    SHA256(in, (size_t)inlen, out);
}
void xmss_sha512(const unsigned char* in, unsigned long long inlen, unsigned char* out) {
    SHA512(in, (size_t)inlen, out);
}

static void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static void print_hex_file(FILE* fp, const char* label, const unsigned char* data, size_t len) {
    fprintf(fp, "%s: ", label);
    for (size_t i = 0; i < len; i++)
        fprintf(fp, "%02x", data[i]);
    fprintf(fp, "\n");
}

int main(void) {
    xmss_params params;
    int ret;

    printf("========================================\n");
    printf("QNT Genesis Key Generator\n");
    printf("XMSS-SHA2_10_256\n");
    printf("========================================\n\n");

    /* Parse parameters */
    ret = xmss_parse_oid(&params, OID_XMSS_SHA2_10_256);
    if (ret != 0) {
        fprintf(stderr, "ERROR: xmss_parse_oid failed\n");
        return 1;
    }

    printf("Parameters:\n");
    printf("  n=%u, full_height=%u, tree_height=%u\n", params.n, params.full_height, params.tree_height);
    printf("  sig_bytes=%u, sk_bytes=%u, pk_bytes=%u\n\n", params.sig_bytes, params.sk_bytes, params.pk_bytes);

    /* Allocate key buffers */
    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];

    /* Verify entropy */
    printf("Checking entropy...\n");
    unsigned char test_rand[32];
    if (RAND_bytes(test_rand, 32) != 1) {
        fprintf(stderr, "ERROR: RAND_bytes failed — insufficient entropy\n");
        return 1;
    }
    printf("  [OK]   /dev/urandom is available\n\n");

    /* Generate key pair */
    printf("Generating XMSS key pair (this may take 10-30 seconds)...\n");
    ret = xmss_keypair(pk, sk, OID_XMSS_SHA2_10_256);
    if (ret != 0) {
        fprintf(stderr, "ERROR: xmss_keypair failed\n");
        return 1;
    }
    printf("  [OK]   Key pair generated\n\n");

    /* Display public key */
    printf("=== GENESIS PUBLIC KEY ===\n");
    print_hex("pubkey (full)", pk, XMSS_OID_LEN + params.pk_bytes);
    print_hex("pubkey (root||PUB_SEED)", pk + XMSS_OID_LEN, params.pk_bytes);
    printf("\n");

    /* Display key info */
    printf("=== KEY INFO ===\n");
    printf("  OID: 0x%08x\n", OID_XMSS_SHA2_10_256);
    printf("  Max signatures: 1024 (2^10)\n");
    printf("  Security level: 256-bit\n");
    printf("  Hash function: SHA-256\n");
    printf("  Standard: NIST SP 800-208\n\n");

    /* Save keys to file */
    const char* keyfile = "qnt_genesis_key.txt";
    FILE* fp = fopen(keyfile, "w");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot open %s for writing\n", keyfile);
        return 1;
    }

    fprintf(fp, "========================================\n");
    fprintf(fp, "QNT Genesis Key — PRIVATE — KEEP SECURE\n");
    fprintf(fp, "========================================\n");
    fprintf(fp, "Generated: QNT Genesis Block\n");
    fprintf(fp, "Algorithm: XMSS-SHA2_10_256\n");
    fprintf(fp, "Standard: NIST SP 800-208\n");
    fprintf(fp, "Max sigs: 1024\n");
    fprintf(fp, "Security: 256-bit\n\n");
    print_hex_file(fp, "seckey (full)", sk, XMSS_OID_LEN + params.sk_bytes);
    print_hex_file(fp, "pubkey (full)", pk, XMSS_OID_LEN + params.pk_bytes);
    print_hex_file(fp, "pubkey (raw, 64-byte)", pk + XMSS_OID_LEN, params.pk_bytes);
    fprintf(fp, "\n=== END ===\n");
    fclose(fp);

    printf("=== PRIVATE KEY SAVED ===\n");
    printf("  File: %s\n", keyfile);
    printf("  WARNING: Keep this file SECURE and OFFLINE\n");
    printf("  Anyone with this file can sign as genesis\n\n");

    /* Verify key works */
    printf("Verifying key...\n");
    const char* test_msg = "QNT Genesis Block — First mineable post-quantum blockchain";
    unsigned char sm[params.sig_bytes + strlen(test_msg) + 256];
    unsigned long long smlen = 0;
    ret = xmss_sign(sk, sm, &smlen, (const unsigned char*)test_msg, strlen(test_msg));
    if (ret != 0) {
        fprintf(stderr, "ERROR: xmss_sign failed\n");
        return 1;
    }

    unsigned char m_out[256];
    unsigned long long mlen_out = 0;
    ret = xmss_sign_open(m_out, &mlen_out, sm, smlen, pk);
    if (ret != 0) {
        fprintf(stderr, "ERROR: xmss_sign_open failed\n");
        return 1;
    }
    printf("  [OK]   Genesis key signature verified\n\n");

    printf("========================================\n");
    printf("Genesis key generation COMPLETE\n");
    printf("========================================\n");
    printf("\nNext step: Mine genesis block with this key\n");

    return 0;
}
