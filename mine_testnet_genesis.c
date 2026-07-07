// Mine QNT testnet genesis block with LOW difficulty
// Uses bits=0x207fffff (same as Bitcoin regtest) for instant mining
// This is for TESTNET ONLY - mainnet will use real difficulty

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/sha.h>

static void double_sha256(const unsigned char *data, size_t len, unsigned char *out) {
    unsigned char tmp[32];
    SHA256(data, len, tmp);
    SHA256(tmp, 32, out);
}

static void uint32_to_le(uint32_t val, unsigned char *out) {
    out[0] = val & 0xff;
    out[1] = (val >> 8) & 0xff;
    out[2] = (val >> 16) & 0xff;
    out[3] = (val >> 24) & 0xff;
}

int main(void) {
    // QNT testnet genesis XMSS pubkey
    unsigned char xmss_pubkey[64] = {
        0x8c, 0x5c, 0x7e, 0x72, 0xfb, 0x9a, 0x7b, 0x07,
        0xe7, 0xfb, 0x52, 0x62, 0xab, 0xc7, 0x9c, 0x6e,
        0x32, 0x1d, 0xda, 0xaf, 0x27, 0xe3, 0x3e, 0xbe,
        0xd6, 0xb9, 0xc3, 0xa0, 0x64, 0x8a, 0x2d, 0x08,
        0xd0, 0xe7, 0x04, 0xfa, 0xf3, 0x1f, 0x0a, 0x29,
        0xb5, 0x34, 0x63, 0x02, 0x6e, 0x7e, 0xd8, 0x5d,
        0x0a, 0x37, 0x21, 0x35, 0x42, 0x38, 0x82, 0xc9,
        0x96, 0x77, 0x0c, 0x8a, 0x97, 0x4e, 0xf1, 0x53
    };

    uint32_t timestamp = (uint32_t)time(NULL);
    uint32_t bits = 0x207fffff;  // LOW difficulty for testnet (like Bitcoin regtest)
    uint32_t version = 1;

    // Build simplified coinbase tx hash
    unsigned char tx[512];
    int pos = 0;
    uint32_to_le(1, tx + pos); pos += 4;  // version
    tx[pos++] = 1;  // vin count
    memset(tx + pos, 0, 32); pos += 32;  // prevout hash
    memset(tx + pos, 0xff, 4); pos += 4;  // prevout index
    const char *ts = "Quant Testnet Genesis 11/Jun/2026";
    tx[pos++] = 1 + strlen(ts);
    tx[pos++] = 1;
    memcpy(tx + pos, ts, strlen(ts)); pos += strlen(ts);
    memset(tx + pos, 0xff, 4); pos += 4;  // sequence
    tx[pos++] = 1;  // vout count
    uint64_t value = 5000000000LL;
    memcpy(tx + pos, &value, 8); pos += 8;
    tx[pos++] = 67;  // script len (1+64+1+1)
    tx[pos++] = 0x41;  // push 64 bytes
    memcpy(tx + pos, xmss_pubkey, 64); pos += 64;
    tx[pos++] = 0xBB;  // OP_XMSS_CHECKSIG
    memset(tx + pos, 0, 4); pos += 4;  // locktime

    unsigned char tx_hash[32], merkle_root[32];
    double_sha256(tx, pos, tx_hash);
    memcpy(merkle_root, tx_hash, 32);

    // Build header
    unsigned char header[80];
    pos = 0;
    uint32_to_le(version, header + pos); pos += 4;
    memset(header + pos, 0, 32); pos += 32;  // prev hash
    memcpy(header + pos, merkle_root, 32); pos += 32;
    uint32_to_le(timestamp, header + pos); pos += 4;
    uint32_to_le(bits, header + pos); pos += 4;
    memset(header + pos, 0, 4); pos += 4;  // nonce

    printf("QNT Testnet Genesis Miner (low difficulty)\n");
    printf("Timestamp: %u\n", timestamp);
    printf("Bits: 0x%08x\n", bits);
    printf("Merkle: ");
    for (int i = 0; i < 32; i++) printf("%02x", merkle_root[i]);
    printf("\n\n");

    // Target for 0x207fffff: 0x7fffff0000000000000000000000000000000000000000000000000000000000
    unsigned char target[32];
    memset(target, 0, 32);
    target[3] = 0x7f;
    target[4] = 0xff;
    target[5] = 0xff;

    uint32_t nonce = 0;
    unsigned char hash[32];

    while (1) {
        uint32_to_le(nonce, header + 76);
        double_sha256(header, 80, hash);

        int valid = 1;
        for (int i = 31; i >= 0; i--) {
            if (hash[i] < target[i]) { valid = 1; break; }
            if (hash[i] > target[i]) { valid = 0; break; }
        }

        if (valid) {
            printf("FOUND! nonce=%u\n", nonce);
            printf("Hash: ");
            for (int i = 31; i >= 0; i--) printf("%02x", hash[i]);
            printf("\n\n");
            printf("=== UPDATE chainparams.cpp (CTestNetParams) ===\n");
            printf("genesis = CreateGenesisBlock(%u, %u, 0x%08x, 1, 50 * COIN);\n",
                   timestamp, nonce, bits);
            printf("consensus.hashGenesisBlock = uint256S(\"");
            for (int i = 31; i >= 0; i--) printf("%02x", hash[i]);
            printf("\");\n");
            break;
        }

        nonce++;
        if (nonce == 0) {
            printf("FAILED: nonce overflow\n");
            return 1;
        }
    }

    return 0;
}
