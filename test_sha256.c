#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main(void) {
    unsigned char header[80];
    memset(header, 0, 80);
    uint32_t ver = 1;
    memcpy(header, &ver, 4);
    uint32_t nTime = 1749600000;
    memcpy(header + 68, &nTime, 4);
    uint32_t nBits = 0x20ffffff;
    memcpy(header + 72, &nBits, 4);
    uint32_t nonce = 0;
    memcpy(header + 76, &nonce, 4);

    unsigned char hash[32];
    SHA256(header, 80, hash);
    SHA256(hash, 32, hash);

    printf("Hash (nonce=0): ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    /* Target: first 4 bytes = 0, byte 5 < 0x7f */
    unsigned char target[32];
    memset(target, 0, 32);
    target[4] = 0x7f;
    target[5] = 0xff;
    target[6] = 0xff;

    printf("Target:         ");
    for (int i = 0; i < 32; i++) printf("%02x", target[i]);
    printf("\n");

    /* Check if hash < target */
    int valid = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] < target[i]) { valid = 1; break; }
        if (hash[i] > target[i]) { valid = 0; break; }
    }
    printf("Valid: %s\n", valid ? "YES" : "NO");

    /* Try a few nonces */
    for (uint32_t n = 1; n < 100; n++) {
        memcpy(header + 76, &n, 4);
        SHA256(header, 80, hash);
        SHA256(hash, 32, hash);
        valid = 1;
        for (int i = 0; i < 32; i++) {
            if (hash[i] < target[i]) { valid = 1; break; }
            if (hash[i] > target[i]) { valid = 0; break; }
        }
        if (valid) {
            printf("FOUND at nonce=%u! Hash: ", n);
            for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
            printf("\n");
            break;
        }
    }

    return 0;
}
