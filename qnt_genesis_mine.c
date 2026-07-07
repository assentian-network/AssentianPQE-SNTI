#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

int main(void) {
    unsigned char header[80];
    memset(header, 0, 80);

    unsigned char target[32];
    memset(target, 0, 32);
    target[4] = 0x7f;
    target[5] = 0xff;
    target[6] = 0xff;

    printf("Starting mining test...\n");
    printf("Target: ");
    for (int i = 0; i < 32; i++) printf("%02x", target[i]);
    printf("\n\n");

    time_t start = time(NULL);
    uint32_t nonce = 0;
    unsigned char hash[32];

    while (1) {
        memcpy(header + 76, &nonce, 4);
        SHA256(header, 80, hash);
        SHA256(hash, 32, hash);

        /* Simple check: first 4 bytes must be 0x00000000 and byte 5 < 0x7f */
        if (hash[0] == 0 && hash[1] == 0 && hash[2] == 0 && hash[3] == 0 && hash[4] < 0x7f) {
            printf("FOUND! nonce=%u\n", nonce);
            printf("Hash: ");
            for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
            printf("\n");
            break;
        }

        nonce++;
        if (nonce == 1000000) {
            time_t now = time(NULL);
            printf("1M hashes in %ld seconds (%.0f H/s)\n", (long)(now-start), 1000000.0/(now-start));
        }
        if (nonce == 10000000) {
            time_t now = time(NULL);
            printf("10M hashes in %ld seconds (%.0f H/s)\n", (long)(now-start), 10000000.0/(now-start));
            break;
        }
    }

    return 0;
}
