#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include "xmss_bridge.h"

int main(void) {
    printf("Step 1: Generate\n"); fflush(stdout);
    XMSS::CXMSSKey key;
    if (!key.Generate()) { printf("FAIL\n"); return 1; }
    printf("Step 1 OK\n"); fflush(stdout);

    printf("Step 2: GetPubKey\n"); fflush(stdout);
    std::vector<uint8_t> pubkey = key.GetPubKey();
    printf("Step 2 OK (size=%zu)\n", pubkey.size()); fflush(stdout);

    printf("Step 3: hash\n"); fflush(stdout);
    std::vector<uint8_t> hash(32);
    for (int i = 0; i < 32; i++) hash[i] = (unsigned char)i;
    printf("Step 3 OK\n"); fflush(stdout);

    printf("Step 4: Sign\n"); fflush(stdout);
    std::vector<uint8_t> sig;
    if (!key.Sign(hash, sig)) { printf("FAIL sign\n"); return 1; }
    printf("Step 4 OK (sig=%zu)\n", sig.size()); fflush(stdout);

    printf("Step 5: Verify\n"); fflush(stdout);
    if (!key.Verify(hash, sig, pubkey)) { printf("FAIL verify\n"); return 1; }
    printf("Step 5 OK\n"); fflush(stdout);

    printf("Step 6: Sign#2\n"); fflush(stdout);
    std::vector<uint8_t> sig2;
    if (!key.Sign(hash, sig2)) { printf("FAIL sign2\n"); return 1; }
    printf("Step 6 OK (sig2=%zu)\n", sig2.size()); fflush(stdout);

    printf("Step 7: Verify#2\n"); fflush(stdout);
    if (!key.Verify(hash, sig2, pubkey)) { printf("FAIL verify2\n"); return 1; }
    printf("Step 7 OK\n"); fflush(stdout);

    printf("Step 8: GetPrivKey\n"); fflush(stdout);
    std::vector<uint8_t> sk = key.GetPrivKey();
    printf("Step 8 OK (sk=%zu)\n", sk.size()); fflush(stdout);

    printf("Step 9: wrong hash\n"); fflush(stdout);
    std::vector<uint8_t> wh(32, 0xFF);
    key.Verify(wh, sig, pubkey);
    printf("Step 9 OK\n"); fflush(stdout);

    printf("ALL OK\n");
    return 0;
}
