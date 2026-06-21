#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include "xmss_bridge.h"

int main(void) {
    printf("Step 1: Generate\n"); fflush(stdout);
    {
        XMSS::CXMSSKey key;
        if (!key.Generate()) { printf("FAIL\n"); return 1; }
        printf("Step 1 OK\n"); fflush(stdout);

        std::vector<uint8_t> pubkey = key.GetPubKey();
        printf("Step 2 OK (pk=%zu)\n", pubkey.size()); fflush(stdout);

        std::vector<uint8_t> hash(32, 42);
        std::vector<uint8_t> sig;
        key.Sign(hash, sig);
        printf("Step 3 OK (sig=%zu)\n", sig.size()); fflush(stdout);

        key.Verify(hash, sig, pubkey);
        printf("Step 4 OK\n"); fflush(stdout);

        printf("About to exit scope (destructor)...\n"); fflush(stdout);
    }
    printf("Destructor done\n"); fflush(stdout);
    printf("ALL OK\n");
    return 0;
}
