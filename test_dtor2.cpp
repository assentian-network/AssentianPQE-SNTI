#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include "xmss_bridge.h"

int main(void) {
    XMSS::CXMSSKey key;
    key.Generate();
    std::vector<uint8_t> pubkey = key.GetPubKey();
    std::vector<uint8_t> hash(32, 42);
    std::vector<uint8_t> sig;
    key.Sign(hash, sig);
    key.Verify(hash, sig, pubkey);
    printf("sig=%zu pk=%zu\n", sig.size(), pubkey.size());
    printf("ALL OK\n");
    fflush(stdout);
    return 0;
}
