#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
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

    /* Sign #2 stateful */
    std::vector<uint8_t> sig2;
    key.Sign(hash, sig2);
    key.Verify(hash, sig2, pubkey);

    /* Wrong hash reject */
    std::vector<uint8_t> wh(32, 0xFF);
    if (key.Verify(wh, sig, pubkey)) {
        printf("FAIL: wrong hash accepted\n");
        _exit(1);
    }

    printf("sig=%zu pk=%zu\n", sig.size(), pubkey.size());
    printf("ALL OK\n");
    fflush(stdout);
    _exit(0);
}
