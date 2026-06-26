/*
This code was taken from the SPHINCS reference implementation and is public domain.
Modified for SNTI: replaced static fd with getrandom() syscall for thread safety.
*/

#include <unistd.h>
#include <sys/random.h>

void randombytes(unsigned char *x, unsigned long long xlen)
{
    while (xlen > 0) {
        size_t chunk = (xlen > 256) ? 256 : (size_t)xlen;
        ssize_t ret = getrandom(x, chunk, 0);
        if (ret < 0) continue;
        x += ret;
        xlen -= ret;
    }
}
