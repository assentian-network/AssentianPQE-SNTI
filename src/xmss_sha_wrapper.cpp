// SNTI: SHA256/SHA512 C wrapper for XMSS
// Provides OpenSSL-compatible SHA256/SHA512 using Bitcoin's implementation
#include <stdint.h>
#include <stddef.h>

#include "crypto/sha256.h"
#include "crypto/sha512.h"

extern "C" {

void xmss_sha256(const unsigned char* in, unsigned long long inlen, unsigned char* out) {
    CSHA256 sha;
    sha.Write(in, (size_t)inlen);
    sha.Finalize(out);
}

void xmss_sha512(const unsigned char* in, unsigned long long inlen, unsigned char* out) {
    CSHA512 sha;
    sha.Write(in, (size_t)inlen);
    sha.Finalize(out);
}

} // extern "C"
