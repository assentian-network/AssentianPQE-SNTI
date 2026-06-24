// SNTI: SHA256/SHA512 compatibility header (C-compatible)
// Declares wrapper functions that replace OpenSSL SHA256/SHA512
#ifndef BITCOIN_XMSS_SHA_COMPAT_H
#define BITCOIN_XMSS_SHA_COMPAT_H

#include <stdint.h>

// OpenSSL-compatible function signatures
// These are implemented in xmss_sha_wrapper.cpp using Bitcoin's CSHA256/CSHA512
extern void xmss_sha256(const unsigned char* in, unsigned long long inlen, unsigned char* out);
extern void xmss_sha512(const unsigned char* in, unsigned long long inlen, unsigned char* out);

// Map OpenSSL names to our wrappers
#define SHA256(in, inlen, out) xmss_sha256((in), (inlen), (out))
#define SHA512(in, inlen, out) xmss_sha512((in), (inlen), (out))

#endif // BITCOIN_XMSS_SHA_COMPAT_H
