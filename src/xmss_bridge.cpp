// Copyright (c) 2025 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xmss_bridge.h"

#include <cstring>
#include <algorithm>
#include <cstdlib>

extern "C" {
#include "xmss.h"
}

namespace XMSS {

// Helper: Build a pk with OID prefix from raw 64-byte pubkey.
// xmss_sign_open expects pk = [OID(4) || root(32) || PUB_SEED(32)]
static std::vector<uint8_t> MakePKWithOID(const uint8_t* pubkey_64, uint32_t oid)
{
    std::vector<uint8_t> pk(4 + 64);
    // OID in big-endian
    pk[0] = (oid >> 24) & 0xFF;
    pk[1] = (oid >> 16) & 0xFF;
    pk[2] = (oid >> 8) & 0xFF;
    pk[3] = oid & 0xFF;
    std::memcpy(pk.data() + 4, pubkey_64, 64);
    return pk;
}

void CXMSSKey::SecureClear(void* ptr, size_t len)
{
    if (ptr && len > 0) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (len--) {
            *p++ = 0;
        }
    }
}

CXMSSKey::CXMSSKey()
    : m_pk(nullptr), m_sk(nullptr), m_pk_len(0), m_sk_len(0), m_has_key(false)
{
}

CXMSSKey::~CXMSSKey()
{
    Clear();
}

CXMSSKey::CXMSSKey(CXMSSKey&& other) noexcept
    : m_pk(other.m_pk), m_sk(other.m_sk),
      m_pk_len(other.m_pk_len), m_sk_len(other.m_sk_len),
      m_has_key(other.m_has_key)
{
    other.m_pk = nullptr;
    other.m_sk = nullptr;
    other.m_pk_len = 0;
    other.m_sk_len = 0;
    other.m_has_key = false;
}

CXMSSKey& CXMSSKey::operator=(CXMSSKey&& other) noexcept
{
    if (this != &other) {
        Clear();
        m_pk = other.m_pk;
        m_sk = other.m_sk;
        m_pk_len = other.m_pk_len;
        m_sk_len = other.m_sk_len;
        m_has_key = other.m_has_key;
        other.m_pk = nullptr;
        other.m_sk = nullptr;
        other.m_pk_len = 0;
        other.m_sk_len = 0;
        other.m_has_key = false;
    }
    return *this;
}

bool CXMSSKey::Generate()
{
    Clear();

    // Use dynamic OID (default: XMSS-SHA2_10_256)
    uint32_t oid = XMSS_OID_SHA2_10_256;
    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        return false;
    }

    // sk format: [OID(4) | index_bytes | SK_SEED(n) | SK_PRF(n) | PUB_SEED(n) | root(n)]
    // pk format: [OID(4) | root(n) | PUB_SEED(n)]
    size_t sk_buf_size = 4 + params.sk_bytes;  // +4 for OID prefix
    size_t pk_buf_size = 4 + params.pk_bytes;  // +4 for OID prefix

    m_sk = static_cast<unsigned char*>(std::malloc(sk_buf_size));
    m_pk = static_cast<unsigned char*>(std::malloc(pk_buf_size));
    if (!m_sk || !m_pk) {
        Clear();
        return false;
    }

    std::memset(m_sk, 0, sk_buf_size);
    std::memset(m_pk, 0, pk_buf_size);
    m_sk_len = sk_buf_size;
    m_pk_len = pk_buf_size;

    // xmss_keypair writes OID into pk and sk buffers
    int ret = xmss_keypair(m_pk, m_sk, oid);
    if (ret != 0) {
        Clear();
        return false;
    }

    m_has_key = true;
    return true;
}

bool CXMSSKey::Sign(const std::vector<uint8_t>& hash, std::vector<uint8_t>& sig)
{
    if (!m_has_key || !m_sk) {
        return false;
    }

    if (hash.size() != 256 / 8) {
        return false;
    }

    // Parse OID from sk to get params
    uint32_t oid = (static_cast<uint32_t>(m_sk[0]) << 24)
                 | (static_cast<uint32_t>(m_sk[1]) << 16)
                 | (static_cast<uint32_t>(m_sk[2]) << 8)
                 |  static_cast<uint32_t>(m_sk[3]);

    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        return false;
    }

    // xmss_sign expects:
    //   sm = output buffer large enough for sig + msg
    //   On output, *smlen = total bytes written
    // The output sm format is: [signature || message]
    // Use dynamic sig_bytes from params, not hardcoded size
    unsigned long long sig_msg_size = 0;
    size_t sm_buf_size = params.sig_bytes + hash.size() + 256; // generous buffer
    std::vector<unsigned char> sm(sm_buf_size, 0);

    int ret = xmss_sign(
        m_sk,
        sm.data(), &sig_msg_size,
        hash.data(), static_cast<unsigned long long>(hash.size())
    );

    if (ret != 0 || sig_msg_size < params.sig_bytes) {
        // Clear partial output on failure
        std::memset(sm.data(), 0, sm_buf_size);
        return false;
    }

    // Extract just the signature from the beginning of sm
    sig.assign(sm.begin(), sm.begin() + (size_t)sig_msg_size - hash.size());

    // Clear the temporary buffer
    std::memset(sm.data(), 0, sm_buf_size);

    return true;
}

bool CXMSSKey::Verify(const std::vector<uint8_t>& hash,
                      const std::vector<uint8_t>& sig,
                      const std::vector<uint8_t>& pubkey_bytes)
{
    if (hash.empty() || sig.empty()) {
        return false;
    }

    // Default OID for verify
    uint32_t oid = XMSS_OID_SHA2_10_256;

    // SNTI FIX (17/Jun/2026): the reference xmssmt_core_sign_open() writes
    // into m at offset params.sig_bytes (it uses the tail of the output
    // buffer as scratch space for message-hash computation), then copies
    // the actual message into the front. The output buffer m therefore
    // MUST be at least params.sig_bytes + message_length bytes, not just
    // message_length. Allocating only hash.size() here caused a heap
    // buffer overflow on every single call to Verify(), corrupting the
    // allocator and crashing intermittently a few mallocs later (visible
    // under Valgrind as "Invalid read ... inside an unallocated block").
    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        return false;
    }

    // Build pk with OID prefix from the 64-byte raw pubkey.
    std::vector<uint8_t> pk = MakePKWithOID(pubkey_bytes.data(), oid);

    // xmss_sign_open expects:
    //   sm = [signature || message] as one concatenated buffer
    //   pk = [OID(4) || root(32) || PUB_SEED(32)]
    // On success, it extracts the message from sm into output m.
    std::vector<unsigned char> sm(sig.size() + hash.size());
    std::memcpy(sm.data(), sig.data(), sig.size());
    std::memcpy(sm.data() + sig.size(), hash.data(), hash.size());

    unsigned long long mlen = 0;
    // Must be at least params.sig_bytes + hash.size() — see comment above.
    std::vector<unsigned char> m(params.sig_bytes + hash.size(), 0);

    int ret = xmss_sign_open(
        m.data(), &mlen,
        sm.data(), static_cast<unsigned long long>(sm.size()),
        pk.data()
    );

    bool ok = (ret == 0) &&
              (mlen == hash.size()) &&
              (std::memcmp(m.data(), hash.data(), hash.size()) == 0);

    // Clean up temp buffers
    std::memset(sm.data(), 0, sm.size());
    std::memset(m.data(), 0, m.size());
    std::memset(pk.data(), 0, pk.size());

    return ok;
}

std::vector<uint8_t> CXMSSKey::GetPubKey() const
{
    if (!m_has_key || !m_pk || m_pk_len < 4 + 64) {
        return {};
    }

    // m_pk has format [OID(4) || root(32) || PUB_SEED(32)]
    // Return just [root(32) || PUB_SEED(32)] = 64 bytes
    const uint8_t* pubkey_data = m_pk + 4; // skip OID
    std::vector<uint8_t> pubkey(pubkey_data, pubkey_data + 64);
    return pubkey;
}

std::vector<uint8_t> CXMSSKey::GetPrivKey() const
{
    if (!m_has_key || !m_sk || m_sk_len == 0) {
        return {};
    }

    // Return the full secret key buffer (includes OID prefix)
    std::vector<uint8_t> sk(m_sk, m_sk + m_sk_len);
    return sk;
}

bool CXMSSKey::Load(const std::vector<uint8_t>& sk_bytes)
{
    Clear();

    if (sk_bytes.size() < 4) {
        return false;
    }

    // Copy the serialized secret key
    m_sk_len = sk_bytes.size();
    m_sk = static_cast<unsigned char*>(std::malloc(m_sk_len));
    if (!m_sk) {
        return false;
    }
    std::memcpy(m_sk, sk_bytes.data(), m_sk_len);

    // Parse OID from sk
    uint32_t oid = (static_cast<uint32_t>(m_sk[0]) << 24)
                 | (static_cast<uint32_t>(m_sk[1]) << 16)
                 | (static_cast<uint32_t>(m_sk[2]) << 8)
                 |  static_cast<uint32_t>(m_sk[3]);

    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        Clear();
        return false;
    }

    // Reconstruct the public key from the secret key.
    // sk format: [OID(4) | index_bytes | SK_SEED(n) | SK_PRF(n) | PUB_SEED(n) | root(n) | state...]
    // root is at offset: 4 + index_bytes + 2*n
    // PUB_SEED is at offset: 4 + index_bytes + 3*n
    size_t root_offset = 4 + params.index_bytes + 2 * params.n;
    size_t pubseed_offset = 4 + params.index_bytes + 3 * params.n;

    if (m_sk_len < root_offset + params.n) {
        // Not enough data for basic XMSS key
        Clear();
        return false;
    }

    // Allocate pk buffer: [OID(4) || root(n) || PUB_SEED(n)]
    m_pk_len = 4 + params.pk_bytes;
    m_pk = static_cast<unsigned char*>(std::malloc(m_pk_len));
    if (!m_pk) {
        Clear();
        return false;
    }

    // Copy OID from sk
    std::memcpy(m_pk, m_sk, 4);

    // Copy root and PUB_SEED
    std::memcpy(m_pk + 4, m_sk + root_offset, params.n);         // root
    std::memcpy(m_pk + 4 + params.n, m_sk + pubseed_offset, params.n); // PUB_SEED

    m_has_key = true;
    return true;
}

void CXMSSKey::Clear()
{
    if (m_pk) {
        SecureClear(m_pk, m_pk_len);
        std::free(m_pk);
        m_pk = nullptr;
    }
    m_pk_len = 0;

    if (m_sk) {
        SecureClear(m_sk, m_sk_len);
        std::free(m_sk);
        m_sk = nullptr;
    }
    m_sk_len = 0;

    m_has_key = false;
}

namespace {
void LocalSecureClear(void* ptr, size_t len)
{
    if (ptr && len > 0) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (len--) {
            *p++ = 0;
        }
    }
}
} // anonymous namespace

bool ComputeRootFromSeed(const std::vector<uint8_t>& seed96, std::vector<uint8_t>& out_root)
{
    if (seed96.size() != 96) return false;

    uint32_t oid = XMSS_OID_SHA2_10_256;
    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) return false;

    size_t sk_buf_size = 4 + params.sk_bytes;
    size_t pk_buf_size = 4 + params.pk_bytes;

    std::vector<uint8_t> pk(pk_buf_size, 0);
    std::vector<uint8_t> sk(sk_buf_size, 0);
    std::vector<uint8_t> seed_copy(seed96); // xmss_seed_keypair() takes non-const seed

    int ret = xmss_seed_keypair(pk.data(), sk.data(), oid, seed_copy.data());
    LocalSecureClear(sk.data(), sk.size());
    LocalSecureClear(seed_copy.data(), seed_copy.size());
    if (ret != 0) return false;

    // pk format: [OID(4) | root(32) | PUB_SEED(32)] -- root starts right after OID
    out_root.assign(pk.begin() + 4, pk.begin() + 4 + 32);
    return true;
}

} // namespace XMSS
