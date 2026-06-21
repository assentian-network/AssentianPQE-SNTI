// Copyright (c) 2025 The Quant developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/xmss_address.h>

#include <base58.h>
#include <util/strencodings.h>

#include <vector>

namespace XMSSAddr {

std::string Encode(const std::vector<uint8_t>& xmss_pubkey, bool testnet)
{
    if (xmss_pubkey.size() != 64) return {};

    uint160 h = Hash(xmss_pubkey);

    uint8_t version = testnet ? XMSS_PUBKEY_VERSION_TESTNET : XMSS_PUBKEY_VERSION_MAINNET;

    // Build payload: [version(1) || hash(20)]
    std::vector<unsigned char> data;
    data.reserve(21);
    data.push_back(version);
    data.insert(data.end(), h.begin(), h.end());

    return EncodeBase58Check(data);
}

bool Decode(const std::string& str, uint160& hash, bool testnet)
{
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(str, data, 21)) return false;

    uint8_t expected_version = testnet ? XMSS_PUBKEY_VERSION_TESTNET : XMSS_PUBKEY_VERSION_MAINNET;
    if (data.size() != 21) return false;
    if (data[0] != expected_version) return false;

    std::copy(data.begin() + 1, data.end(), hash.begin());
    return true;
}

bool IsValid(const std::string& str, bool testnet)
{
    uint160 hash;
    return Decode(str, hash, testnet);
}

} // namespace XMSSAddr
