// Copyright (c) 2025 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/xmss_address.h>

#include <bech32.h>
#include <util/strencodings.h>

#include <vector>

namespace XMSSAddr {

std::string Encode(const std::vector<uint8_t>& xmss_pubkey, const std::string& hrp)
{
    if (xmss_pubkey.size() != 64) return {};

    uint160 h = Hash(xmss_pubkey);

    // Build bech32m payload: [witness_version(5-bit)] + ConvertBits<8→5>(hash160)
    std::vector<unsigned char> enc;
    enc.push_back(static_cast<unsigned char>(XMSS_WITNESS_VERSION));
    ConvertBits<8, 5, true>([&](unsigned char c) { enc.push_back(c); }, h.begin(), h.end());

    return bech32::Encode(bech32::Encoding::BECH32M, hrp, enc);
}

bool Decode(const std::string& str, uint160& hash, const std::string& hrp)
{
    const auto dec = bech32::Decode(str);
    if (dec.encoding != bech32::Encoding::BECH32M) return false;
    if (dec.hrp != hrp) return false;
    if (dec.data.empty() || static_cast<int>(dec.data[0]) != XMSS_WITNESS_VERSION) return false;

    std::vector<unsigned char> data;
    if (!ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); },
                                   dec.data.begin() + 1, dec.data.end())) return false;
    if (data.size() != XMSS_ADDRESS_HASH_SIZE) return false;

    std::copy(data.begin(), data.end(), hash.begin());
    return true;
}

bool IsValid(const std::string& str, const std::string& hrp)
{
    uint160 hash;
    return Decode(str, hash, hrp);
}

} // namespace XMSSAddr
