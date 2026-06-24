// Copyright (c) 2025 The Quant developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_XMSS_ADDRESS_H
#define BITCOIN_WALLET_XMSS_ADDRESS_H

#include <hash.h>
#include <script/script.h>
#include <uint256.h>

#include <string>
#include <vector>

//
// SNTI XMSS Address Encoding
//
// XMSS public keys are 64 bytes (root || PUB_SEED), which is fundamentally
// different from ECDSA (33/65 bytes) or Schnorr (32 bytes).
//
// We define a XMSS address as:
//   Base58Check(0x60 || RIPEMD160(SHA256(xmss_pubkey64)))
//
// This produces a 21-byte payload (1 version + 20 hash) — the same structure
// as P2PKH but with a different version byte so XMSS addresses are distinct.
//
// Mainnet addresses will start with 'q' (lowercase, distinguishable from 'Q'
// used by legacy P2PKH which uses version 0x51).
//
// For regtest/testnet we use version 0x80 (starts with 'q' in base58).
//
// The 64-byte full public key is required for verification — the address
// alone only contains the hash. The full pubkey is stored in the wallet
// and included in the scriptPubKey (P2XMSS output).
//

namespace XMSSAddr {

// Version bytes for Base58Check encoding
static constexpr uint8_t XMSS_PUBKEY_VERSION_MAINNET = 0x60;  // 96
static constexpr uint8_t XMSS_PUBKEY_VERSION_TESTNET = 0x80;   // 128
static constexpr uint8_t XMSS_PUBKEY_VERSION_REGTEST  = 0x80;   // 128
static constexpr size_t  XMSS_ADDRESS_HASH_SIZE       = 20;      // RIPEMD160 output

/**
 * Compute the 20-byte address hash from a 64-byte XMSS public key.
 * HASH160(pubkey) = RIPEMD160(SHA256(pubkey))
 */
inline uint160 Hash(const std::vector<uint8_t>& xmss_pubkey)
{
    assert(xmss_pubkey.size() == 64);
    uint160 hash;
    CHash160().Write(xmss_pubkey).Finalize(hash);
    return hash;
}

/**
 * Encode a 64-byte XMSS public key as a Base58Check address.
 * Pass true for testnet to use testnet version byte.
 */
std::string Encode(const std::vector<uint8_t>& xmss_pubkey, bool testnet = false);

/**
 * Decode a XMSS Base58Check address back to the 20-byte hash.
 * Returns false if the string is not a valid XMSS address.
 */
bool Decode(const std::string& str, uint160& hash, bool testnet = false);

/**
 * Validate that a string is a valid XMSS address (correct version byte,
 * correct length, valid checksum).
 */
bool IsValid(const std::string& str, bool testnet = false);

} // namespace XMSSAddr

#endif // BITCOIN_WALLET_XMSS_ADDRESS_H
