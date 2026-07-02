// Copyright (c) 2025 The Assentian-PQE developers
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
// ── SNTI R3: Quantum security analysis ────────────────────────────────────────
//
// XMSS provides post-quantum signing security (hash-based, no discrete log or
// factoring assumptions). However, address privacy under a quantum adversary
// depends on which script output type is used:
//
// P2XMSS (bare pubkey in output):
//   scriptPubKey = <64-byte-pubkey> OP_XMSS_CHECKSIG
//   ❌ The full 64-byte pubkey is visible on-chain in the UNSPENT output.
//      A sufficiently powerful quantum computer could attempt a preimage attack
//      on the XMSS root (break tree structure), though this would require
//      breaking SHA-256 preimage resistance (2^256 classical, 2^128 post-Grover).
//      This is considered safe for at least the next 20–30 years.
//
// P2XMSSHASH (hash-committed — RECOMMENDED for quantum-grade privacy):
//   scriptPubKey = OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_XMSS_CHECKSIG
//   ✓ Only HASH160(pubkey) is in the unspent output — the pubkey is hidden.
//   ✓ The pubkey is revealed only AT SPEND TIME, in the scriptSig.
//   ✓ Since XMSS addresses are one-time-use (H7/retired model), the window
//     between spend broadcast and confirmation is the only exposure period.
//   ✓ Grover's algorithm reduces RIPEMD160 preimage resistance from 160-bit
//     to 80-bit, which is currently considered acceptable but watch post-2035.
//
// Remaining quantum privacy gaps (SNTI R3 future work):
//   1. Transaction graph is fully public — no confidential amounts, no stealth.
//   2. Change output to a non-XMSS address leaks metadata.
//   3. A fault-tolerant quantum computer with ~2 300 logical qubits could break
//      RIPEMD160 in ~1 hour (estimated 2040+). Mitigation: upgrade address hash
//      to SHA3-256 (256-bit security → 128-bit post-Grover) in a future fork.
//   4. Privacy layer (Mimblewimble / Confidential Transactions / ZK proofs)
//      is NOT implemented — transaction amounts are visible.
//
// Recommendation: always use P2XMSSHASH outputs for receive addresses.
// The sendtoxmssaddress RPC uses P2XMSSHASH when the recipient pubkey is
// unknown, and P2XMSS only when paying our own wallet (pubkey already known).
//

namespace XMSSAddr {

// XMSS uses bech32m witness version 2 (v0=P2WPKH, v1=Taproot, v2=XMSS).
// Addresses: snti1z... (mainnet), tsnti1z... (testnet), sntirt1z... (regtest).
static constexpr int    XMSS_WITNESS_VERSION   = 2;
static constexpr size_t XMSS_ADDRESS_HASH_SIZE = 20;  // RIPEMD160 output

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
 * Encode a 64-byte XMSS public key as a bech32m address using the given HRP.
 * Result format: <hrp>1z<bech32m-data>
 */
std::string Encode(const std::vector<uint8_t>& xmss_pubkey, const std::string& hrp);

/**
 * Decode a bech32m XMSS address back to the 20-byte hash.
 * Returns false if not a valid XMSS address for the given HRP.
 */
bool Decode(const std::string& str, uint160& hash, const std::string& hrp);

/**
 * Validate that a string is a valid XMSS bech32m address for the given HRP.
 */
bool IsValid(const std::string& str, const std::string& hrp);

} // namespace XMSSAddr

#endif // BITCOIN_WALLET_XMSS_ADDRESS_H
