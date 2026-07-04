// Copyright (c) 2026 The Assentian-PQE developers
// SNTI PoUW v2 — Failed Seed Key Derivation
//
// Miner collects 10-20 failed SK_SEEDs during mining loop.
// Their Merkle root is committed in block header (commitmentsRoot).
// Full seed list embedded in coinbase OP_RETURN for node verification.

#ifndef ASSENTIAN_POUW_V2_KEYDER_H
#define ASSENTIAN_POUW_V2_KEYDER_H

#include <hash.h>
#include <uint256.h>
#include <cstring>
#include <vector>

namespace PoUWv2KeyDer {

// ── Constants ────────────────────────────────────────────────────────────────
static constexpr size_t SEED_BYTES       = 96;   // SK_SEED + SK_PRF + PUB_SEED
static constexpr size_t MAX_FAILED_SEEDS = 20;
static constexpr size_t MIN_FAILED_SEEDS = 10;

// Magic for coinbase OP_RETURN seed list
static constexpr uint8_t SEEDS_MAGIC[4] = {'F','S','L',0x01}; // Failed Seed List v1

// ── FailedSeedList ───────────────────────────────────────────────────────────
// Container for 10-20 failed seeds per block
struct FailedSeedList {
    struct Entry {
        uint8_t sk_seed[SEED_BYTES];   // Original failed SK_SEED
        uint8_t xmss_root[32];         // Root of the failed tree
        uint8_t commitment[32];        // SHA256(root || seed || height)
    };

    std::vector<Entry> entries;
    uint32_t block_height{0};

    void AddFailedSeed(const uint8_t* sk_seed, const uint8_t* xmss_root, uint32_t height) {
        if (entries.size() >= MAX_FAILED_SEEDS) return;
        Entry e;
        memcpy(e.sk_seed, sk_seed, SEED_BYTES);
        memcpy(e.xmss_root, xmss_root, 32);
        block_height = height;

        // Compute commitment
        uint8_t height_be[4];
        height_be[0] = (height >> 24) & 0xFF;
        height_be[1] = (height >> 16) & 0xFF;
        height_be[2] = (height >>  8) & 0xFF;
        height_be[3] =  height        & 0xFF;

        CHash256 hasher;
        hasher.Write({xmss_root, 32});
        hasher.Write({sk_seed, SEED_BYTES});
        hasher.Write({height_be, 4});
        uint256 h;
        hasher.Finalize(h);
        memcpy(e.commitment, h.begin(), 32);

        entries.push_back(e);
    }

    // Compute Merkle root of all commitments
    uint256 ComputeMerkleRoot() const {
        if (entries.empty()) return uint256();
        std::vector<uint256> leaves;
        for (const auto& e : entries) {
            uint256 leaf;
            memcpy(leaf.begin(), e.commitment, 32);
            leaves.push_back(leaf);
        }
        // Simple binary Merkle tree
        while (leaves.size() > 1) {
            std::vector<uint256> next;
            for (size_t i = 0; i < leaves.size(); i += 2) {
                CHash256 h;
                h.Write({leaves[i].begin(), 32});
                if (i + 1 < leaves.size()) {
                    h.Write({leaves[i+1].begin(), 32});
                } else {
                    h.Write({leaves[i].begin(), 32}); // duplicate last
                }
                uint256 parent;
                h.Finalize(parent);
                next.push_back(parent);
            }
            leaves = next;
        }
        return leaves[0];
    }

    // Serialize for coinbase OP_RETURN
    // Format: MAGIC(4) | count(1) | height(4) | [sk_seed(96) | xmss_root(32)](×N)
    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> out;
        out.insert(out.end(), SEEDS_MAGIC, SEEDS_MAGIC + 4);
        out.push_back((uint8_t)entries.size());
        // height BE4
        out.push_back((block_height >> 24) & 0xFF);
        out.push_back((block_height >> 16) & 0xFF);
        out.push_back((block_height >>  8) & 0xFF);
        out.push_back( block_height        & 0xFF);
        for (const auto& e : entries) {
            out.insert(out.end(), e.sk_seed, e.sk_seed + SEED_BYTES);
            out.insert(out.end(), e.xmss_root, e.xmss_root + 32);
        }
        return out;
    }

    // Deserialize from coinbase OP_RETURN data
    bool Deserialize(const uint8_t* data, size_t len) {
        if (len < 9) return false;
        if (memcmp(data, SEEDS_MAGIC, 4) != 0) return false;
        size_t count = data[4];
        if (count < MIN_FAILED_SEEDS || count > MAX_FAILED_SEEDS) return false;
        block_height = ((uint32_t)data[5] << 24) | ((uint32_t)data[6] << 16) |
                       ((uint32_t)data[7] <<  8) |  (uint32_t)data[8];
        size_t expected = 9 + count * (SEED_BYTES + 32);
        if (len < expected) return false;

        entries.clear();
        size_t off = 9;
        for (size_t i = 0; i < count; i++) {
            Entry e;
            memcpy(e.sk_seed,   data + off, SEED_BYTES); off += SEED_BYTES;
            memcpy(e.xmss_root, data + off, 32);         off += 32;
            // Recompute commitment
            uint8_t height_be[4];
            height_be[0] = (block_height >> 24) & 0xFF;
            height_be[1] = (block_height >> 16) & 0xFF;
            height_be[2] = (block_height >>  8) & 0xFF;
            height_be[3] =  block_height        & 0xFF;
            CHash256 hasher;
            hasher.Write({e.xmss_root, 32});
            hasher.Write({e.sk_seed, SEED_BYTES});
            hasher.Write({height_be, 4});
            uint256 h;
            hasher.Finalize(h);
            memcpy(e.commitment, h.begin(), 32);
            entries.push_back(e);
        }
        return true;
    }

    // Verify: recompute Merkle root and compare with header
    bool VerifyAgainstHeader(const uint256& header_commitments_root) const {
        if (entries.size() < MIN_FAILED_SEEDS) return false;
        return ComputeMerkleRoot() == header_commitments_root;
    }
};

} // namespace PoUWv2KeyDer

#endif // ASSENTIAN_POUW_V2_KEYDER_H
