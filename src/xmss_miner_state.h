// Copyright (c) 2026 The Assentian-PQE developers
// SNTI PoUW v2 — XMSS Miner State (persistent leaf tracking)
//
// Menyimpan SK dan leafIndex ke disk agar:
// 1. Leaf tidak di-reuse setelah restart
// 2. Tree 1024 leaves dipakai untuk 1024 block sebelum rebuild
// 3. Mencegah WOTS+ key reuse (catastrophic jika terjadi)

#ifndef ASSENTIAN_XMSS_MINER_STATE_H
#define ASSENTIAN_XMSS_MINER_STATE_H

#include <util/fs.h>
#include <logging.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <fcntl.h>
#include <unistd.h>

extern "C" {
#include "xmss.h"
#include "params.h"
}

// pouw_v2.h defines XMSS_OID, PoUWv2Proof, R_BYTES, WOTS_SIG_BYTES, AUTH_PATH_BYTES
// which are used below. Include explicitly so this header is self-contained (audit fix #8).
#include <pouw_v2.h>

#include <array>
#include <cstring>
#include <fstream>
#include <mutex>
#include <vector>

namespace PoUWv2 {

// SK size untuk XMSS-SHA2_10_256 dengan OID prefix:
// OID(4) + idx(4) + SK_SEED(32) + SK_PRF(32) + PUB_SEED(32) + root(32) = 136 bytes
static constexpr size_t MINER_SK_BYTES = 2048; // BDS state included (fast impl ~1373 bytes)
static constexpr uint32_t XMSS_MAX_LEAVES = 1024; // 2^10
static constexpr uint32_t STATE_MAGIC = 0x534E5432; // "SNT2"
// SNTI SECURITY FIX (audit KRITIS #6, 2 Jul 2026): v2 adds ownerStamp, a
// per-datadir instance ID recording which machine/process last wrote this
// state. See xmss_tree_ledger.cpp for the check this enables. v1 files (no
// ownerStamp) still load fine -- STATE_VERSION_MIN_COMPAT guards that.
static constexpr uint32_t STATE_VERSION = 2;
static constexpr uint32_t STATE_VERSION_MIN_COMPAT = 1;
static constexpr size_t OWNER_STAMP_BYTES = 16;

struct XMSSMinerState {
    uint32_t magic   = STATE_MAGIC;
    uint32_t version = STATE_VERSION;
    uint256  xmssRoot;                    // Root dari tree aktif
    uint32_t nextLeafIndex = 0;           // Leaf berikutnya yang akan dipakai
    uint32_t skLen = 0;                   // Panjang SK aktual
    std::vector<uint8_t> sk;             // Secret key dengan BDS state (termasuk OID)
    // KRITIS #6: which datadir/instance last claimed a leaf from this tree.
    // All-zero = legacy file (pre-v2) or never claimed yet -- not a conflict.
    std::array<uint8_t, OWNER_STAMP_BYTES> ownerStamp{};

    bool IsValid() const {
        return magic == STATE_MAGIC &&
               version >= STATE_VERSION_MIN_COMPAT && version <= STATE_VERSION &&
               !xmssRoot.IsNull() &&
               nextLeafIndex < XMSS_MAX_LEAVES &&
               skLen > 0 &&
               sk.size() == skLen;
    }

    bool IsExhausted() const {
        return nextLeafIndex >= XMSS_MAX_LEAVES;
    }

    // Serialize ke disk. Always writes the current STATE_VERSION and
    // ownerStamp -- callers that loaded a legacy v1 file should bump
    // `version = STATE_VERSION` before re-saving (xmss_tree_ledger.cpp does
    // this), so a resaved file is always fully v2 on disk.
    std::vector<uint8_t> Serialize() const {
        DataStream ds{};
        ds << magic << version;
        ds << xmssRoot;
        ds << nextLeafIndex;
        ds << skLen;
        ds.write(MakeByteSpan(sk));
        ds.write(MakeByteSpan(ownerStamp));
        return {UCharCast(ds.data()), UCharCast(ds.data() + ds.size())};
    }

    bool Deserialize(const std::vector<uint8_t>& data) {
        try {
            DataStream ds{MakeByteSpan(data)};
            ds >> magic >> version;
            if (magic != STATE_MAGIC) return false;
            if (version < STATE_VERSION_MIN_COMPAT || version > STATE_VERSION) return false;
            ds >> xmssRoot;
            ds >> nextLeafIndex;
            ds >> skLen;
            if (skLen == 0 || skLen > MINER_SK_BYTES) return false;
            sk.resize(skLen);
            ds.read(MakeWritableByteSpan(sk));
            ownerStamp.fill(0);
            if (version >= 2) {
                ds.read(MakeWritableByteSpan(ownerStamp));
            }
            return true;
        } catch (...) {
            return false;
        }
    }
};

// ── XMSSMinerStateManager ────────────────────────────────────────────────────
// Thread-safe manager untuk load/save state ke disk
class XMSSMinerStateManager {
public:
    explicit XMSSMinerStateManager(const fs::path& datadir)
        : m_state_path(datadir / "xmss_miner_state.dat") {}

    // Load state dari disk. Return false jika tidak ada / invalid.
    bool Load(XMSSMinerState& state) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!fs::exists(m_state_path)) return false;

        std::ifstream f(m_state_path, std::ios::binary);
        if (!f.is_open()) return false;

        std::vector<uint8_t> data(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>());

        if (!state.Deserialize(data)) {
            LogPrintf("XMSSMinerState: invalid state file, will regenerate\n");
            return false;
        }

        if (state.IsExhausted()) {
            LogPrintf("XMSSMinerState: tree exhausted (leaf %u/%u), will regenerate\n",
                      state.nextLeafIndex, XMSS_MAX_LEAVES);
            return false;
        }

        LogPrintf("XMSSMinerState: loaded, root=%s leaf=%u/%u\n",
                  state.xmssRoot.GetHex().substr(0, 16),
                  state.nextLeafIndex, XMSS_MAX_LEAVES);
        return true;
    }

    // Save state ke disk (atomic write via temp file + fsync)
    bool Save(const XMSSMinerState& state) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto tmp = m_state_path;
        tmp += ".tmp";

        std::vector<uint8_t> data = state.Serialize();

        int fd = open(fs::PathToString(tmp).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            LogPrintf("XMSSMinerState: failed to open temp file for write\n");
            return false;
        }
        ssize_t written = write(fd, data.data(), data.size());
        if (written < 0 || static_cast<size_t>(written) != data.size()) {
            LogPrintf("XMSSMinerState: write failed\n");
            close(fd);
            return false;
        }
        // Flush kernel buffer ke storage sebelum rename — mencegah leaf reuse jika crash
        if (fsync(fd) != 0) {
            LogPrintf("XMSSMinerState: fsync failed\n");
            close(fd);
            return false;
        }
        close(fd);

        // Atomic rename
        fs::rename(tmp, m_state_path);
        return true;
    }

    // Hapus state (saat chain reorg atau wipe)
    void Reset() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (fs::exists(m_state_path)) {
            fs::remove(m_state_path);
            LogPrintf("XMSSMinerState: state reset\n");
        }
    }

    fs::path GetPath() const { return m_state_path; }

private:
    fs::path m_state_path;
    std::mutex m_mutex;
};

// ── BuildNewTree ─────────────────────────────────────────────────────────────
// Build XMSS tree baru dari random seed, simpan SK ke state
// Dipanggil saat state kosong atau exhausted
inline bool BuildNewTree(XMSSMinerState& state) {
    xmss_params params;
    if (xmss_parse_oid(&params, XMSS_OID) != 0) return false;

    // SK size dengan OID: 4 + params.sk_bytes (include BDS state dari xmss_core_fast)
    // xmss_core_fast sk_bytes ~1373 bytes untuk height=10
    size_t sk_len = 4 + (size_t)params.sk_bytes;
    size_t pk_len = 4 + params.pk_bytes; // with OID

    std::vector<uint8_t> pk(pk_len + 64, 0); // safety buffer
    std::vector<uint8_t> sk(sk_len + 64, 0); // safety buffer

    // Generate fresh key pair
    int ret = xmss_keypair(pk.data(), sk.data(), XMSS_OID);
    if (ret != 0) {
        LogPrintf("XMSSMinerState: xmss_keypair failed ret=%d\n", ret);
        return false;
    }

    // Extract root from PK (skip 4-byte OID prefix)
    // PK format (with OID): OID(4) | root(32) | PUB_SEED(32)
    uint256 root;
    memcpy(root.begin(), pk.data() + 4, 32);

    state.xmssRoot     = root;
    state.nextLeafIndex = 0;
    state.sk           = std::vector<uint8_t>(sk.begin(), sk.begin() + sk_len);
    state.skLen        = sk_len;
    state.magic        = STATE_MAGIC;
    state.version      = STATE_VERSION;

    LogPrintf("XMSSMinerState: new tree built, root=%s\n",
              root.GetHex().substr(0, 16));
    return true;
}

// ── SignWithState ─────────────────────────────────────────────────────────────
// Sign block_hash menggunakan leaf state.nextLeafIndex
// Update SK setelah sign (leaf index di-increment di dalam xmss_sign)
// Caller wajib Save() state setelah success
inline bool SignWithState(XMSSMinerState& state,
                          const uint8_t* block_hash32,
                          PoUWv2Proof& proof)
{
    if (!state.IsValid() || state.IsExhausted()) return false;

    xmss_params params;
    if (xmss_parse_oid(&params, XMSS_OID) != 0) return false;

    // Verify SK leaf index matches our tracked index
    // SK format (with OID): OID(4) | idx(index_bytes=4) | SK_SEED(n) | ...
    uint32_t sk_idx = 0;
    const uint8_t* sk_data = state.sk.data();
    // Skip OID prefix (4 bytes), read idx (4 bytes big-endian)
    sk_idx = ((uint32_t)sk_data[4] << 24) |
             ((uint32_t)sk_data[5] << 16) |
             ((uint32_t)sk_data[6] <<  8) |
             ((uint32_t)sk_data[7]);
    LogPrintf("XMSSMinerState: SK internal idx=%u state.nextLeafIndex=%u sk_len=%zu\n",
              sk_idx, state.nextLeafIndex, state.sk.size());

    if (sk_idx != state.nextLeafIndex) {
        LogPrintf("XMSSMinerState: SK leaf mismatch! sk=%u state=%u\n",
                  sk_idx, state.nextLeafIndex);
        return false;
    }

    const size_t sm_size = params.sig_bytes + 32 + 64;
    std::vector<uint8_t> sm(sm_size, 0);
    unsigned long long smlen = 0;

    // xmss_sign() dengan full SK (termasuk OID)
    // Ini akan increment leaf index di dalam SK secara otomatis
    LogPrintf("XMSSMinerState: calling xmss_sign sk_size=%zu sm_size=%zu\n",
              state.sk.size(), sm.size());
    int ret = xmss_sign(state.sk.data(), sm.data(), &smlen, block_hash32, 32);
    LogPrintf("XMSSMinerState: xmss_sign done ret=%d smlen=%llu\n", ret, (unsigned long long)smlen);
    if (ret != 0) {
        LogPrintf("XMSSMinerState: xmss_sign failed ret=%d\n", ret);
        return false;
    }

    // Parse signature: [idx(4) | R(32) | WOTS_sig(2144) | auth_path(320)]
    size_t off = 4; // skip leaf index in sig
    memcpy(proof.r,         sm.data() + off, R_BYTES);          off += R_BYTES;
    memcpy(proof.wots_sig,  sm.data() + off, WOTS_SIG_BYTES);   off += WOTS_SIG_BYTES;
    memcpy(proof.auth_path, sm.data() + off, AUTH_PATH_BYTES);

    // SK fast format: OID(4) | idx(4) | SK_SEED(32) | SK_PRF(32) | root(32) | PUB_SEED(32) | BDS(...)
    // Seed material stays private to the miner — NOT written to proof (C1 fix).
    size_t sk_prf_off     = 4 + params.index_bytes + params.n;  // 4+4+32=40
    size_t sk_root_off    = sk_prf_off + params.n;              // 40+32=72
    size_t sk_pubseed_off = sk_root_off + params.n;             // 72+32=104

    // xmss_pk = root(32) | PUB_SEED(32)
    memcpy(proof.xmss_pk,      state.xmssRoot.begin(), 32);
    memcpy(proof.xmss_pk + 32, sk_data + sk_pubseed_off, params.n);

    // Increment our tracked leaf index
    state.nextLeafIndex++;

    return true;
}

} // namespace PoUWv2

#endif // ASSENTIAN_XMSS_MINER_STATE_H
