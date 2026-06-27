# FINDINGS LOG — Assentian-PQE / SNTI
# Audit Keamanan & Kesiapan Mainnet
# Tanggal: 27 Jun 2026 | Auditor: Internal Review + Claude Code
# Diurutkan: CRITICAL → HIGH → MEDIUM → LOW → FUTURE RISK

---

## STATUS RINGKAS

| Severity  | Total | Fixed | Open |
|-----------|-------|-------|------|
| CRITICAL  |   5   |   3   |   2  |
| HIGH      |   8   |   5   |   3  |
| MEDIUM    |   7   |   0   |   7  |
| LOW       |   4   |   0   |   4  |
| FUTURE    |   5   |   0   |   5  |
| **TOTAL** | **29**| **8** |**21**|

Referensi commit fix: `7ec14ed` (26 Jun 2026)

---

---

## ■■■ CRITICAL — BLOCKER MAINNET ■■■

---

### [C1] SK_SEED Private Key Terekspos di Coinbase OP_RETURN
- **Status:** ✓ FIXED — 27 Jun 2026
- **File:** `src/pouw_v2.h`, `src/xmss_miner_state.h`
- **Ditemukan:** 27 Jun 2026 (audit mendalam)

**Apa yang terjadi:**
`PoUWv2Proof::Serialize()` menulis `seed[96]` — yaitu `SK_SEED + SK_PRF + PUB_SEED`
— langsung ke coinbase `OP_RETURN` yang ter-broadcast ke seluruh network dan tersimpan
di blockchain selamanya.

Ini adalah **materi kunci privat penuh** untuk XMSS tree yang digunakan mining.

**Dampak:**
Siapapun yang membaca blockchain bisa:
1. Ekstrak `seed[96]` dari coinbase output
2. Panggil `xmssmt_core_seed_keypair(seed)` → rekonstruksi secret key penuh
3. Tandatangani dengan semua 1024 leaf yang tersisa di tree tersebut
4. Kalau miner menggunakan tree yang sama sebagai wallet key → **dana bisa dicuri**

**Mengapa verifier tidak butuh seed:**
`CheckPoUWv2()` hanya menggunakan `xmss_pk + auth_path + wots_sig + r`.
Field `seed[SEED_BYTES]` di struct **tidak pernah dibaca saat verifikasi**.
Ini berarti 96 byte tersebut adalah **pure poison** — tidak berguna, sangat berbahaya.

**Fix yang diterapkan:**
- `src/pouw_v2.h`: Hapus `uint8_t seed[SEED_BYTES]` dari `PoUWv2Proof`.
  Hapus dari `Serialize()` dan `Deserialize()`.
  `SERIAL_SIZE` diupdate: `4+64+320+2144+32 = 2564 bytes` (dari 2660).
- `src/xmss_miner_state.h`: Hapus 3 baris `memcpy(proof.seed, ...)` dan
  variabel `sk_seed_off`. Seed tetap ada di memori miner tapi tidak ditulis ke proof.
- `pouw_v2_keyder.h`: Tidak perlu diubah — `dk.seed` adalah struct berbeda (`DerivedKey`).
- Build: **PASS** — tidak ada error/warning.

**Effort realisasi:** <1 jam

---

### [C2] commitmentsRoot Tidak Pernah Diverifikasi
- **Status:** ✗ OPEN — BELUM DIPERBAIKI
- **File:** `src/validation.cpp` (CheckPoUW, line 3902-4020), `src/primitives/block.h:38-40`
- **Ditemukan:** 27 Jun 2026

**Apa yang terjadi:**
Block header punya field `commitmentsRoot` (uint256, 32 byte). Field ini:
- Ada di `CBlockHeader` (block.h:40)
- Di-serialize ke LevelDB (chain.h:210, 264, 440)
- Di-broadcast lewat P2P

Tapi `CheckPoUW()` di `validation.cpp` **tidak pernah memeriksa** apakah Merkle root
dari failed seeds yang di-embed di coinbase cocok dengan `commitmentsRoot` di header.
Grep `commitmentsRoot` di `validation.cpp` → nol hasil.

**Dampak:**
- Miner bisa isi `commitmentsRoot` = `0x000...000` atau random → block **tetap diterima**
- Fitur `pouw_v2_keyder.h` (key derivation dari failed seeds) bisa di-spoof sepenuhnya
- 32 byte di setiap block header = **sampah tidak terverifikasi**

**Fix:**
Di `CheckPoUW()` setelah `v2_ok` check, tambahkan:
1. Parse semua failed seeds dari coinbase `OP_RETURN`
2. Hitung Merkle root dari seeds tersebut
3. Tolak block jika `computed_root != block.commitmentsRoot`

**Effort:** 4 jam

---

### [C3] vFixedSeeds Di-clear Setelah Di-assign (Mainnet Zero Seed Nodes)
- **Status:** ✓ FIXED — commit `7ec14ed` (26 Jun 2026)
- **File:** `src/kernel/chainparams.cpp` line 170 (dihapus)

**Apa yang terjadi:**
```cpp
vFixedSeeds = std::vector<uint8_t>(chainparams_seed_main, ...);  // line 158
// ...
vFixedSeeds.clear();  // line 170 — BUG: langsung dihapus lagi
```
Node baru tidak punya seed node sama sekali. Chain tidak bisa sync dari nol.

**Fix yang diterapkan:** Baris `vFixedSeeds.clear()` di line 170 (mainnet section) dihapus.
Node 104.234.26.7 sekarang tersedia sebagai seed.

**Catatan:** `vFixedSeeds.clear()` di testnet section (line 248, sebelum assign) adalah
pattern yang benar dan tidak bermasalah.

---

### [C4] Signature Chunking Hardcoded 2500 Bytes — Locks ke Satu OID
- **Status:** ✗ OPEN — BELUM DIPERBAIKI
- **File:** `src/script/interpreter.cpp:1095-1097`
- **Ditemukan:** Audit awal

**Apa yang terjadi:**
```cpp
static const unsigned int XMSS_SIG_CHUNK_SIZE = 500;
static const unsigned int XMSS_SIG_NUM_CHUNKS = 5;  // 5 × 500 = 2500 bytes
```
Hanya bekerja untuk `XMSS-SHA2_10_256` (sig = 2500 byte, kebetulan cocok).

**Dampak:**
- `XMSS-SHA2_16_256` → sig 2696+ byte → **transaksi gagal**
- `XMSS-SHA2_20_256` → sig 3348+ byte → **transaksi gagal**
- Kode mendukung OID lain tapi script layer memblok penggunaannya

**Fix:** Gunakan witness data untuk signature (SegWit-style), atau dynamic-length script
handler berdasarkan `params.sig_bytes` yang dibaca dari OID di signature.

**Effort:** 1–2 hari (butuh redesign script handling)

---

### [C5] PermittedDifficultyTransition Salah Total untuk EMA
- **Status:** ✓ FIXED — commit `7ec14ed` (26 Jun 2026)
- **File:** `src/pow.cpp:63-87`

**Apa yang terjadi:**
Fungsi lama memakai Bitcoin-style `smallest_timespan = nPowTargetTimespan/4 = 15s` dan
`largest_timespan = nPowTargetTimespan*4 = 240s`. Di mainnet EMA per-block, ini akan
menolak hampir setiap block valid yang nBits-nya berubah sesuai EMA.

**Fix yang diterapkan:** Fungsi direwrite. Sekarang validasi band ±4x dari target lama:
```cpp
arith_uint256 max_target = old_target * 4;
arith_uint256 min_target = old_target / 4;
```
Membolehkan swing EMA yang legitimate, menolak yang di luar batas reasonable.

---

---

## ■■ HIGH — RISIKO SERIUS ■■

---

### [H1] Wallet Tidak Flush ke Disk Setelah XMSS Sign
- **Status:** ✓ FIXED — 27 Jun 2026
- **File:** `src/wallet/wallet.cpp:PersistXMSSState()`, `src/wallet/xmss_keystore.h`
- **Ditemukan:** Audit mendalam 27 Jun 2026

**Klarifikasi setelah investigasi:**
`CXMSSKeyStore::Sign()` (yang disebut di audit awal) ternyata **dead code** — tidak ada
satu pun caller di seluruh codebase. Jalur signing aktual adalah:
`CXMSSSigner::SignXMSS()` → `CWallet::PersistXMSSState()` di `wallet.cpp:2195`.

`PersistXMSSState()` sudah menulis state ke `WalletBatch`, tapi hanya sampai ke DB buffer
layer. Crash antara `WriteXmssState()` dan database flush bisa meninggalkan stale state
di disk — leaf_index di memori sudah advance tapi disk masih yang lama.

**Fix yang diterapkan:**
- `wallet.cpp PersistXMSSState()`: scope `WalletBatch` ke dalam block `{}` agar destructs
  sebelum `GetDatabase().Flush()` dipanggil. `Flush()` memaksa fsync ke disk.
- `xmss_keystore.h CXMSSKeyStore::Sign()`: tambah komentar peringatan bahwa fungsi ini
  bukan jalur aktif dan butuh persist callback kalau ever digunakan.
- Build: **PASS**

**Effort realisasi:** 30 menit

---

### [H2] randombytes.c Thread-Unsafe (Static fd Global)
- **Status:** ✓ FIXED — commit `7ec14ed` (26 Jun 2026)
- **File:** `src/randombytes.c`

**Apa yang terjadi:**
```c
static int fd = -1;  // global, tanpa mutex
```
Dua thread parallel key generation bisa race pada `fd`. Salah satunya leak fd.

**Fix yang diterapkan:** Diganti dengan `getrandom()` syscall (Linux 3.17+):
```c
ssize_t ret = getrandom(x, chunk, 0);
```
Atomik, tidak ada global state, tidak ada race condition.

---

### [H3] SK Trim-Trailing-Zero — PARTIAL FIX (Satu File Masih Buggy)
- **Status:** ✓ FIXED — 27 Jun 2026
- **File:** `src/xmss_state.h:77-80` (namespace `QNT::XMSS`)
- **File ref:** `src/wallet/xmss_state.h` (sudah fix di commit `7ec14ed`, dijadikan referensi)

**Apa yang terjadi di file yang masih buggy:**
```cpp
size_t actual = 2048;
while (actual > 4 && m_sk[actual-1] == 0) actual--;  // ← masih ada
actual += 64;  // ← padding arbitrer
m_sk.resize(actual);
```
BDS state XMSS bisa punya trailing zero yang **legitimate**. Setelah save+load,
SK berbeda dari aslinya → signature gagal atau corrupt.

File `src/xmss_state.h` digunakan oleh **mining path** (xmss_miner_state).

**Fix yang diterapkan:**
- Tambah `#include "params.h"` ke blok `extern "C"` di `src/xmss_state.h`
- Replace `Generate()`: hapus `resize(2048)` + `while`-trim + `+= 64`;
  ganti dengan `xmss_parse_oid()` → `xp.sk_bytes` → `resize(QNT_XMSS_OID_LEN + sk_bytes)`
- Build: **PASS**

**Effort realisasi:** 5 menit

---

### [H4] malloc Tanpa Secure Clear untuk SK
- **Status:** ✓ FIXED — sudah ada sebelum audit ini
- **File:** `src/xmss_bridge.cpp:312-320`

`SecureClear(m_sk, m_sk_len)` sudah dipanggil sebelum `std::free(m_sk)` di destructor.
Tidak ada tindakan yang diperlukan.

---

### [H5] Testnet nPowTargetTimespan Mismatch → Testnet Tidak Menguji EMA
- **Status:** ✗ OPEN — BELUM DIPERBAIKI
- **File:** `src/kernel/chainparams.cpp:208`
- **Ditemukan:** Audit awal

**Apa yang terjadi:**
```
Testnet: nPowTargetTimespan = 14 * 24 * 60 * 60 = 1,209,600 (2 minggu)
Mainnet: nPowTargetTimespan = 60 (EMA per-block)
```
Testnet menggunakan Bitcoin-style 2016-block retarget. EMA behavior tidak pernah
diuji di testnet. Bug EMA yang terlewat di testnet bisa muncul di mainnet.

**Fix:** Set `consensus.nPowTargetTimespan = 60` di testnet section.

**Effort:** 30 menit

---

### [H6] Sighash Tanpa Chain ID → Replay Attack Testnet ke Mainnet
- **Status:** ✗ OPEN — BELUM DIPERBAIKI
- **File:** `src/script/sign.cpp:173-188`

**Apa yang terjadi:**
Sighash v2 (fix 21 Jun) menambah `leaf_index` ke sighash, tapi **tidak ada chain ID**:
```
sighash_v2 = SHA256(sighash_v1 || leaf_index_4_bytes_BE)
```
`pchMessageStart` berbeda antara mainnet (`0x53 0x4E 0x54 0x49`) dan testnet, tapi
ini hanya untuk P2P layer — tidak masuk ke transaction sighash.

**Dampak:** Transaksi yang valid di testnet bisa di-replay ke mainnet setelah launch
(dan sebaliknya). Serupa dengan insiden ETH/ETC 2016.

**Fix:**
```
sighash_v2 = SHA256(sighash_v1 || leaf_index_BE || SNTI_CHAIN_ID_BE)
```
Definisikan: `SNTI_CHAIN_ID_MAINNET = 1`, `SNTI_CHAIN_ID_TESTNET = 2`.

**Effort:** 2–4 jam

---

### [H7] Tidak Ada Mekanisme Auto-Rotate Key XMSS Saat Exhaustion
- **Status:** ✗ OPEN — temuan baru 27 Jun 2026
- **File:** `src/wallet/xmss_keystore.h:113-115`

**Apa yang terjadi:**
```cpp
if (entry.leaf_index >= 1024) {
    LogPrintf("CXMSSKeyStore::Sign: key exhausted ..., refusing to sign\n");
    return {};
}
```
Sign gagal silently (return kosong), tidak ada notify ke user, tidak ada auto-rotate,
tidak ada auto-transfer balance. User bisa stuck tidak bisa kirim transaksi tanpa tahu
penyebabnya. Saldo terkunci di key exhausted.

**Fix roadmap:**
- Warn user di `leaf_index == 900` (87.5% terpakai, 124 sigs tersisa)
- Auto-generate key baru di `leaf_index == 950` (pre-rotate, sebelum exhaustion)
- Setelah exhausted: auto-create transaksi transfer saldo ke key baru

**Effort:** 2–3 hari (butuh wallet UX + auto-transfer logic)

---

### [H8] PoUW v1 Path Masih Aktif, Tidak Ada Height-Gate
- **Status:** ✗ OPEN — temuan baru 27 Jun 2026
- **File:** `src/validation.cpp` CheckPoUW (v1 fallback path)

**Apa yang terjadi:**
`CheckPoUW()` menerima v1 (64-byte pubkey di OP_RETURN) DAN v2 (magic `PW2\x02`).
Tidak ada height-gated enforcement bahwa ab height tertentu **hanya v2 yang valid**.
Miner bisa terus submit v1 proof selamanya tanpa penalti.

**Dampak:**
- v1 proof tidak mengandung `commitmentsRoot` data → seluruh keyder feature tidak jalan
- Miner malicious bisa kirim v1 untuk bypass v2 validation rules
- Tidak ada cara deprecate v1 tanpa kode eksplisit

**Fix:** Tambah `nPoUWv2StartHeight` di `Consensus::Params`. Block >= height ini
yang kirim v1 proof → `BLOCK_CONSENSUS` rejected.

**Effort:** 2 jam

---

---

## ■ MEDIUM — PERLU DIPERBAIKI SEBELUM LAUNCH ■

---

### [M1] Empat Versi XMSS State Class — Mudah Desync
- **Status:** ✗ OPEN
- **File:** `xmss_keystore.h`, `xmss_signer.h`, `xmss_state.h` (×2), `xmss_miner_state.h`

5 file berbeda mengelola XMSS state dengan format serialisasi yang berbeda.
`SaveState/LoadState` di `xmss_signer.cpp` pakai magic "QNT2", `xmss_miner_state`
pakai format lain. Sangat mudah terjadi desync antara wallet dan mining state.

**Fix:** Konsolidasi ke 1 state manager class dengan 1 format serialisasi.

---

### [M2] Namespace dan Branding Tidak Konsisten: QNT/Quant/PoUWv2/XMSS/SNTI
- **Status:** ✗ OPEN
- **File:** Tersebar di seluruh codebase

Daftar inkonsistensi:
- `src/xmss_state.h` → `namespace QNT::XMSS`, header guard `QUANT_XMSS_STATE_H`
- `pouw.h` → `namespace QNT::PoUW`
- `xmss_miner_state.h` → `namespace PoUWv2`
- `xmss_bridge.h` → `namespace XMSS`
- `xmss_address.h` → `namespace XMSSAddr`
- `wallet/xmss_keystore.h` → copyright "The Quant developers"
- SaveState magic → `"QNT2"`

Project adalah SNTI/Assentian. Confusing untuk contributor baru.

---

### [M3] PoUW v1 Dead Code (pouw.h) Masih Ada di Repo
- **Status:** ✗ OPEN
- **File:** `src/pouw.h` (8267 bytes)

Tidak di-include dimanapun tapi masih ada di repo. `namespace QNT::PoUW` deprecated.
Menambah kebingungan dan ukuran repo.

---

### [M4] Nol Unit Test XMSS di src/test/
- **Status:** ✗ OPEN
- **File:** `src/test/` (kosong untuk XMSS)

Tidak ada satu pun test file di `src/test/` yang menguji:
- XMSS sign + verify round-trip
- State persistence (save/load leaf_index)
- Key exhaustion behavior
- PoUW v2 proof verification
- EMA difficulty calculation

Test yang ada hanya ad-hoc `.c/.cpp` di root repo, tidak terintegrasi dengan test runner.

---

### [M5] EMA Tanpa Dampening → Oscillation di Network Kecil
- **Status:** ✗ OPEN
- **File:** `src/pow.cpp` (CalcNextTargetEMA)

EMA `alpha=0.1` tanpa moving average window. Dengan 1–3 miner:
- 1 miner offline → block spacing 5+ menit → difficulty turun 30%+
- Miner kembali → blocks tiap 10 detik → difficulty naik 30%+
- Cycle sawtooth berulang, chain tidak stabil

Bitcoin pakai 2016-block window untuk smooth transition.

---

### [M6] OP_RETURN Size Policy Tidak Eksplisit untuk PoUW v2
- **Status:** ✗ OPEN

`MAX_OP_RETURN_RELAY = 83 bytes`. `PoUWv2Proof` = 2660 bytes. Coinbase OP_RETURN
harus dibebaskan dari limit ini tapi tidak ada definisi eksplisit di policy code.
Potensi integer underflow atau policy rejection di node yang strict.

---

### [M7] Leaf Reuse Scan Perlu Persistensi "Used Trees"
- **Status:** ✗ OPEN
- **File:** `src/validation.cpp:3986-4007`
- **Ditemukan:** 27 Jun 2026

Scan leaf reuse mundur 1024 block dan break saat ganti tree. Tapi miner yang menyimpan
seed dan memulai ulang tree dari index 0 (setelah ganti node/restart) bisa reuse
leaves dari tree yang sama tanpa terdeteksi kalau sudah >1024 block berlalu.

**Fix:** Simpan daftar `(xmssRoot, usedLeafBitmap)` di chainstate DB untuk tree yang
pernah digunakan. Tolak block kalau leaf sudah pernah dipakai di tree tersebut.

---

---

## □ LOW — MINOR / ACCEPTABLE PRE-MAINNET ■

---

### [L1] nMinimumChainWork = 0
- **Status:** ✗ OPEN (acceptable pre-launch)
- **File:** `src/kernel/chainparams.cpp:125, 223, 295, 302, 413`

Semua chain types: `consensus.nMinimumChainWork = uint256{}`. Rentan terhadap
long-range attack dari genesis. Wajib diupdate setelah mainnet punya ~10k blocks.

---

### [L2] Checkpoint Hanya Genesis Block
- **Status:** ✗ OPEN (acceptable pre-launch)

Hanya `{0, hashGenesisBlock}`. Tambah checkpoint setiap 10k blocks setelah mainnet.

---

### [L3] nNonce=0 Legacy Field di Block Header
- **Status:** ✗ OPEN (tunda post-launch)
- **File:** `src/primitives/block.h`

4 byte tidak terpakai di setiap block header. Menghapus butuh hard fork.
Low priority — tunda ke post-mainnet.

---

### [L4] Monitoring Leaf Index Miner Tidak Ada
- **Status:** ✗ OPEN
- **File:** `src/wallet/xmss_keystore.h`, RPC layer
- **Ditemukan:** 27 Jun 2026

Tidak ada RPC atau metric untuk:
- Sisa leaf index per mining key
- Warning saat mendekati exhaustion
- Prometheus metric untuk pool operator

`listxmsskeys` RPC ada tapi tidak diekspos ke miner via stratum.

**Fix:** Tambah field `remaining_signatures` dan `warning` di respons `listxmsskeys`.
Log `WARN` saat `remaining < 200`. Expose via stratum atau mining API.

**Effort:** 2 jam

---

---

## ◇ FUTURE RISK — POST-MAINNET ■

---

### [R1] Kapasitas Block Sangat Rendah (~357 tx/block vs Bitcoin ~10,000)

XMSS signature 2500 byte vs ECDSA 72 byte = ~34x lebih besar. Dengan block size
1MB: `(1MB - overhead) / 2500B ≈ 357 tx/block ≈ 6 tx/s`. Fee market akan sangat
ketat. Solusi: SegWit-style witness discount atau XMSS^MT.

---

### [R2] XMSS Key 1024 Signature Limit → UX Buruk Tanpa Auto-Rotate

Setiap key hanya 1024 signing operations. Tanpa auto-rotate (lihat H7), user yang
aktif akan exhausted dalam hitungan bulan. Perlu wallet-level key lifecycle management.

---

### [R3] Quantum Security Hanya di Signature, Bukan Privacy

XMSS mengamankan signing. Tapi:
- `address = RIPEMD160(SHA256(pubkey))` → quantum computer bisa derive pubkey dari address
- Transaction graph fully visible
- Tidak ada privacy layer (no Mimblewimble, no CT, no zero-knowledge proofs)

---

### [R4] Pool Mining Masih Proxy Model, Tidak Scalable

Stratum server pakai `generatetoaddress` proxy — block construction terjadi di `bitcoind`.
Tidak scalable untuk pool besar. Perlu `getblocktemplate` + `submitblock` full.

---

### [R5] Tidak Ada Hard Fork Governance

Tidak ada version bits, tidak ada miner signaling, tidak ada deployment height/window.
Kalau ada bug post-mainnet yang butuh fork, prosesnya manual dan berisiko split chain.

---

---

## RINGKASAN PRIORITAS KERJA

```
MINGGU INI (sebelum mainnet bisa dipertimbangkan):
  [C1] Hapus seed[] dari PoUWv2Proof                    2 jam
  [H3] Fix src/xmss_state.h trailing-zero (mining path) 30 mnt
  [H1] Wallet flush setelah XMSS sign                   1-2 jam
  [C2] Verifikasi commitmentsRoot di CheckPoUW           4 jam

MINGGU DEPAN:
  [H6] Chain ID di sighash (replay protection)           2-4 jam
  [H5] Testnet nPowTargetTimespan = 60                   30 mnt
  [H8] Height-gate PoUW v1 deprecation                   2 jam
  [H7] Auto-rotate key + UX warning exhaustion           2-3 hari

SEBELUM NETWORK LAUNCH:
  [C4] Dynamic signature chunking / witness              1-2 hari
  [M4] Unit tests XMSS di src/test/                     1-2 minggu
  [M7] Persistensi used-tree bitmap di chainstate        4 jam
  [L4] RPC remaining_signatures + warning               2 jam

POST-LAUNCH:
  M1/M2/M3 (cleanup), R1-R5 (scaling), L1/L2 (update setelah mainnet)
```

---

*Log ini dihasilkan dari inspeksi langsung kode sumber pada 27 Jun 2026.*
*Referensi: `test_audit.md` (analisis lengkap), commit `7ec14ed` (fix terbaru).*
