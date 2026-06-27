 =====================================================================

      AUDIT MENDALAM: Assentian-PQE / SNTI

      Mainnet Readiness & Security Review — 27 Jun 2026
      UPDATE: Rekonsiliasi dengan commit 7ec14ed (26 Jun 2026)

 =====================================================================



   ╔══════════════════════════════════════════════════════════════════════╗
   ║  LEGEND STATUS                                                       ║
   ║  ✓ FIXED    — Diperbaiki, diverifikasi dari kode aktual             ║
   ║  ✗ OPEN     — Belum diperbaiki per 27 Jun 2026                      ║
   ║  ~ PARTIAL  — Fix sebagian / satu file, file duplikat masih buggy   ║
   ╚══════════════════════════════════════════════════════════════════════╝



   ╔═════════════════════════════════════════════════════════════════════════╗
   ║  DIMENSION              STATUS   DONE  TOTAL  RISK     UPDATE         ║
   ╠═════════════════════════════════════════════════════════════════════════╣
   ║  1. Key State Mgmt      █████░░░  4/8     8    CRITICAL  H3~, H4✓    ║
   ║  2. Replay Protection   ████░░░░  3/6     6    CRITICAL  H6✗ tetap   ║
   ║  3. Eclipse / Peers     █░░░░░░░  1/6     6    CRITICAL               ║
   ║  4. Seed Node Infra     ████░░░░  3/5     5    HIGH      C3✓ FIXED   ║
   ║  5. Economic Model      ████░░░░  3/7     7    HIGH                   ║
   ║  6. Mining / Pool       ████░░░░  4/8     8    HIGH      C5✓, H2✓   ║
   ╚═════════════════════════════════════════════════════════════════════════╝



   VERDICT: TIDAK SIAP MAINNET.
   Sisa blocker setelah commit 7ec14ed: C1, C2, C4 (CRITICAL) + H1, H3~,
   H5, H6 (HIGH).

   =====================================================================



   ══════════════════════════════════════════════════════════════
   REKAP CEPAT: YANG SUDAH DIPERBAIKI (commit 7ec14ed, 26 Jun)
   ══════════════════════════════════════════════════════════════

   ✓ C3  vFixedSeeds.clear() di mainnet dihapus             (30 detik)
   ✓ C5  PermittedDifficultyTransition rewrite untuk EMA    (4-8 jam)
   ✓ H2  randombytes.c → getrandom() (thread-safe)          (2 jam)
   ✓ H4  SecureClear sebelum std::free(m_sk) di destructor  (sudah ada)
   ~  H3  wallet/xmss_state.h diperbaiki TAPI src/xmss_state.h MASIH BUGGY

   CATATAN: Commit 7ec14ed memakai penomoran C1/C2 internal yang BERBEDA
   dari audit ini. Jangan bingung — di commit itu "C1" = trim-trailing-zero
   (audit: H3), "C2" = exhaustion guard (tidak ada di audit awal).

   ══════════════════════════════════════════════════════════════
   YANG BELUM DIPERBAIKI (blocker mainnet tersisa)
   ══════════════════════════════════════════════════════════════

   ✗ C1  SK_SEED masih di coinbase OP_RETURN  ← KRITIS, belum disentuh
   ✗ C2  commitmentsRoot tidak diverifikasi   ← field ada, verifikasi tidak
   ✗ C4  Signature chunking hardcoded 2500 B  ← belum ada redesign
   ✗ H1  Wallet tidak flush setelah sign      ← tidak ada Flush() di Sign()
   ✗ H3  src/xmss_state.h masih trailing-zero trim (duplikat file)
   ✗ H5  Testnet nPowTargetTimespan salah (2-minggu bukan 60s)
   ✗ H6  Sighash tanpa chain ID (replay testnet→mainnet tetap bisa)

   =====================================================================




   BUG CRITICAL (BLOCKER MAINNET)
   ════════════════════════════════


   C1. SK_SEED Private Key Terekspos di Coinbase OP_RETURN   ✗ OPEN

   File: src/pouw_v2.h:47, 62, 74

   Status: BELUM DIPERBAIKI per 27 Jun 2026.
   seed[SEED_BYTES] masih ada di PoUWv2Proof dan masih di-serialize
   (Serialize() baris 62, Deserialize() baris 74). Verifikasi CheckPoUWv2()
   tidak pernah membaca field ini — 96 byte pure poison di setiap block.

   PoUWv2Proof.serialize() menulis seed[96] (SK_SEED + SK_PRF + PUB_SEED)
   langsung ke coinbase OP_RETURN. Ini MATERI KUNCI PRIVAT PENUH untuk
   XMSS tree yang digunakan mining.

   Siapapun bisa:
   1. Baca seed dari blockchain (public data)
   2. Rekonstruksi seluruh XMSS secret key
   3. Tandatangani dengan SEMUA 1024 leaves yang tersisa
   4. Kalau wallet address menggunakan tree yang sama = dana bisa dicuri

   Fix: Hapus seed[] dari PoUWv2Proof (struct, Serialize, Deserialize).
        Verifier hanya butuh xmss_pk + auth_path + wots_sig + r.
        Kalau perlu untuk key derivation, gunakan commitment scheme.

   Effort: 2 jam



   C2. commitmentsRoot TIDAK PERNAH DIVERIFIKASI             ✗ OPEN

   File: src/validation.cpp CheckPoUW() (line 3902-4020),
         src/primitives/block.h:38-40

   Status: Field commitmentsRoot ada di block header dan di-serialize ke
   LevelDB (block.h:40, chain.h:210, 226, 264, 440). Tapi CheckPoUW() di
   validation.cpp tidak pernah memverifikasi bahwa Merkle root dari failed
   seeds di coinbase cocok dengan header.commitmentsRoot.

   Bukti: Grep "commitmentsRoot" di validation.cpp → tidak ada check sama sekali.
   CheckPoUW() v2 path (line 3977) hanya memanggil CheckPoUWv2() lalu
   cek leaf reuse — commitmentsRoot diabaikan.

   Artinya:
   - Miner bisa tulis commitmentsRoot = random garbage → block diterima
   - Fitur "failed-seed key derivation" (pouw_v2_keyder.h) bisa di-spoof
   - 32 byte di setiap block header = sampah tidak terverifikasi

   Fix: Tambah di CheckPoUW (setelah v2_ok check):
        - Parse failed seeds dari coinbase OP_RETURN
        - Hitung Merkle root dari seeds tersebut
        - Tolak block jika != block.commitmentsRoot

   Effort: 4 jam



   C3. vFixedSeeds Di-clear Setelah Di-assign               ✓ FIXED

   File: src/kernel/chainparams.cpp
   Fixed: commit 7ec14ed (26 Jun 2026)

   Baris vFixedSeeds.clear() di line 170 (mainnet section) sudah dihapus.
   Verified: tidak ada .clear() antara line 158 (assign) dan base58Prefixes
   di bawahnya. Mainnet sekarang punya seed node 104.234.26.7.

   Catatan: vFixedSeeds.clear() di line 248 adalah bagian testnet section
   (sebelum assign), itu normal dan benar.

   Effort realisasi: 30 detik



   C4. Signature Chunking Hardcoded (2500 bytes)             ✗ OPEN

   File: src/script/interpreter.cpp:1095-1097

   Status: BELUM DIPERBAIKI.

   cpp
   static const unsigned int XMSS_SIG_CHUNK_SIZE = 500;
   static const unsigned int XMSS_SIG_NUM_CHUNKS = 5;  // 5 × 500 = 2500


   XMSS-SHA2_10_256 signature = 2500 bytes (kebetulan cocok). Tapi:
   - XMSS-SHA2_16_256 sig = 2696+ bytes → TRANSAKSI GAGAL
   - XMSS-SHA2_20_256 sig = 3348+ bytes → TRANSAKSI GAGAL
   - Tidak ada cara pakai parameter set lain meskipun kode mendukung OID lain

   Fix: Gunakan witness data untuk signature, atau dynamic-length script
        handler berdasarkan params.sig_bytes dari OID.

   Effort: 1-2 hari (butuh redesign script handling)



   C5. PermittedDifficultyTransition Salah Total untuk EMA   ✓ FIXED

   File: src/pow.cpp:63-87
   Fixed: commit 7ec14ed (26 Jun 2026)

   Fungsi telah direwrite. Sekarang:
   - Mengizinkan perubahan target dalam band ±4x (cocok dengan EMA alpha=0.1)
   - Menolak target > powLimit
   - Tidak lagi menggunakan Bitcoin-style window check yang salah

   Kode baru (verified):
   cpp
   arith_uint256 max_target = old_target * 4;
   if (max_target > pow_limit) max_target = pow_limit;
   arith_uint256 min_target = old_target / 4;
   if (observed_new_target > max_target) return false;
   if (observed_new_target < min_target) return false;


   Effort realisasi: diperkirakan 4-8 jam



   ═══════════════════════════════════════
   BUG HIGH (RISIKO SERIUS)
   ═══════════════════════════════════════


   H1. Wallet TIDAK Flush Setelah XMSS Sign                  ✗ OPEN

   File: src/wallet/xmss_keystore.h:128-133

   Status: BELUM DIPERBAIKI. Kode di Sign():
   cpp
   entry.leaf_index++;
   entry.seckey = key.GetPrivKey();
   return sig;   // ← tidak ada Flush() / persist ke disk

   Kalau node crash setelah sign tapi sebelum periodic flush:
   - SK lama di disk, leaf_index lama
   - Reload → sign lagi dengan leaf yang sama → WOTS+ KEY REUSE
   - Private key bisa direcovery dari dua signature dengan leaf sama

   Fix: Panggil wallet database write setelah entry update. Opsi:
        (a) Inject wallet DB handle ke CXMSSKeyStore::Sign()
        (b) Return "needs-persist" flag dan panggil Flush() di caller
        (c) Simpan leaf_index ke file terpisah yang sync setelah setiap sign

   Effort: 1-2 jam (tergantung arsitektur wallet DB access)



   H2. randombytes.c Thread-Unsafe                           ✓ FIXED

   File: src/randombytes.c
   Fixed: commit 7ec14ed (26 Jun 2026)

   Sekarang menggunakan getrandom() syscall (Linux 3.17+):
   c
   ssize_t ret = getrandom(x, chunk, 0);

   Static fd global sudah dihilangkan. Thread-safe secara atomik.

   Effort realisasi: 2 jam



   H3. SK Trim-Trailing-Zero                                  ~ PARTIAL

   File: src/wallet/xmss_state.h (FIXED), src/xmss_state.h (MASIH BUGGY)

   PERHATIAN: Ada DUA file xmss_state.h yang berbeda:

   wallet/xmss_state.h → SUDAH DIPERBAIKI (commit 7ec14ed):
   cpp
   // Allocate exactly the right size using params (no trailing-zero trimming)
   size_t sk_buf = QNT_XMSS_OID_LEN + (size_t)xp.sk_bytes;
   m_sk.resize(sk_buf, 0);

   src/xmss_state.h (namespace QNT::XMSS) → MASIH BUGGY (line 77-80):
   cpp
   size_t actual = 2048;
   while (actual > 4 && m_sk[actual-1] == 0) actual--;  // ← MASIH ADA
   actual += 64;  // ← padding arbitrer tetap ada
   m_sk.resize(actual);

   File src/xmss_state.h digunakan oleh xmss_miner_state dan stratum server.
   Bug ini TETAP ADA di mining path. Miner yang crash setelah banyak blocks
   bisa corrupt mining SK.

   Fix: Terapkan patch yang sama ke src/xmss_state.h:Generate() —
        gunakan xmss_parse_oid() + params.sk_bytes, hapus while-trim.

   Effort: 30 menit (copy paste dari wallet/xmss_state.h)



   H4. malloc Tanpa Secure Clear untuk SK                    ✓ FIXED

   File: src/xmss_bridge.cpp:312-320

   Status: SUDAH FIXED bahkan sebelum audit ini ditulis.
   Verified dari kode:
   cpp
   SecureClear(m_pk, m_pk_len);
   std::free(m_pk);
   // ...
   SecureClear(m_sk, m_sk_len);
   std::free(m_sk);

   SecureClear() dipanggil sebelum free di destructor path. OK.



   H5. Testnet nPowTargetTimespan MISMATCH → Emulasi Salah   ✗ OPEN

   File: src/kernel/chainparams.cpp:208

   Status: BELUM DIPERBAIKI.
   Testnet: nPowTargetTimespan = 14 * 24 * 60 * 60 = 1,209,600 (2 minggu)
   Mainnet: nPowTargetTimespan = 60

   Testnet menggunakan Bitcoin-style 2016-block retarget window, BUKAN
   EMA per-block. Testing di testnet tidak mencerminkan behavior mainnet.
   Bug EMA yang terlewat di testnet bisa muncul di mainnet.

   Fix: Set testnet nPowTargetTimespan = 60 (sama dengan mainnet).
   Effort: 30 menit



   H6. Sighash TANPA Chain ID Binding → Replay Attack         ✗ OPEN

   File: src/script/sign.cpp:173-188

   Status: BELUM ADA CHAIN ID. Kode sekarang:
   cpp
   // sighash_v2 = SHA256(sighash_v1 || leaf_index_4_bytes_BE)

   leaf_index ditambahkan (fix 21/Jun/2026), tapi TIDAK ADA chain ID.
   Transaksi testnet MASIH BISA di-replay ke mainnet setelah launch.

   pchMessageStart berbeda antara mainnet (0x53,0x4E,0x54,0x49 = "SNTI")
   dan testnet, tapi ini hanya untuk P2P layer — tidak masuk ke sighash.

   Fix: Definisikan SNTI_CHAIN_ID_MAINNET = 1, SNTI_CHAIN_ID_TESTNET = 2.
        Tambah ke preimage:
        sighash_v2 = SHA256(sighash_v1 || leaf_index_BE || chain_id_BE)

   Effort: 2-4 jam



   ═══════════════════════════════════════
   BUG MEDIUM
   ═══════════════════════════════════════


   M1. 4 Versi XMSS State Class — Kode Confusing

   File terkait: xmss_keystore.h, xmss_signer.h, xmss_state.h (×2),
                 xmss_miner_state.h

   5 file berbeda mengelola XMSS state dengan format berbeda-beda.
   SaveState/LoadState di xmss_signer.cpp pakai format "QNT2",
   xmss_miner_state pakai format lain. Sangat mudah terjadi desync.

   Fix: Konsolidasi ke 1 state manager class.



   M2. Namespace Branding Inkonisten: QNT/Quant/PoUWv2/XMSS/SNTI

   - src/xmss_state.h: namespace QNT::XMSS (header: "QUANT_XMSS_STATE_H")
   - pouw.h: namespace QNT::PoUW
   - xmss_miner_state.h: namespace PoUWv2
   - xmss_bridge.h: namespace XMSS
   - xmss_address.h: namespace XMSSAddr
   - wallet/xmss_keystore.h: copyright "The Quant developers"
   - SaveState format: "QNT2"

   Project sekarang SNTI/Assentian. Confusing untuk contributor baru
   dan bisa menyebabkan namespace collision.



   M3. PoUW v1 Dead Code Masih Ada

   File: src/pouw.h (8267 bytes)

   Tidak di-include dimanapun tapi masih ada di repo. Kode namespace
   QNT::PoUW yang deprecated. CheckPoUW di validation.cpp masih punya
   v1 path — apakah v1 blocks masih diterima?



   M4. NOL Unit Test untuk XMSS di src/test/

   Tidak ada satu pun file test di src/test/ yang menguji XMSS signing,
   verification, state management, atau PoUW. Test files hanya ada di
   root repo (ad-hoc C/C++ files).



   M5. EMA Tanpa Dampening — Oscillation di Network Kecil

   EMA alpha=0.1 tanpa moving average window. Dengan hanya 1-3 miner:
   - 1 miner offline → block spacing 5+ menit → difficulty turun 30%+
   - Miner kembali → blocks tiap 10 detik → difficulty naik 30%+
   - Cycle berulang (sawtooth pattern)

   Bitcoin pakai 2016-block window untuk smooth transition. EMA per-block
   tanpa dampener = sangat volatile saat network kecil.



   M6. Mining Seed Exposure → Integer Underflow Risk

   PoUW v2 menyimpan 96-byte seed di coinbase.
   MAX_OP_RETURN_RELAY = 83 bytes.
   PoUWv2Proof total = 2660 bytes.
   Coinbase OP_RETURN harus exempt dari standardness policy, tapi TIDAK
   ADA definisi explicit di policy.



   M7. [BARU] PoUW v1 Path Masih Aktif di CheckPoUW

   File: src/validation.cpp:3958-4090

   CheckPoUW() menerima BAIK v1 (64-byte xmss_pk langsung di OP_RETURN)
   maupun v2 (magic PW2\x02). Tidak ada height-gated v1 deprecation.
   Miner bisa kirim v1 proof bahkan setelah v2 seharusnya mandatory.

   Fix: Tambah nPoUWv2StartHeight di consensus params.
        Block >= nPoUWv2StartHeight yang kirim v1 proof → REJECTED.

   Effort: 2 jam



   ═══════════════════════════════════════
   BUG LOW
   ═══════════════════════════════════════


   L1. nMinimumChainWork = 0 (Zero)

   Semua chain types: consensus.nMinimumChainWork = uint256{}.
   Rentan terhadap long-range attack dari genesis. Ini normal untuk
   pre-launch tapi WAJIB diupdate setelah chain punya ~10k blocks.


   L2. Checkpoint Hanya Genesis Block

   Hanya {0, hashGenesisBlock}. Tidak ada checkpoint di height > 0.
   Sama seperti L1 — update setelah mainnet berjalan.


   L3. nNonce=0 Legacy Field Masih di Block Header            ✓ NOTED

   4 byte sampah di setiap block header. Diserialize di semua format.
   Bisa dihapus untuk hemat bandwidth, tapi butuh hard fork.
   Low priority — tunda ke post-mainnet.


   L4. Stratum Password Default "password"

   Catatan: stratum_server.py tidak ditemukan di src/. Kemungkinan
   sudah dipindah atau diganti. Perlu verifikasi lokasi aktual.



   ═══════════════════════════════════════
   TEMUAN BARU (Tidak Ada di Audit Awal)
   ═══════════════════════════════════════


   N1. [BARU — HIGH] src/xmss_state.h Duplikat dengan Bug Aktif

   Lihat H3 di atas. Ada dua xmss_state.h yang berbeda:
   - wallet/xmss_state.h → FIXED
   - src/xmss_state.h → MASIH BUGGY (namespace QNT::XMSS, file lama)

   Ini bukan hanya code smell — src/xmss_state.h::KeyState::Generate()
   masih punya trailing-zero trim yang bisa corrupt mining SK. Mining
   path terpengaruh.


   N2. [BARU — HIGH] Tidak Ada Mekanisme Auto-Rotate Key XMSS

   File: src/wallet/xmss_keystore.h:113-115

   Saat leaf_index >= 1024, Sign() return {} tanpa notify user, tanpa
   auto-rotate ke key baru, tanpa auto-transfer balance. User bisa stuck
   tidak bisa send transaksi TANPA TAHU KENAPA.

   Fix roadmap:
   (a) Warn user di leaf_index 900 (87.5% — 124 sigs tersisa)
   (b) Auto-generate key baru di leaf_index 950 (pre-rotate)
   (c) Setelah exhausted: auto-transfer balance ke key baru dan retire

   Effort: 2-3 hari (butuh wallet UX + auto-transfer logic)


   N3. [BARU — MEDIUM] Leaf Reuse Scan Hanya Mundur 1024 Block

   File: src/validation.cpp:3986-4007

   Kode scan leaf reuse:
   cpp
   while (pindex && scan_depth < 1024) { ... }

   Kalau miner berganti tree (xmssRoot berbeda), loop break early (baris
   di dalam: "Different tree — no reuse possible before this point").
   Tapi kalau miner malicious berganti-ganti tree setiap 1023 blocks,
   dan scan hanya 1024, reuse di block ke-1025+ bisa lolos.

   Fix: Setelah tree switch, scan tidak perlu mundur lebih jauh karena
   reuse hanya meaningful dalam satu tree. Logika break sudah benar.
   TAPI: indeks 0-1023 bisa dipakai ulang kalau miner menyimpan seed
   dan memulai ulang tree dari index 0. Perlu persistensi "used trees"
   di chainstate DB.

   Effort: 4 jam


   N4. [BARU — MEDIUM] Tidak Ada Warning/Metric untuk Leaf Usage

   Tidak ada logging/metrics untuk:
   - Berapa leaf yang tersisa per mining key
   - Alert saat mendekati exhaustion
   - Pool monitoring untuk leaf usage miner

   Saat testnet kecil ini mungkin OK. Tapi di mainnet dengan miners
   yang mungkin tidak monitoring log, key exhaustion = mining berhenti
   tiba-tiba tanpa penjelasan.

   Fix: Tambah metric/RPC:
        - getxmsskeyinfo → returns leaf_index, remaining, warning level
        - Log level WARN saat remaining < 200
        - Prometheus metric jika ada metrics framework


   N5. [BARU — LOW] CheckPoUWv2 Tidak Verifikasi XMSS OID di Proof

   File: src/pouw_v2.h, src/validation.cpp

   PoUWv2Proof berisi xmss_pk[64] tapi tidak menyimpan OID eksplisit.
   CheckPoUWv2() menggunakan OID hardcoded (XMSS_SHA2_10_256).
   Kalau di masa depan ada migrasi OID (ke height 16 atau 20), tidak
   ada cara proof lama diverifikasi dengan benar.

   Fix: Tambah uint8_t oid[4] ke PoUWv2Proof, verifikasi di CheckPoUWv2.
   Effort: 1 jam



   ═══════════════════════════════════════
   SARAN TAMBAHAN
   ═══════════════════════════════════════


   S1. Commit Message Convention Perlu Disinkronkan dengan Audit

   Commit 7ec14ed memakai penomoran bug INTERNAL ("C1/C2") yang berbeda
   dari dokumen audit ini. Ini sudah menyebabkan kebingungan:
   - "C1" di commit = "H3" di audit (trim-trailing-zero)
   - "C2" di commit = tidak ada di audit (exhaustion guard baru)
   - "H3" di commit = "H2" di audit (randombytes)
   - "H6" di commit = "C5" di audit (EMA difficulty)

   Rekomendasi: Pakai AUDIT-Cxx / AUDIT-Hxx prefix di commit message
   supaya progress tracking lebih jelas.


   S2. Test Suite Harus Jalan di CI Sebelum Mainnet

   Saat ini ZERO unit test untuk XMSS di src/test/. Tambah minimal:
   - xmss_sign_verify.cpp: sign + verify round-trip
   - xmss_state_persist.cpp: save + reload state, pastikan leaf_index benar
   - xmss_key_exhaustion.cpp: pastikan Sign() gagal gracefully di leaf 1024
   - pouw_v2_verify.cpp: CheckPoUWv2 dengan proof valid/invalid
   - difficulty_ema.cpp: EMA calculation correctness + boundary cases


   S3. Pisahkan Mining Key dari Wallet Key (Arsitektur)

   Saat ini tidak jelas apakah mining key dan wallet key bisa overlap.
   Audit C1 menyebutkan "kalau wallet address menggunakan tree yang sama
   = dana bisa dicuri". Ini harus jadi HARD CONSTRAINT di kode:
   - Mining key (PoUW) = key yang SK_SEEDnya di-broadcast di OP_RETURN
   - Wallet key = key yang menandatangani transaksi, TIDAK BOLEH sama
   Tambah assertion di GenerateBlock(): pastikan mining key != wallet key.


   S4. Genesis Block Harus Ada di Test / Dokumentasi

   Commit 4044d53 "set official genesis block" ada, tapi:
   - Hash genesis harus hard-coded di chainparams untuk verifikasi
   - Semua node harus reject chain yang tidak mulai dari genesis yang sama
   Verifikasi: genesis hash saat ini 0x... apa? Harus match semua node.


   S5. Stratum Server: Lokasi & Keamanan

   stratum_server.py tidak ditemukan di src/. Perlu:
   (a) Konfirmasi lokasi aktual file stratum
   (b) Cek DEFAULT_RPC_PASS
   (c) Tambah TLS atau setidaknya dokumentasi "jangan expose ke internet"


   S6. Hard Fork Governance

   Saat ini tidak ada mekanisme signaling soft/hard fork. Kalau ada bug
   post-mainnet yang butuh fork:
   - Tidak ada version bits
   - Tidak ada miner signaling
   - Tidak ada deployment height / window

   Bitcoin pakai BIP9/BIP8 untuk ini. Minimal definisikan proses manual:
   "fork di height X, announced N weeks sebelumnya".



   ═══════════════════════════════════════
   RISIKO MASA DEPAN (POST-MAINNET)
   ═══════════════════════════════════════


   R1. Kapasitas Block Sangat Rendah

   Bitcoin:  ~10,000 tx/block → ~7 tx/s
   SNTI:     ~357 tx/block   → ~6 tx/s (dengan XMSS sig 2500 byte)

   Dengan pertumbuhan pengguna, fee market akan sangat ketat. Solusi:
   SegWit-style witness discount untuk XMSS sigs, atau XMSS^MT
   (multi-tree) dengan sig yang lebih kecil.


   R2. XMSS Key 1024 Signature Limit

   Setiap XMSS-SHA2_10_256 key hanya bisa sign 1024 kali. Setelah itu
   harus generate key baru. Wallet UX harus:
   (a) auto-rotate, (b) auto-transfer balance ke key baru,
   (c) warn user sebelum exhaustion.
   Saat ini CXMSSSigner menolak sign setelah exhausted tapi TIDAK ada
   mekanisme auto-rotate. Lihat N2 di atas.


   R3. Quantum Advantage hanya di Signatures, Bukan Privacy

   XMSS mengamankan signature, tapi:
   - Address = RIPEMD160(SHA256(pubkey)) → quantum-vulnerable untuk
     melihat balance
   - Transaction graph → fully visible
   - Tidak ada privacy layer (no Mimblewimble, no CT, no zero-knowledge)


   R4. Pool Mining Masih Proxy Model

   Stratum server menggunakan generatetoaddress proxy — miner hanya
   submit SHA-256 share, block construction terjadi di bitcoind. Ini
   TIDAK scalable untuk pool besar. Mining pool profesional butuh
   getblocktemplate + submitblock yang full.


   R5. Hard Fork Tanpa Replay Protection

   Kalau ada fork/upgrade, tidak ada chain ID binding di sighash →
   semua transaksi bisa di-replay di kedua chain (seperti ETH/ETC 2016).
   Lihat H6 — ini perlu fix sebelum mainnet untuk prevent replay antara
   testnet dan mainnet juga.



   ═══════════════════════════════════════
   ROADMAP PERBAIKAN (DIUPDATE)
   ═══════════════════════════════════════


   Phase 1: EMERGENCY (minggu ini) — Blocker Mainnet Tersisa

   | #   | Item                                              | Effort    | Status |
   |-----|---------------------------------------------------|-----------|--------|
   | 1   | Hapus seed[] dari PoUWv2Proof (C1)                | 2 jam     | ✗ OPEN |
   | 2   | Verifikasi commitmentsRoot di CheckPoUW (C2)      | 4 jam     | ✗ OPEN |
   | 3   | Fix src/xmss_state.h trailing-zero trim (H3/N1)   | 30 menit  | ✗ OPEN |
   | 4   | Wallet flush setelah XMSS sign (H1)               | 1-2 jam   | ✗ OPEN |
   | 5   | Hapus vFixedSeeds.clear() mainnet (C3)             | 30 detik  | ✓ DONE |
   | 6   | Rewrite PermittedDifficultyTransition EMA (C5)    | 4-8 jam   | ✓ DONE |
   | 7   | Thread-safe randombytes getrandom() (H2)           | 2 jam     | ✓ DONE |


   Phase 2: HARDENING (2-4 minggu)

   | #   | Item                                                    | Effort    | Status  |
   |-----|---------------------------------------------------------|-----------|---------|
   | 8   | Tambah chain ID ke sighash (H6)                         | 2-4 jam   | ✗ OPEN  |
   | 9   | Fix testnet nPowTargetTimespan = 60 (H5)                | 30 menit  | ✗ OPEN  |
   | 10  | Dynamic signature chunking / witness (C4)               | 1-2 hari  | ✗ OPEN  |
   | 11  | SecureClear sebelum free SK (H4)                        | —         | ✓ DONE  |
   | 12  | Height-gate PoUW v1 path — v2-only dari height X (M7)  | 2 jam     | ✗ OPEN  |
   | 13  | Auto-rotate XMSS wallet key + UX warning (N2)          | 2-3 hari  | ✗ OPEN  |
   | 14  | RPC getxmsskeyinfo (remaining sigs) (N4)               | 2 jam     | ✗ OPEN  |


   Phase 3: NETWORK LAUNCH (4-8 minggu)

   | #   | Item                                | Effort          | Status |
   |-----|-------------------------------------|-----------------|--------|
   | 15  | Minimum 3 seed node (ASN berbeda)   | 2-3 hari        | ~ 1/3  |
   | 16  | DNS seed domain (seed.snti.io)      | 1 hari          | ✗ OPEN |
   | 17  | Checkpoints setiap 10k blocks       | ongoing         | ✗ OPEN |
   | 18  | nMinimumChainWork update            | per update      | ✗ OPEN |
   | 19  | Unit tests di src/test/ (S2)        | 1-2 minggu      | ✗ OPEN |
   | 20  | Public testnet 10k+ blocks          | 2-4 minggu      | ✗ OPEN |
   | 21  | External security audit             | budget: $10-30k | ✗ OPEN |


   Phase 4: POST-LAUNCH

   | #   | Item                                         |
   |-----|----------------------------------------------|
   | 22  | EMA dampening bands (M5)                     |
   | 23  | XMSS^MT untuk >1024 sigs/key                 |
   | 24  | getblocktemplate + submitblock full (R4)      |
   | 25  | Stratum V2 + TLS (L4)                        |
   | 26  | Witness discount untuk XMSS sigs (R1)        |
   | 27  | Consolidate 4 XMSS state classes → 1 (M1)   |
   | 28  | Rebrand QNT→SNTI namespace (M2)              |
   | 29  | Hard fork governance / version bits (S6)     |
   | 30  | OID field di PoUWv2Proof (N5)               |



   ═══════════════════════════════════════
   KESIMPULAN (DIUPDATE 27 Jun 2026)
   ═══════════════════════════════════════

   Commit 7ec14ed (26 Jun) sudah menutup 3 dari 5 blocker CRITICAL:
   C3 (seed nodes), C5 (EMA difficulty), H2 (randombytes). Tapi 3 blocker
   terbesar BELUM disentuh sama sekali:

   1. SK_SEED terekspos di blockchain (C1) — ini fundamental design flaw.
      Setiap block yang sudah di-mine MENYIARKAN private key miner.
      Satu-satunya alasan belum jadi bencana: mining key != wallet key
      (diharapkan). Tapi tidak ada hard constraint yang memastikan ini.

   2. commitmentsRoot tidak diverifikasi (C2) — 32 byte header sampah
      yang miner bisa isi random tanpa penalti apapun.

   3. Wallet tidak flush setelah sign (H1) — crash = WOTS+ key reuse
      potensial = private key leak. Ini risiko nyata untuk user biasa.

   4. src/xmss_state.h MASIH punya trailing-zero bug (N1) — fix hanya
      menyentuh wallet/xmss_state.h, bukan file mining-path yang sama.

   Minimal 2-3 minggu kerja lagi sebelum bisa launch mainnet dengan aman.
   Testnet publik harus jalan minimal 10k blocks SETELAH semua fix Phase 1
   dan Phase 2 diterapkan.

   Priority urutan kerja:
   C1 → H3/N1 → H1 → C2 → H6 → C4 → H5

   =====================================================================
