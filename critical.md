 3 CRITICAL Threats untuk SNTI



    1. WOTS+ Verify Regression — "Root-Only Check" Bypass

    Kenapa critical: Jika WOTS+ verification disabled (seperti yang pernah terjadi sebelumnya — "WOTS verify disabled pending BDS state fix"), attacker bisa:
    - Buat arbitrary block dengan root < target (trivial, cuma perlu SK_SEED random)
    - Signature tidak perlu valid — xmss_sign_open tidak dipanggil
    - Network accept block ini → consensus split / fake chain

    Bukti kode yang rentan:

    // pouw_v2.h line 96-98
    if (UintToArith256(root) > target) return false;  // ← ini saja yang checked
    // WOTS verify di line 138 — bisa di-skip jika ada bug/fix


    Yang harusnya:
    cpp
    // Hard-fail: JANGAN pernah return true tanpa WOTS verify
    int ret = xmss_sign_open(...);
    if (ret != 0) return false;  // ← ini HARUS unconditional


    Status: DEVDOCS.md line 354 bilang "WOTS+ signature verification in CheckPoUWv2() is currently checking root < target only (WOTS verify disabled pending BDS state fix)" — tapi line 519 bilang "WOTS+ verification is fully active". Kontradiksi ini perlu diverifikasi ulang.



    2. 51% Attack — Hashrate Sangat Rendah

    Kenapa critical:
    - Testnet hashrate: ~0.0025 H/s (dari DEVDOCS.md)
    - Mining: 1 XMSS tree = ~6 detik di 4 CPU cores
    - powLimit testnet = max (trivial)
    - Attacker butuh ~$5 cloud CPU untuk solo mine 100 blok sendiri

    Attack scenario:
    1. Attacker sewa 4 CPU di cloud ($2/jam)
    2. Mine 100 blok sendiri dalam ~10 menit
    3. Broadcast chain dengan total work lebih tinggi
    4. EMA adjustment butuh ~10 blocks untuk catch up
    5. Semua TX di block yang di-reorg jadi invalid — double-spend possible

    Bukti kode — tidak ada finality mechanism:
    cpp
    // validation.cpp — hanya check root < target
    // Tidak ada: minimum confirmations, finality gadget, atau checkpoint


    Status: Tidak ada checkpoint mechanism. Tidak ada finality. Confirmations = probabilistic only.



    3. Eclipse Attack — Single Seed Node

    Kenapa critical:
    - Hanya 1 node publik: 104.234.26.7:39333
    - Tidak ada DNS seeds
    - Tidak ada seed nodes di AS/region lain

    Attack scenario:
    1. Attacker sewa 10 VPS di AS yang sama dengan target
    2. Flood target node dengan attacker's peers (BIP324 encrypted)
    3. Target node's outbound connections semua ke attacker
    4. Attacker feed false chain / censor transactions
    5. Isolated node = mudah di-double-spend atau di-censor

    Bukti dari PROJECT_STATUS.md:

    "Belum dikerjakan: reconnect node eksternal (VM) ke testnet baru ini"


    Artinya: Setelah rebrand ke SNTI, tidak ada external node yang connected. Hanya 1 node di jaringan.



    Rekomendasi Immediate (sebelum mainnet)

    #: 1
    Fix: Verify WOTS+ verify enabled di production build — grep xmss_sign_open call
    Effort: 30 menit
    ────────────────────────────────────────
    #: 2
    Fix: Tambah checkpoint mechanism (hardcoded block hashes di chainparams)
    Effort: 1-2 hari
    ────────────────────────────────────────
    #: 3
    Fix: Deploy 2+ seed nodes di region berbeda
    Effort: 1 hari
    ────────────────────────────────────────
    #: 4
    Fix: DNS seeds (seed.assentian-pqe.org)
    Effort: 1 hari