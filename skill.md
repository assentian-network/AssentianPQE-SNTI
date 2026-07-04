# SNTI Debugging & Deployment Playbook

Metodologi yang dipakai untuk investigasi bug leaf-1023 (3-4 Jul 2026), ditulis
supaya sesi/agent berikutnya bisa pakai pendekatan yang sama tanpa mengulang
proses coba-coba dari nol.

## 1. Repo mana yang dipercaya

Ada beberapa clone/mirror SNTI di disk dengan nama mirip
(`/root/AssentianPQE-SNTI`, `/root/Assentian-PQE/SNTI`, dst). SEBELUM baca kode
untuk audit/debug apa pun: `git fetch origin <branch> && git status` di
direktori yang mau dipakai, cek apakah ada "forced update"/divergence dari
origin. Working dir otoritatif untuk kerja aktif: `/root/Assentian-PQE/SNTI`.
Salah pilih direktori pernah menghasilkan kesimpulan audit yang SALAH TOTAL
(lihat job_queue.md, insiden 3 Jul).

## 2. Saat sesuatu terlihat "stuck"/aneh: baca log dulu, jangan tebak

Urutan yang terbukti efektif:
1. `journalctl -u <service> --no-pager -n N` untuk gambaran umum + timeline.
2. `debug.log` node (`grep`/`tail` di sekitar waktu kejadian) untuk detail
   teknis (nBits, target, leaf index, error message persis).
3. Hitung ekspektasi statistik SEBELUM menyimpulkan "bug" — banyak hal yang
   kelihatan aneh (burst block cepat lalu diam lama) ternyata konsekuensi
   desain yang sudah didokumentasikan (1 tree valid = ratusan blok nyaris
   instan, floor difficulty bikin pencarian tree berikutnya bisa hari-an).
   Jangan asumsikan "stuck" = "hang"/bug tanpa hitungan probabilitas dulu.
4. Kalau ada pesan error KONSISTEN yang muncul di titik yang SAMA PERSIS lebih
   dari sekali (mis. selalu di leaf 1023/1024), itu petunjuk kuat root cause
   deterministik, bukan flakiness — grep seluruh log historis untuk semua
   kemunculannya sebelum menyimpulkan apa pun.

## 3. Menelusuri bug kripto: sign DAN verify, vendor DAN wrapper

- Cek dulu apakah kode yang "salah" itu punya diff dari upstream
  (`diff xmss-reference/foo.c src/foo.c`) — kalau IDENTIK dengan reference,
  bug ada di WRAPPER SNTI (xmss_bridge.cpp, xmss_tree_ledger.cpp,
  xmss_miner_state.h), bukan di crypto vendor.
- Kalau ternyata bug memang ada di reference library sendiri (seperti leaf
  1023 — reference sengaja skip signature terakhir untuk height=64 tapi lupa
  untuk height lain), **jangan patch crypto vendor**. Fix di layer SNTI yang
  membungkusnya (turunkan kapasitas usable, dsb) — jauh lebih aman daripada
  mengubah kode kripto yang sudah diaudit dan dipakai proyek lain.
- Cari SEMUA hardcoded angka yang seharusnya jadi satu konstanta
  (`grep -rn "1024"` dsb) sebelum menganggap fix selesai — literal yang
  terpisah adalah sumber bug kelas ini di masa depan.

## 4. Urutan verifikasi sebelum sentuh produksi

1. Tulis test regresi yang pakai JALUR PRODUKSI ASLI (fungsi yang benar-benar
   dipanggil mining.cpp/wallet), bukan cuma primitive level — supaya test
   membuktikan fix di titik yang sama persis dengan bug ditemukan.
2. `make -j4 test/test_bitcoin` (hapus binary lama dulu kalau nambah file test
   baru: `rm -f src/test/test_bitcoin` + `automake --include-deps` kalau perlu
   — quirk dependency-tracking automake yang sudah beberapa kali kejadian).
3. `--run_test=<suite>` dan baca satu-satu Entering/Leaving per test case,
   jangan cuma percaya ringkasan pass/fail total (ada 2 test EMA yang memang
   sudah lama gagal, pre-existing, harus dibedakan dari kegagalan baru).
4. Build binary penuh (`make bitcoind bitcoin-cli`), lalu smoke-test REGTEST
   (bukan cuma unit test) — mining beberapa blok, cek `debug.log` bersih.
5. Baru setelah semua di atas hijau, minta approval user untuk deploy.

## 5. Pola deploy 3 node (SG → KC → Main)

Urutan ini konsisten dipakai di semua fix sebelumnya, ikuti terus:
1. Deploy ke SG dulu, lalu KC, baru Main TERAKHIR (Main jalankan miner+wallet,
   paling sensitif).
2. Tiap node: `sha256sum` binary lama → backup dengan nama jelas
   (`bitcoind.pre-<nama-fix>.bak`) → stop service → copy binary baru →
   `chmod +x` → start service → `sha256sum /proc/<pid>/exe` HARUS cocok
   dengan binary baru (bukan cuma asumsi restart otomatis pakai binary baru).
3. Main VPS: kalau ada `assentian-vps-miner` yang jalan, STOP dulu sebelum
   restart `assentian-mainnet-node`, baru START lagi setelah node up (miner
   BuildNewTree stateless per percobaan — aman stop/resume kapan saja, tidak
   ada progress hilang).
4. Verifikasi akhir WAJIB di ketiga node: `getblockcount` +
   `getbestblockhash` harus IDENTIK persis, `getpeerinfo` ada koneksi sehat,
   `debug.log` tail bersih dari error baru.
5. Kalau ada binary installer publik (`bin/bitcoind` diserver nginx untuk user
   luar), update juga di langkah yang sama — jangan lupa, ini sering
   terlewat karena bukan "node produksi" secara langsung.

## 6. Troubleshooting instalasi user eksternal (danu/dini pattern)

Kalau user eksternal lapor macet saat sync/install:
- Curigai dulu STATE/BINARY LAMA yang nyangkut dari percobaan sebelumnya,
  bukan bug baru — ini sudah beberapa kali terjadi (BUG KELIMA danu, insiden
  dini). Cek `explorer/server.py` untuk path `INSTALL_DIR` vs `DATADIR` YANG
  BERLAKU SAAT INI (bisa beda-beda per versi script) — minta user
  `pkill -f "bitcoind.*<pola>"` + `rm -rf` KEDUA path itu, bukan cuma satu.
- Dari sisi server, `getpeerinfo` untuk IP user itu (di SEMUA node yang dia
  connect, bukan cuma satu) kasih banyak info tanpa perlu akses ke mesin dia:
  `bytessent_per_msg`/`bytesrecv_per_msg` per jenis pesan (headers vs block)
  nunjukkin di FASE mana dia macet. Kalau byte count BEKU di semua node
  secara SIMETRIS (bukan cuma satu), itu tanda masalah ADA DI SISI DIA,
  bukan ditolak salah satu node kita.
- Kalau butuh log dari sisi user, minta persis: `tail -N <path>/debug.log`
  atau `cat` — user sering salah ketik path sebagai perintah langsung
  (`~/.snti_mainnet/debug.log` dieksekusi, bukan dibaca → "Permission
  denied" yang menyesatkan, padahal filenya baik-baik saja).

## 7. Batasan jujur yang perlu diingat

Jaringan ini saat ini masih bergantung pada infrastruktur satu orang (DNS
seed = 3 IP milik sendiri, mayoritas hashrate = Main VPS). Ini tahap wajar
untuk chain yang baru lahir (sama seperti Bitcoin bulan-bulan pertama), tapi
JANGAN dijual sebagai "sudah terdesentralisasi penuh" — jawab jujur kalau
ditanya, termasuk risiko fork/isolasi kalau backbone mati bersamaan. Lihat
job_queue.md bagian "CATATAN ARSITEKTUR" untuk detail dan mitigasi yang
diusulkan (belum dikerjakan).
