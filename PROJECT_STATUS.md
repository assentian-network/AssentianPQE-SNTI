# QNT — Status Project Sebenarnya (Konsolidasi)
**Disusun: 20 Juni 2026, sesi Claude.** Dokumen ini menggantikan referensi ke
FIX_LOG.md (berantakan, duplikat fase, terakhir update 11 Juni — sebelum
commit pertama project), dan mem-vereifikasi ulang AUDIT.md/SECURITY_AUDIT.md/
TESTNET_CHECKLIST.md/mainnet-checklist.html terhadap kondisi kode aktual.
File-file lama TIDAK dihapus (sejarah berharga) tapi JANGAN dijadikan acuan
status terkini — selalu cek file ini dulu.

---

## 1. Timeline asli (dari `git log`, 32 commit, 15-20 Juni 2026)

| Tanggal | Commit | Yang terjadi |
|---|---|---|
| 15 Jun 10:09 | 7b4a88b | First commit — import Bitcoin Core fork |
| 15 Jun 16:12 | a545e92 | Lisensi BSL-1.1 |
| 16 Jun 00:29 | cff5dd5 | **Genesis block resmi ditambang** (NIST SP 800-208 XMSS) |
| 16 Jun 06:16 | 700f683 | RPC export/import xmsskey |
| 16 Jun 07:56 | 91355f5 | Keputusan SADAR: tunda proteksi reuse key XMSS demi alasan lain dulu |
| 16 Jun 08:10 | ec1c4fe | Halaman mainnet checklist dibuat |
| 17 Jun 06:46 | 9b371b6 | **CRITICAL**: heap buffer overflow di XMSS `Verify()` — fixed |
| 17 Jun 23:50 | 76c1ea6 | **CRITICAL**: BIP141/SegWit violation, multi-node nggak konsensus — fixed |
| 18 Jun 01:47 | 7e08e3a | Checklist update: multi-node test verified, BIP141 resolved |
| 18 Jun 23:51 | 2d43c2a | Fix halving interval (salah 10x) |
| 19 Jun 04:36 | d61ae76 | **CRITICAL**: XMSS private key nggak ke-persist sampai spend pertama — fixed |
| 20 Jun 01:19 | eeef9ea | Fix scriptSig XMSS kebesaran (chunking) — **sesi hari ini, bagian 1** |
| 20 Jun 07:10 | 50dffbe | P2XMSSHASH ditambahkan |
| 20 Jun 09:17–10:43 | 353c66c, 9af9802, fd1f645 | Gap #4 (investigasi, tidak reproduce) + Gap #3 (key retirement) — **sesi ini** |

**Kesimpulan:** progress ini NYATA. Bukan fabrikasi. 6 hari kerja intensif, beberapa bug CRITICAL asli ditemukan & diperbaiki.

---

## 1.8 MILESTONE: First externally-mined block accepted [20 Jun]

Dari VM yang sama (node independen, build dari nol, sync via internet),
dipanggil `generatetoaddress` di TESTNET (bukan regtest) -- ternyata
RPC ini emang didesain bekerja di chain manapun di fork ini, bukan
dibatasi regtest. Hasil: blok PoUW asli (XMSS keygen + PoW grind +
sign + verify) berhasil ditambang CPU biasa dalam **2 detik**
(`networkhashps` testnet saat itu ~0.0025 H/s, difficulty nyaris nol).

Blok `1254f0a0...` berhasil PROPAGASI ke node resmi VPS dan DITERIMA
-- `getbestblockhash` identik di kedua sisi (208/208). Ini bukti
end-to-end lengkap: node eksternal bisa sync DAN aktif menambang DAN
blok-nya diterima jaringan.

## 1.7b MILESTONE: Assentian-PQE testnet service LIVE [21 Jun]

`assentian-node.service` (systemd) resmi jalan di lokasi baru
(`/root/Assentian-PQE/SNTI`), datadir terpisah (`/root/.assentian_testnet`),
port baru (RPC 39332, P2P 39333 - sengaja beda dari port lama biar nggak
bentrok). Genesis terverifikasi: `2d858f51fc4af7926bee59c82d06d58a3f260647145aaf6f89263bcb3643b66d`.

Repo lama (`bitcoin-quant`, folder `/root/quant/bitcoin-quant`) dan
servis lama (`qnt-node.service`) dibiarkan MATI sebagai arsip - tidak
dihapus, tapi tidak lagi jadi acuan aktif.

**Belum dikerjakan**: reconnect node eksternal (VM) ke testnet baru ini
(perlu wipe data lama di VM dulu, chain lama sudah obsolete).

## 1.7a MILESTONE: Rebrand to Assentian-PQE / SNTI [21 Jun]

QNT bentrok dengan Quant Network (ticker mapan, ~$1 miliar market cap) -
diputuskan rebrand. Nama baru: **Assentian-PQE**, ticker **SNTI**.
Verifikasi manual dilakukan di CoinMarketCap/CoinGecko - bersih.

Genesis BARU di-mine untuk testnet & regtest:
- Pesan: "Assentian-PQE Genesis 21/Jun/2026 - NIST SP 800-208 XMSS - Post Quantum Era Begins"
- Hash: `2d858f51fc4af7926bee59c82d06d58a3f260647145aaf6f89263bcb3643b66d`
- Magic bytes baru per chain (SNTI/sTST/sREG)
- Mainnet & signet genesis BELUM diupdate (beda nBits, perlu nonce search terpisah - open item)

Genesis lama "QNT Genesis 15/Jun/2026..." (hash 743c2849...) sekarang
jadi sejarah/arsip - masih ada di git history, tapi chain aktif testnet/
regtest sekarang pakai identitas baru.

**Belum dikerjakan**: swap binary di `qnt-node.service` (servis testnet
LIVE) ke genesis baru - servis itu masih jalan dengan chain lama sampai
langkah ini dilakukan.

## 1.7 MILESTONE: First independent external node [20 Jun]

Node di-build dari nol di mesin TERPISAH (Windows + VirtualBox Ubuntu,
bukan VPS yang sama), via internet publik asli (IP publik eksternal
103.133.x.x), connect ke `104.234.26.7:19333`. Hasil: sync penuh 207/207
blok dalam ~20 detik, transport BIP324 (v2 encrypted) jalan normal.

Bug ditemukan & diperbaiki sepanjang proses: `configure.ac` punya 3
baris `AC_CONFIG_LINKS` rusak (self-referencing, nggak ke-guard
`ENABLE_QT`) yang bikin `autogen.sh` GAGAL TOTAL di checkout fresh manapun
-- sebelumnya nggak ketahuan karena VPS selalu pakai Makefile hasil
generate lama, nggak pernah re-run autogen.sh. Sekarang fixed & ke-verify
build bersih dari nol di DUA mesin independen.

Ini bukti pertama: orang lain (bukan tim/VPS asli) bisa build & jalanin
node QNT dan ikut sinkron jaringan secara nyata.

## 1.6 Testnet legacy-block scan [20 Jun]

Scan semua 207 blok testnet (`qnt-node.service`) buat pola corrupt yang
sama kayak regtest. **Hasil: BERSIH.** Semua slot pubkey OP_RETURN
persis 66 byte. Testnet aman dari bug ini — confirmed dimulai setelah
fix BIP141 17 Jun.

## 1.5 MULTI-NODE SYNC — FULLY VERIFIED [20 Jun, final]

Fix `CheckPoUW()` (commit lihat git log) + chain regtest baru dari nol +
binary terpatch penuh. Hasil: node kedua sync 110/110 blok dari genesis,
TERMASUK blok berisi transaksi `sendfromxmssaddress` asli (bukan cuma
coinbase). Tip hash node 1 dan node 2 identik persis. Ini penutup
investigasi multi-node yang dimulai gap #4 lalu berkembang jadi
penemuan bug konsensus nyata.

## 2. TERVERIFIKASI LANGSUNG hari ini (bukti konkret, bukan klaim file lama)

- ✅ `OP_XMSS_CHECKSIG` benar-benar verifikasi matematis di consensus layer (`interpreter.cpp`, bukan stub)
- ✅ State save/load XMSS (`SaveState`/`LoadState`) tahan restart bersih DAN `kill -9` mendadak
- ✅ Key retirement (gap #3): sign kedua ke key yang sama berhasil ditolak (`SignXMSS refused -- key is retired`)
- ✅ Dashboard/explorer live di `104.234.26.7` (HTTP 200, `server.py` jalan sejak 17 Jun)
- ✅ Kode stratum server ADA (`stratum_server.py` + `/root/qnt-stratum/stratum.js`) — tapi **tidak sedang jalan** saat ini
- ✅ **[21 Jun]** Sighash-v2 diimplementasi — `sighash_v2 = SHA256(sighash_v1 || leaf_index_BE)`. Cross-index recombination attack gap dari AUDIT.md 13 Jun DITUTUP secara teknis. Verified end-to-end (sign+verify simetris, transaksi confirmed on-chain).
- ✅ **[20 Jun]** XMSS state encryption at rest — diimplementasi & diverifikasi end-to-end (locked=ismine:false, unlock=decrypt otomatis & ismine:true). MEDIUM finding audit 13 Jun DITUTUP.

## 3. BELUM TERVERIFIKASI ulang (klaim dari dokumen lama, perlu dicek lagi)

- ✅ **[20 Jun]** Minimum sig length — sudah ter-cover (exact-match 2500 byte di interpreter.cpp), lebih ketat dari rekomendasi audit
- ✅ **[20 Jun]** `CheckPoUW()` direview penuh — verifikasi XMSS REAL di consensus layer, desain preimage anti-circular yang solid. 2 catatan minor (dead code duplikat di parsing pubkey, heuristik ukuran buat identifikasi sig output) — bukan bahaya, tapi layak digali auditor eksternal
- ⚠️ "Key exhausted check" (leaf_index>=1024) ternyata ada di fungsi Sign(), BUKAN SignXMSS() yang dipakai jalur asli — dokumentasi lama salah taruh. Sudah moot karena fix retirement hari ini otomatis mencegah key sampai index 1024 lewat jalur manapun
- ⚠️ Multi-node test (commit 76c1ea6/7e08e3a, 17-18 Jun) — kemungkinan REAL, tapi terjadi SEBELUM P2XMSSHASH dan format state v2 ditambahkan. **Perlu di-retest** dengan kode terkini, jangan asumsikan masih valid.
- ⚠️ Testnet node — tidak ada yang jalan sekarang (RPC port 18332 timeout). Kalau pernah ada, sudah dimatikan.

## 4. Dokumen lama — status & cara bacanya

| File | Status |
|---|---|
| `FIX_LOG.md` | ⚠️ Berantakan, fase duplikat, stale (update terakhir 11 Jun). Jangan jadi acuan status. |
| `AUDIT.md` | Self-audit 13 Jun. Verdict "key reuse impossible"-nya **TERBUKTI SALAH** (baru fixed 20 Jun). Anggap semua verdict "Aman" di situ perlu diverifikasi ulang, jangan diterima mentah. |
| `SECURITY_AUDIT.md` | Bukan audit — ini **template persiapan** untuk audit eksternal (Trail of Bits dkk) yang belum dilakukan. |
| `TESTNET_CHECKLIST.md` / `mainnet-checklist.html` | Snapshot kondisi di tanggal tertentu, bukan status live yang terus berlaku. |

## 5. NEXT STEP — urutan prioritas

1. **Cek 2 klaim "sudah fixed" di FIX_LOG** (key exhausted check, min sig length) — cepat, tinggal grep
2. **Baca `CheckPoUW()`** — belum pernah direview sama sekali, consensus-critical
3. **[20 Jun, SELESAI — akar masalah ketemu]** Multi-node retest:
   - ✅ Testnet (207 blok, semua format baru pasca-fix 17 Jun) — sync INSTAN
   - ❌ Regtest (137 blok, ada blok historis FORMAT LAMA) — node baru macet PERMANEN di height 0
   - **AKAR MASALAH**: blok height 1 regtest ditambang sebelum fix BIP141 (commit 76c1ea6), OP_RETURN pubkey-nya 131 byte — `CheckPoUW()` versi sekarang butuh PERSIS 66 byte exact-match, jadi blok lama ini DITOLAK PERMANEN oleh node manapun yang sync dari genesis dengan kode terkini
   - Hipotesis paralelisasi (XMSS verify nggak di-paralelkan) **gugur** — `CScriptCheck` generic, ini bukan soal itu
   - **RISIKO STRUKTURAL**: ini bisa terjadi di jaringan LIVE manapun kalau ada mismatch dikit aja antara format mining-side vs parser-side → network-halting bug (node baru nggak akan pernah bisa sync)
   - **Code quality**: ekstraksi signature pakai `script.GetOp()` (robust), tapi ekstraksi pubkey cuma `size()==66` (rapuh) — TIDAK KONSISTEN, perlu di-robust-kan
   - **Fix buat regtest kita**: chain ini disposable test data, tinggal wipe & re-genesis biar bisa lanjut tes 2-node bersih
4. **Encryption at rest** untuk XMSS state (MEDIUM, dari AUDIT.md, masih terbuka)
5. Baru pertimbangkan: nyalain testnet lagi, nyalain stratum, audit eksternal beneran
