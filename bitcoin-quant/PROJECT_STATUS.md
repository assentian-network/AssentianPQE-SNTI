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

## 2. TERVERIFIKASI LANGSUNG hari ini (bukti konkret, bukan klaim file lama)

- ✅ `OP_XMSS_CHECKSIG` benar-benar verifikasi matematis di consensus layer (`interpreter.cpp`, bukan stub)
- ✅ State save/load XMSS (`SaveState`/`LoadState`) tahan restart bersih DAN `kill -9` mendadak
- ✅ Key retirement (gap #3): sign kedua ke key yang sama berhasil ditolak (`SignXMSS refused -- key is retired`)
- ✅ Dashboard/explorer live di `104.234.26.7` (HTTP 200, `server.py` jalan sejak 17 Jun)
- ✅ Kode stratum server ADA (`stratum_server.py` + `/root/qnt-stratum/stratum.js`) — tapi **tidak sedang jalan** saat ini
- ❌ Sighash XMSS **tidak** include `leaf_index` (masih sama seperti temuan AUDIT.md 13 Juni) — risiko teoretis, tapi praktis sudah diredam oleh fix retirement hari ini
- ❌ XMSS state di wallet DB **masih plaintext**, belum di-enkripsi terpisah

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
3. **[20 Jun, SELESAI sebagian]** Multi-node retest dilakukan — hasil CAMPURAN:
   - ✅ Testnet (207 blok, coinbase-only/PoUW, 0 transaksi wallet) — Node kedua sync INSTAN
   - ❌ Regtest (137 blok, BANYAK transaksi XMSS wallet asli dari testing hari ini) — Node kedua MACET TOTAL di blok 0, CPU tinggi terus
   - Hipotesis awal (XMSS verify nggak di-paralelkan ke CCheckQueue) **TERBUKTI SALAH** — `CScriptCheck::operator()` generic, nggak ada bypass khusus XMSS
   - **Akar masalah BELUM ketemu.** Prioritas investigasi berikutnya: kemungkinan bug spesifik di salah satu transaksi P2XMSSHASH/chunked-scriptSig (bukan masalah arsitektur paralelisasi)
   - Reproduksi: 2 node regtest, sync dari node yang udah ada riwayat testing wallet XMSS hari ini (banyak `sendfromxmssaddress`/P2XMSSHASH) — server kedua connect & amati `getblockcount` macet di 0, CPU thread `msghand` tinggi, `scriptch` idle
4. **Encryption at rest** untuk XMSS state (MEDIUM, dari AUDIT.md, masih terbuka)
5. Baru pertimbangkan: nyalain testnet lagi, nyalain stratum, audit eksternal beneran
