# Mainnet Launch Checklist

**Status per 20-21 Juni 2026.** Checklist ini jujur berdasarkan apa yang sudah TERVERIFIKASI LANGSUNG (lihat `PROJECT_STATUS.md` untuk detail teknis tiap item), bukan asumsi atau klaim yang belum dibuktikan.

---

## 1. Consensus & Protocol (paling kritis)

| Item | Status | Catatan |
|---|---|---|
| Genesis block (testnet) | ✅ Done | Ditambang 15 Jun 2026 |
| `OP_XMSS_CHECKSIG` verifikasi signature transaksi | ✅ Verified | Real, bukan stub — dicek langsung di `interpreter.cpp` |
| `CheckPoUW()` verifikasi signature blok | ✅ Verified & robustness fix diterapkan | Parsing pubkey diperbaiki (GetOp(), bukan exact-size match) |
| Key retirement / anti-reuse XMSS | ✅ Verified | One-time-use per address, diuji end-to-end |
| Multi-node consensus agreement | ✅ Verified | Regtest + testnet, termasuk blok berisi transaksi XMSS asli |
| Bug format blok legacy (pra-fix BIP141) | ✅ Ditemukan & diperbaiki | Hanya pengaruhi blok historis sebelum fix 17 Jun |
| Mainnet genesis di production difficulty | ❌ Belum | Masih placeholder `0x1d00ffff`, belum pernah ditambang di difficulty asli |
| Difficulty retarget di bawah beban nyata | ❌ Belum diuji | Belum ada testnet jalan berhari-hari dengan banyak miner |
| Chain reorg handling dengan blok PoUW | ❌ Belum diuji | Belum pernah dipaksa fork/reorg |

## 2. Wallet & RPC

| Item | Status |
|---|---|
| `getnewxmssaddress`, `sendfromxmssaddress`, `getxmssaddressinfo` | ✅ Verified |
| P2XMSSHASH (hash-committed funding) | ✅ Verified |
| Encryption at rest (XMSS state) | ✅ Verified end-to-end |
| `exportxmsskey`/`importxmsskey` | ⚠️ Diklaim fixed di histori lama, belum diverifikasi ulang hari ini |
| Wallet backup/restore dengan XMSS state | ❌ Belum diuji |

## 3. Network & Infrastructure

| Item | Status |
|---|---|
| Testnet node (`assentian-node.service`) | ✅ Running — **PERLU RESTART pakai binary terbaru** (fix CheckPoUW + encryption belum aktif di servis ini!) |
| Multi-node sync (lokal) | ✅ Verified |
| **Node independen eksternal** (mesin terpisah, internet asli) | ✅ Verified — build + sync + MINING berhasil dari VM terpisah |
| Firewall/port 19333 dapat diakses dari luar | ✅ Verified |
| Block explorer | ✅ Live |
| DNS seeds | ❌ Belum (di-comment di chainparams.cpp) |
| Stratum mining pool | ⚠️ Kode ada, TIDAK sedang jalan, belum diverifikasi fungsional |
| Build system (autotools) fresh checkout | ✅ Diperbaiki hari ini | Sebelumnya gagal total di checkout baru |

## 4. Security

| Item | Status |
|---|---|
| Self-audit 13 Jun (`AUDIT.md`) | ⚠️ Verdict "key reuse impossible"-nya TERBUKTI SALAH, jangan dipercaya mentah |
| Key reuse / retirement | ✅ Fixed & verified |
| Encryption at rest | ✅ Fixed & verified |
| Sighash tidak include leaf_index | ⚠️ Masih terbuka secara teori, diredam praktis oleh key retirement |
| `CheckPoUW` pubkey parsing | ✅ Fixed (robust parsing) |
| **Audit eksternal independen** | ❌ Belum dilakukan — PRIORITAS sebelum mainnet beneran |
| Adversarial / fuzz testing | ❌ Belum |
| Bug bounty program | ❌ Belum |

## 5. Branding & Penamaan

| Item | Status |
|---|---|
| Ticker "SNTI" | ❌ **BENTROK** dengan Quant Network (market cap ~$1 miliar) — harus diganti sebelum launch publik |
| Nama/ticker final | 🔄 Dalam evaluasi — kandidat "Assentian-PQE" / SNTI relatif bersih, perlu verifikasi manual final di CoinMarketCap/CoinGecko |
| Genesis baru dengan nama final | ❌ Belum dibuat (genesis sekarang masih pakai pesan "SNTI") |

## 6. Dokumentasi & Legal

| Item | Status |
|---|---|
| `PROJECT_STATUS.md` (source of truth) | ✅ Aktif dijaga akurat |
| `README.md` | ✅ Ditulis ulang, akurat |
| Whitepaper | ⚠️ Perlu update kalau nama final berubah |
| Lisensi BSL-1.1 | ✅ Diterapkan |
| Audit eksternal profesional | ❌ Belum — lihat Section 4 |

---

## Urutan Prioritas Rekomendasi

1. **Selesaikan keputusan nama/ticker final** — ini blocker buat semua yang lain (genesis, whitepaper, branding)
2. **Restart `assentian-node.service` pakai binary terbaru** — fix hari ini (CheckPoUW, encryption) belum aktif di servis live
3. **Mine genesis baru** dengan nama final, di difficulty yang lebih realistis
4. **Audit keamanan eksternal** sebelum exposure publik lebih luas
5. Baru pertimbangkan: testnet publik resmi, stratum aktif, DNS seed, marketing/komunitas
