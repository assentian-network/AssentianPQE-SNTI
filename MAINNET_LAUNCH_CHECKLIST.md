# Mainnet Launch Checklist

**Diperbarui: 25 Jun 2026.** Berdasarkan verifikasi langsung dari kode, log node, dan sesi pengembangan aktif. Item yang status-nya berubah dari checklist sebelumnya (20-21 Jun) diberi catatan.

---

## 1. Consensus & Protocol

| Item | Status | Catatan |
|---|---|---|
| Genesis block (testnet) | ✅ Done | Chain wipe 24 Jun 2026 — genesis baru PoUW v2, nTime=1782275807, nNonce=0, nBits=0x207fffff |
| **PoUW v2 implementation** | ✅ Done | SHA-256 nonce grinding dihapus total — XMSS tree building IS the PoW (major milestone 24 Jun) |
| `OP_XMSS_CHECKSIG` verifikasi signature transaksi | ✅ Verified | Real, bukan stub |
| `CheckPoUWv2()` verifikasi blok — root < target | ✅ Verified | Berjalan di setiap blok |
| `CheckPoUWv2()` verifikasi blok — WOTS+ signature | ✅ Verified | **Diperbarui 25 Jun:** auth_path non-zero, `xmss_sign_open()` lulus di semua blok (log: `result=1`). Sebelumnya dilaporkan disabled di handoff note 24 Jun — sudah resolved oleh commit 5409c3f |
| XMSS miner state persistence (leafIndex) | ✅ Fixed | Commit 01e54a0 — state tidak ter-load karena SK size limit salah, sudah diperbaiki |
| WOTS+ leaf reuse vulnerability | ✅ Fixed | Commit f8788c6 — miner bisa reuse leaf jika save state gagal, sudah diperbaiki dengan abort |
| EMA difficulty adjustment per-block | ✅ Implemented | alpha=0.1, alpha=60s target, clamped [T/4, T×4] |
| Key retirement / anti-reuse XMSS (TX signing) | ✅ Verified | One-time-use per address |
| Multi-node consensus agreement (PoUW v2) | ❌ Belum diverifikasi | Chain wipe 24 Jun — perlu re-verifikasi dengan PoUW v2 blocks. Node eksternal belum sync ulang |
| Chain reorg handling dengan blok PoUW v2 | ❌ Belum diuji | Belum pernah dipaksa fork/reorg dengan PoUW v2 |
| Difficulty retarget di bawah beban nyata | ❌ Belum diuji | EMA terimplementasi tapi belum diuji multi-miner berhari-hari |
| Mainnet genesis | ⚠️ Placeholder | Code says "PLACEHOLDER — do not use for mainnet launch". nNonce=26 (PoUW v1, 23 Jun) sudah outdated. Genesis PoUW v2 resmi perlu dibuat saat launch nyata |

## 2. Wallet & RPC

| Item | Status | Catatan |
|---|---|---|
| `getnewxmssaddress`, `sendfromxmssaddress`, `getxmssaddressinfo` | ✅ Verified | |
| P2XMSSHASH (hash-committed funding via `sendtoaddress`) | ✅ Verified | |
| Encryption at rest (XMSS state) | ✅ Verified end-to-end | |
| `exportxmsskey` / `importxmsskey` | ⚠️ Belum diverifikasi ulang | Diklaim fixed di histori lama, belum diuji di build PoUW v2 |
| Wallet backup / restore dengan XMSS state | ❌ Belum diuji | |

## 3. Network & Infrastructure

| Item | Status | Catatan |
|---|---|---|
| Testnet node (`assentian-node.service`) | ✅ Running | Binary terbaru, berjalan sejak 25 Jun. Port P2P override ke 39333 |
| Block explorer (`assentian-explorer.service`) | ✅ Live | **Fix 25 Jun:** orphan process di port 8081 menyebabkan crash loop — sudah resolved |
| Stratum server (`assentian-stratum.service`) | ✅ Verified fungsional | **Fix 25 Jun:** `generatetoaddress` ke wallet endpoint gagal diam-diam — diperbaiki ke root RPC + load wallet + mining lock. End-to-end test lulus: 3 shares → block mined |
| Multi-node sync lokal | ⚠️ Perlu re-verifikasi | Sebelumnya verified, tapi setelah chain wipe + PoUW v2 belum diuji ulang |
| Node independen eksternal | ❌ Perlu re-verifikasi | VM terpisah sebelumnya berhasil sync, tapi itu era PoUW v1. Perlu sync ulang dengan PoUW v2 |
| Firewall / port dapat diakses dari luar | ✅ Verified | Port P2P 39333 (override dari default 19333), stratum 3333 |
| DNS seeds | ❌ Belum | Di-comment di chainparams.cpp — tunggu domain sendiri |
| Build system (autotools) fresh checkout | ✅ Verified | |

## 4. Security

| Item | Status | Catatan |
|---|---|---|
| Key reuse / retirement (TX signing) | ✅ Fixed & verified | |
| WOTS+ leaf reuse (mining) | ✅ Fixed | Commit f8788c6 — abort jika save state gagal setelah sign |
| XMSS miner state load | ✅ Fixed | Commit 01e54a0 — SK size limit menyebabkan state tidak ter-load |
| WOTS+ verification di CheckPoUWv2 | ✅ Verified aktif | Konfirmasi 25 Jun dari log node |
| Encryption at rest | ✅ Fixed & verified | |
| Sighash tidak include `nLeafIndex` (TX signing) | ⚠️ Masih terbuka | Secara teori memungkinkan replay jika key retirement tidak berjalan. Diredam praktis oleh one-time-address enforcement, tapi belum dianalisis formal |
| `CheckPoUW` pubkey parsing | ✅ Fixed | Sekarang `CheckPoUWv2()` dengan full WOTS+ verify |
| Self-audit 13 Jun (`AUDIT.md`) | ⚠️ Jangan dipercaya | Verdict "key reuse impossible"-nya terbukti salah |
| **Audit eksternal independen** | ❌ Belum | PRIORITAS sebelum mainnet beneran |
| Adversarial / fuzz testing | ❌ Belum | |
| Bug bounty program | ❌ Belum | |

## 5. Branding & Penamaan

| Item | Status | Catatan |
|---|---|---|
| Nama project | ✅ Decided | **Assentian-PQE**, ticker **SNTI** — genesis string: "Assentian-PQE 22/Jun/2026 XMSS Post Quantum Era - For Sentia" |
| Konflik ticker SNTI | ⚠️ Perlu verifikasi final | Sebelumnya dilaporkan bentrok dengan Quant Network — project tetap lanjut sebagai SNTI. Verifikasi manual di CoinMarketCap/CoinGecko sebelum listing publik |
| Mainnet genesis dengan nama final | ⚠️ Belum | Code mainnet genesis masih placeholder — perlu genesis PoUW v2 resmi saat launch |

## 6. Dokumentasi

| Item | Status | Catatan |
|---|---|---|
| `README.md` | ✅ Diperbarui 25 Jun | Rewrite lengkap: nama, PoUW v2, max supply, ports, address prefix, repo URL |
| `DEVDOCS.md` | ✅ Diperbarui 25 Jun | Rewrite: semua konten QNT/PoUW v1 stale sudah dikoreksi |
| Whitepaper | ✅ v1.1 (25 Jun) | Security fixes + klaim akurat |
| `PROJECT_STATUS.md` | ⚠️ Perlu dicek | Terakhir akurat per 20-21 Jun — belum diperbarui setelah PoUW v2 |
| Lisensi BSL-1.1 | ✅ Diterapkan | Konversi ke GPL-2.0 pada 15/Jun/2030 |
| Audit eksternal profesional | ❌ Belum | Lihat Section 4 |

---

## Urutan Prioritas (per 25 Jun 2026)

1. **Re-verifikasi multi-node dengan PoUW v2** — chain wipe 24 Jun memutus semua external node, perlu node kedua sync ulang dari genesis baru
2. **Audit keamanan eksternal** — tidak ada perubahan signifikansi ini; wajib sebelum exposure publik lebih luas
3. **Test chain reorg dengan PoUW v2** — belum pernah diuji, potensi edge case di `CheckPoUWv2()` saat reorganisasi
4. **Test difficulty retarget under load** — EMA terimplementasi tapi belum divalidasi dengan banyak miner aktif
5. **Perbarui `PROJECT_STATUS.md`** — belum disentuh sejak PoUW v2 masuk
6. **Verifikasi final konflik ticker SNTI** — sebelum listing publik manapun
7. **Genesis mainnet resmi** — saat ini placeholder, harus di-mine ulang saat launch nyata
8. Baru pertimbangkan: testnet publik resmi, DNS seed, marketing/komunitas
