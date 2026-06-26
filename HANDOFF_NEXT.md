# HANDOFF_NEXT — Assentian-PQE (SNTI)
## Analisa & Next Step Menuju Mainnet
### Sesi: 26 Jun 2026

---

## STATUS CHAIN SAAT INI (26 Jun 2026 — update audit fix)

- Blocks: 465+ (aktif mining via stratum)
- Node: `assentian-node.service` ✅ Running via systemd (P2P:39333, RPC:39332)
- Stratum: `assentian-stratum.service` ✅ Running (port 3333, stats port 3334)
- Miner: `assentian-miner.service` ✅ NEW — cpuminer via systemd, auto-restart
- cpuminer: ✅ `/usr/local/bin/minerd` --threads=2 ~18 MH/s
- VM rumah (`114.79.6.173`): ✅ P2P sync ke VPS, blocks=465 match
- Mining address: `tty64fZ7nMaQ6SnRo79kotinQfRiwFKXWF` (XMSS key dari snti_testnet)
- Genesis: `0616e8b3...` (clean chain, semua blocks format 9-field)

**Catatan penting (26 Jun, sesi ini):**
- Datadir di-wipe (blocks+chainstate) karena mixed format (7-field lama + 9-field baru)
- VPS sync ulang dari VM rumah (462 blocks dalam <15 detik)
- Wallet backup ada di: `/root/wallets_backup_20260626_*/`
- Mining address baru (XMSS): `tty64fZ7nMaQ6SnRo79kotinQfRiwFKXWF`
- Address lama `tq1q...` tidak ada di wallet manapun (sudah tidak dipakai)

---

## AUDIT FIX — 26 Jun 2026 (commit 7ec14ed)

Audit menyeluruh dari `test_audit.md` diverifikasi dan 5 bug nyata diperbaiki.

### Bug yang DIFIX

| # | Severity | File | Fix |
|---|---|---|---|
| C1 | CRITICAL | `src/wallet/xmss_state.h`, `src/pouw.h` | SK sizing pakai `xmss_parse_oid()+params.sk_bytes` — hilangkan trim-trailing-zero yang bisa korupsi BDS state |
| C2 | CRITICAL | `src/wallet/xmss_keystore.h` | Tambah guard `leaf_index >= 1024` + LogPrintf sebelum Sign() |
| H3 | HIGH | `src/randombytes.c` | Ganti static-fd /dev/urandom (race condition) → `getrandom()` syscall |
| H6 | HIGH | `src/pow.cpp` | Rewrite `PermittedDifficultyTransition()` untuk EMA — versi lama reject semua block EMA di mainnet (`fPowAllowMinDifficultyBlocks=false`) |
| L3 | LOW | `src/kernel/chainparams.cpp` | Hapus `vFixedSeeds.clear()` baris 170 — mainnet seed nodes langsung di-clear setelah di-set |

### FALSE POSITIVE di audit (sudah benar / by design)

| # | Claim audit | Realita |
|---|---|---|
| C3 | Sig 2500 ≠ 2498 bytes | `params.c:739` hardcode `index_bytes=4` → 4+32+2144+320 = **2500** ✓ |
| C4 | Header 148 bytes breaking change | By design — SNTI bukan Bitcoin-compatible |
| H1 | Tidak flush setelah sign | Sudah ada `PersistXMSSState()` + `WalletBatch` di `wallet.cpp:2195` ✓ |
| H4 | malloc tanpa secure clear | `Clear()` → `SecureClear()` (volatile zero) sebelum `free()` di `xmss_bridge.cpp` ✓ |

### SKIP (bukan code fix)

| # | Alasan skip |
|---|---|
| H2 (VLA di xmss_core.c) | Upstream XMSS reference lib — perubahan rawan break signing/verification |
| H5 (1 seed node) | Butuh server infrastruktur tambahan, bukan code fix |
| M1–M6 (architecture) | Refactoring besar, jadwalkan di phase hardening |

---

## YANG DIKERJAKAN SESI INI (26 Jun 2026)

1. **cpuminer-multi di-build & install dari source** — tidak tersedia di apt
   - Binary: `/usr/local/bin/minerd`
   - Build: `git clone tpruvot/cpuminer-multi` + `./build.sh`

2. **Stratum + cpuminer verified end-to-end**
   - 18/18 shares accepted, 6 blocks mined dalam 30 detik test
   - Rate: ~9 MH/s SHA-256 per thread

3. **VM rumah confirmed konek** via stratum (bukan P2P)
   - IP: `114.79.6.173`, 9/9 shares accepted

4. **DEVDOCS.md diupdate** — Mining Guide ditambah:
   - Instruksi build cpuminer-multi dari source
   - Command mining lengkap
   - Cara verifikasi via stats endpoint
   - Commit: `c4aa556`

---

## ANALISA CELAH — JALAN KE MAINNET

### 🔴 BLOCKER KERAS (wajib selesai sebelum mainnet publik)

| # | Celah | Lokasi | Keterangan |
|---|---|---|---|
| 1 | **Audit keamanan eksternal** | Semua | Self-audit 13 Jun terbukti salah (verdict "key reuse impossible" keliru). Tidak ada audit independen sama sekali |
| 2 | **Mainnet genesis masih PLACEHOLDER** | `chainparams.cpp:147` | nBits=0x207fffff (testnet difficulty). Comment eksplisit: *"do not use for mainnet launch"*. Genesis PoUW v2 resmi dengan powLimit nyata (2^256/156) belum pernah di-mine |
| 3 | **Chain reorg belum pernah diuji** | `validation.cpp:2079` | `SNTI Fix2: unmark PoUW leaf index on reorg` ada tapi belum diverifikasi berjalan. Kalau reorg handling salah → node bisa split |

### 🟠 PENTING (perlu selesai sebelum testnet publik luas)

| # | Celah | Lokasi | Keterangan |
|---|---|---|---|
| 4 | **DEBUG log di production code** | `validation.cpp:3983` | `LogPrintf("PoUW v2 DEBUG: CheckPoUWv2 result=%d\n", v2_ok)` — LogPrintf selalu print, spam log di setiap block |
| 5 | **Node P2P eksternal belum sync PoUW v2** | Network | VM rumah konek via stratum bukan P2P. Belum ada node lain yang sync blockchain via P2P (port 39333) dengan PoUW v2 |
| 6 | **EMA difficulty belum diuji under load** | `pow.cpp` | Alpha=0.1, target 60s — dengan 1 miner sangat volatile. Perlu diuji miner masuk/keluar |
| 7 | **Fuzz testing belum ada** | `CheckPoUWv2()` | Menerima data eksternal dari network. Input malformed belum pernah di-fuzz |

### 🟡 PERLU DIVERIFIKASI ULANG

| # | Item | Keterangan |
|---|---|---|
| 8 | `exportxmsskey` / `importxmsskey` | Fix ada di git history tapi belum ditest di build PoUW v2 (setelah chain wipe 24 Jun) |
| 9 | Wallet backup/restore | Belum ditest sama sekali |
| 10 | Sighash-v2 analisis formal | Fix 21 Jun menutup cross-index recombination attack secara teknis tapi belum dianalisis formal |

### 🟡 INFRASTRUKTUR

| # | Item | Keterangan |
|---|---|---|
| 11 | DNS seeds | Di-comment di chainparams.cpp — tunggu domain sendiri |
| 12 | Bug bounty program | Belum ada |
| 13 | Explorer stats fmtHashps | Fungsi missing di index.html, stats masih format v1 |

---

## YANG SELESAI SESI 26 JUN 2026

| # | Item | Status | Commit |
|---|---|---|---|
| 1 | Hapus 5x DEBUG LogPrintf di validation.cpp | ✅ Done | `1f9c995` |
| 2 | Test chain reorg via invalidateblock/reconsiderblock | ✅ LULUS | — |
| - | cpuminer-multi build+install | ✅ Done | `c4aa556` |
| - | DEVDOCS Mining Guide update | ✅ Done | `c4aa556` |

**Hasil reorg test (26 Jun 02:41 UTC):**
- Block 38 di-disconnect → rollback ke height 37 ✅
- Node switch ke chain alternatif (d5f24cfb height=38) ✅
- Mining lanjut dengan XMSS leaf tracking (leaf=81, 82) ✅
- Tidak ada crash ✅
- Chain terpanjang menang (height 40 > 38) ✅

**Catatan penting — block file corruption:**
- Root cause: dua proses bitcoind berjalan bersamaan (service Restart=on-failure loop + manual -daemon)
- Fix: RestartSec=30 + StartLimitBurst=3 di service file
- Jangan jalankan bitcoind manual saat service running

---

## URUTAN NEXT STEP (prioritas)

```
1. ✅ DONE — Hapus DEBUG LogPrintf di validation.cpp:3983
2. ✅ DONE — Test chain reorg paksa di testnet
3. ✅ DONE — Verifikasi exportxmsskey/importxmsskey di build PoUW v2
   - listxmsskeys: 3 key (tty64fZ, tiP76f, tXKv9v) ✅
   - exportxmsskey "tty64fZ7..." → pubkey+seckey terpisah ✅
   - importxmsskey pubkey seckey "label" ke snti_importtest → address match ✅
   - getxmssaddressinfo → ismine:true, leaf_index:0, remaining:1024 ✅
   - Catatan: importxmsskey butuh 2 arg terpisah (pubkey, seckey) — bukan 1 blob
4. ✅ DONE (sesi 26 Jun) — Verifikasi wallet backup/restore
   - backupwallet → snti_testnet_backup.dat (40KB sqlite) ✅
   - Copy backup → wallets/snti_restore_test/wallet.dat → loadwallet ✅
   - listxmsskeys: 3 key match persis (address, pubkey, leaf_index, remaining) ✅
   - balance: 99.99973050 match ✅ | txcount: 3 match ✅
   - ismine: true di restored wallet ✅
   - Backup file disimpan di: /root/.assentian_testnet/testnet3/wallets/ (per wallet)
5. ✅ DONE (sesi 26 Jun) — Test P2P sync dari VM rumah (port 39333)
   - VM 114.79.6.173 build dari scratch ✅
   - Genesis mismatch (2d858f51 vs 0616e8b3) → root cause: chainparams uncommitted
   - Fix: commit semua uncommitted VPS changes ke GitHub (b2a5657, a3bff97)
   - VM git pull → rebuild (make -j1) → wipe datadir → restart node
   - VM sync BERHASIL: blocks=456, headers=456 (sama dengan VPS) ✅
   - Genesis match terbukti: sync tidak mungkin terjadi kalau genesis beda
   - Pelajaran: SELALU commit perubahan consensus-critical sebelum test P2P
6. ✅ DONE — Fix explorer stats (fmtHashps missing)
   - Tambah fungsi fmtHashps() dengan SI prefix: H/s, KH/s, MH/s ... EH/s
   - Stats grid sebelumnya crash (ReferenceError) → sekarang render normal
   - Label "Network Hash/s" → "Network Rate (est.)" untuk PoUW v2
   - Commit: 5adb509
7. ✅ DONE — Mine mainnet genesis resmi
   - nTime=1782474812 (Fri Jun 26 11:53:32 UTC 2026)
   - nBits=0x2001a41a (= powLimit mainnet 2^256/156)
   - Genesis hash: b4a26aef52f6f5038815f26917cb0ea1fd3b3b13fbc7cfb5c541088a6943a5ba
   - Commit: 4044d53
   - Binary mainnet siap di /root/Assentian-PQE/SNTI/src/bitcoind
   - Launch mainnet: ./src/bitcoind -datadir=~/.snti_mainnet (tanpa -testnet flag)
8. ✅ DONE (sesi 26 Jun, commit 6adb517) — Fix critical block index corruption bug
   - Root cause: CDiskBlockIndex::SERIALIZE_METHODS tidak menyimpan xmssRoot, nLeafIndex,
     commitmentsRoot ke LevelDB (blocks/index/). Hanya 7 fields lama yang disimpan.
   - Akibat: ConstructBlockHash() menghasilkan hash berbeda dari GetHash() sebenarnya
     karena commitmentsRoot tidak tersimpan. LoadChainTip() gagal karena LookupBlockIndex
     tidak bisa menemukan tip hash dari chainstate.
   - Fix: src/chain.h — tambah 3 fields ke CDiskBlockIndex::SERIALIZE_METHODS dan
     ConstructBlockHash(). Juga tambah commitmentsRoot ke CBlockIndex struct.
   - Fix: src/node/blockstorage.cpp — load commitmentsRoot dari disk ke CBlockIndex
     di LoadBlockIndexGuts.
   - Hasil: node restart stabil tanpa reindex. Diverifikasi 2x restart berturut-turut.
9. ✅ DONE (sesi 26 Jun) — Fix 5 bugs dari audit menyeluruh (test_audit.md)
   - C1: SK corruption trim-trailing-zero → pakai xmss_parse_oid()+params.sk_bytes
   - C2: Tidak ada exhaustion guard di Sign() → tambah leaf_index>=1024 check
   - H3: randombytes.c thread-unsafe (static fd) → ganti getrandom() syscall
   - H6: PermittedDifficultyTransition reject EMA block di mainnet → rewrite
   - L3: vFixedSeeds.clear() hapus seed nodes mainnet → remove clear() line
   - Commit: 7ec14ed | Push: github.com/asepganzu-svg/AssentianPQE-SNTI
10. [?]        Audit keamanan eksternal (budget & waktu)
11. [?]        DNS seeds (perlu domain sendiri)
```

---

## COMMAND REFERENSI CEPAT

```bash
# Cek node
cd ~/Assentian-PQE/SNTI
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 getblockchaininfo

# Mine manual
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 \
  -rpcclienttimeout=300 \
  generatetoaddress 1 "tq1qftvdv0xh4534talv2axxfp5fh57mn4gl7x2cpl" 100

# Stratum stats
curl http://127.0.0.1:3334/

# Jalankan cpuminer
minerd -a sha256d \
  -o stratum+tcp://127.0.0.1:3333 \
  -u tq1qftvdv0xh4534talv2axxfp5fh57mn4gl7x2cpl \
  -p x --threads=$(nproc)

# Load wallet (setelah restart node)
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 loadwallet snti_testnet
```

---

## FILE KUNCI

| File | Fungsi |
|---|---|
| `src/pouw_v2.h` | Core PoUW v2: BuildAndSign(), CheckPoUWv2(), CalcNextTargetEMA() |
| `src/validation.cpp:3902` | CheckPoUW() — consensus critical |
| `src/validation.cpp:3983` | **DEBUG log yang perlu dihapus** |
| `src/kernel/chainparams.cpp:147` | Mainnet genesis PLACEHOLDER |
| `src/script/interpreter.cpp:1757` | Sighash-v2 implementation |
| `stratum_server.py` | Stratum hybrid server |
| `MAINNET_LAUNCH_CHECKLIST.md` | Checklist lengkap per 25 Jun 2026 |
