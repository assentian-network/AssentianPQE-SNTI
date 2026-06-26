# HANDOFF_NEXT — Assentian-PQE (SNTI)
## Analisa & Next Step Menuju Mainnet
### Sesi: 26 Jun 2026

---

## STATUS CHAIN SAAT INI

- Blocks: 10+ (aktif mining via stratum)
- Node: `assentian-node.service` ✅ Running (P2P:39333, RPC:39332)
- Stratum: `assentian-stratum.service` ✅ Running (port 3333, stats port 3334)
- cpuminer: ✅ Installed di `/usr/local/bin/minerd`
- VM rumah (`114.79.6.173`): ✅ Mining via stratum, semua shares accepted
- Miner address VM: `tq1qgccyyw9khr4uqs8z4qzh7rds077czttredxrds`

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

## URUTAN NEXT STEP (prioritas)

```
1. [5 menit]  Hapus DEBUG LogPrintf di validation.cpp:3983
2. [1 jam]    Test chain reorg paksa di testnet
3. [30 menit] Verifikasi exportxmsskey/importxmsskey di build saat ini
4. [30 menit] Verifikasi wallet backup/restore
5. [1 jam]    Test P2P sync dari VM rumah (bukan stratum, tapi port 39333)
6. [2 jam]    Fix explorer stats (fmtHashps missing)
7. [?]        Mine mainnet genesis resmi (timing sesuai keputusan launch)
8. [?]        Audit keamanan eksternal (budget & waktu)
9. [?]        DNS seeds (perlu domain sendiri)
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
