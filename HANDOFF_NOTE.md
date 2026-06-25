# 📋 HANDOFF NOTE — Assentian-PQE (SNTI)
## Sesi Claude berikutnya — 25 Jun 2026

---

## IDENTITAS PROJECT
- Nama: Assentian-PQE (SNTI) — Asep + Sentia + Post Quantum Era
- Ticker: SNTI
- Email: assentianpqe@gmail.com | Copyright: Asep Mulya
- GitHub: https://github.com/asepganzu-svg/AssentianPQE-SNTI
- VPS IP: 104.234.26.7
- Working dir: /root/Assentian-PQE/SNTI/

---

## INFRASTRUKTUR

| Service | Status | Port |
|---|---|---|
| assentian-node.service | ⚠️ Unstable (crash setelah mine) | P2P:39333, RPC:39332 |
| assentian-explorer.service | ✅ Active | HTTP:80 |
| assentian-stratum.service | ❌ Belum update ke v2 | 3333 |

Mining address: tq1qftvdv0xh4534talv2axxfp5fh57mn4gl7x2cpl
Wallet: snti_testnet

RPC command mining:
```bash
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 \
  -rpcclienttimeout=1200 \
  generatetoaddress 1 "tq1qftvdv0xh4534talv2axxfp5fh57mn4gl7x2cpl" 2000000
```

---

## HISTORY LENGKAP — APA YANG SUDAH DIKERJAKAN

### Sesi 22-23 Jun 2026
| Task | Status | Commit |
|---|---|---|
| Genesis block mainnet | ✅ | — |
| XMSS Fix 1: write-before-use | ✅ | — |
| Stratum Wave 2 direct payout | ✅ | — |
| WHITEPAPER.md v1.0 (15 sections) | ✅ | — |
| sighash-v2 + cross-index replay fix | ✅ | — |

### Sesi 23 Jun 2026
| Task | Status | Commit |
|---|---|---|
| Fix 2: On-chain XMSS leaf index tracking | ✅ | 8837c72 |
| Whitepaper HTML v0.2→v1.0 | ✅ | 1b47c6f |
| Explorer stats 6→12 items (mining+stratum) | ✅ | e0aa716 |
| Explorer whitepaper route | ✅ | cb2beb4 |
| 147× // QNT → // SNTI rename | ✅ | 5f97563 |
| Whitepaper section 7 PoUW history | ✅ | 8674cff |

### Sesi 24-25 Jun 2026 — MAJOR: Pure PoUW v2
| Task | Status | Commit |
|---|---|---|
| SHA-256 nonce DIHAPUS TOTAL | ✅ | 5409c3f |
| CBlockHeader: field xmssRoot ditambah | ✅ | 5409c3f |
| CBlockHeader: field nLeafIndex ditambah | ✅ | 5409c3f |
| pow.cpp: EMA per-block difficulty | ✅ | 5409c3f |
| pouw_v2.h: BuildAndSign, CheckPoUWv2 | ✅ | 5409c3f |
| xmss_core_fast.c: xmssmt_core_seed_keypair | ✅ | 5409c3f |
| mining.cpp: XMSS tree search loop | ✅ | 5409c3f |
| validation.cpp: CheckPoUWv2 | ✅ | 5409c3f |
| xmss_miner_state.h: persistent miner state | ✅ | 5409c3f |
| Genesis baru Jun 24 2026 | ✅ | 5409c3f |
| powLimit = 2^256/156 | ✅ | 5409c3f |
| Fix heap corruption (pakai xmss_keypair biasa) | ✅ | 5409c3f |
| 2 blocks confirmed on-chain | ✅ | — |
| Whitepaper section 7 update PoUW v2 | ✅ | dcdd3eb |
| PoUW v2 Key Derivation: pouw_v2_keyder.h | ✅ WIP | latest |
| CBlockHeader: commitmentsRoot field | ✅ WIP | latest |
| mining.cpp: collect 20 failed seeds | ✅ WIP | latest |
| validation.cpp: verify commitmentsRoot | ✅ WIP | latest |

---

## YANG BELUM SELESAI / MASALAH AKTIF

### 🔴 CRITICAL: Node crash setelah mine block
**Gejala:** Node crash (heap corruption) setelah ProcessNewBlock berhasil. Height kembali ke 0 setelah restart.
**Lokasi:** `UpdateTip` → `GetStateFor` → `malloc: corrupted size vs. prev_size`
**Stack trace:** versionbits.cpp:37 dipanggil dari validation.cpp:2863
**Kemungkinan penyebab:** 
- `commitmentsRoot` field baru di CBlockHeader menyebabkan buffer overflow
- Atau PoUWv2Proof serialization terlalu besar untuk coinbase
**File terkait:** src/primitives/block.h, src/pouw_v2.h, src/rpc/mining.cpp

### 🔴 CRITICAL: uint64 counter overflow di mining loop
**Gejala:** `attempt 18446744073708551975` (wrap dari ~-40)
**Lokasi:** src/rpc/mining.cpp, variabel `max_tries`
**Fix:** Ganti `uint64_t` dengan `int64_t` atau tambah check `max_tries > 0`

### 🔴 PoUW v2 Key Derivation belum tested end-to-end
**Status:** Code ada (pouw_v2_keyder.h) tapi belum pernah berhasil verify karena node crash
**Yang perlu:** 
1. Fix node crash dulu
2. Mine block dengan 10+ failed seeds
3. Verify log "X seeds embedded, commitmentsRoot=..."
4. Verify log "derived X wallet keys"

### 🟠 WOTS+ verification disabled
**Status:** CheckPoUWv2() hanya cek root < target
**File:** src/pouw_v2.h fungsi CheckPoUWv2()
**Note:** auth_path tersimpan di proof tapi tidak diverifikasi

### 🟠 Stratum server belum support PoUW v2
**Status:** Stratum masih PoUW v1 format
**Impact:** cpuminer tidak bisa mine

### 🟡 DNS Seeds
**Status:** Tunggu domain sendiri

### 🟡 Explorer stats update (fmtHashps missing)
**Status:** fungsi fmtHashps hilang di index.html

### 🟡 Audit Scope Document
**File:** AUDIT_SCOPE_RFP.md (sudah dibuat)

---

## INFO TEKNIS PENTING

### File-file Kunci PoUW v2
src/pouw_v2.h              — Core PoUW v2 (BuildAndSign, CheckPoUWv2, EMA)

src/pouw_v2_keyder.h       — Key derivation dari failed seeds (HKDF, FailedSeedList)

src/xmss_miner_state.h     — Persistent miner XMSS state (BuildNewTree, SignWithState)

src/primitives/block.h     — CBlockHeader dengan xmssRoot+nLeafIndex+commitmentsRoot

src/pow.cpp                — EMA difficulty adjustment

src/rpc/mining.cpp         — XMSS tree search mining loop + failed seed collection

src/validation.cpp         — CheckPoUWv2 + verify commitmentsRoot

src/kernel/chainparams.cpp — Genesis Jun 24 2026, powLimit=2^256/156, nBits=0x2001a41a
### Build Command
```bash
cd ~/Assentian-PQE/SNTI
make -j$(nproc) 2>&1 | tail -5
```

### Node Commands
```bash
# Wipe + restart (kalau stuck)
sudo systemctl stop assentian-node.service
rm -rf /root/.assentian_testnet/testnet3/
sudo systemctl start assentian-node.service
sleep 6

# Load wallet
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 \
  loadwallet snti_testnet

# Mine (WAJIB -rpcclienttimeout=1200 dan max_tries=2000000)
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 \
  -rpcclienttimeout=1200 \
  generatetoaddress 1 "tq1qftvdv0xh4534talv2axxfp5fh57mn4gl7x2cpl" 2000000
```

### Analisis Key Derivation Flow (sudah didesign, belum fully tested)
Mining attempt (failed):

SK_SEED_i → build XMSS tree → root_i > target → COLLECT
Setelah 20 failed seeds terkumpul + block valid ditemukan:

commitmentsRoot = MerkleRoot([commitment_0..19])

→ disimpan di block.commitmentsRoot (header)

→ seed list embed di coinbase OP_RETURN (FSL magic)
Node verify:

Extract FSL dari coinbase
Verify MerkleRoot(FSL) == block.commitmentsRoot
Derive: WalletSeed_i = HKDF(SK_SEED_i, "SNTI-WalletDerivation-v1", commitment_i)
Generate XMSS keypair dari WalletSeed_i → usable wallet key

Security: Miner tidak bisa fake seeds karena commitmentsRoot di-bind ke block header
---

## CATATAN UNTUK CLAUDE BERIKUTNYA

1. **Prioritas utama: Fix node crash** — heap corruption di UpdateTip setelah ProcessNewBlock
2. Cek apakah `commitmentsRoot` field di CBlockHeader menyebabkan serialization issue
3. Fix uint64 overflow: ganti `DEFAULT_MAX_TRIES - max_tries` di counter mining
4. Setelah node stabil, test key derivation end-to-end
5. Jangan lupa `-rpcclienttimeout=1200` saat mine
6. Load wallet setelah setiap restart node
7. Commit terbaru: lihat `git log --oneline -5`
