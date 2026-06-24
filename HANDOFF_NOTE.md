# 📋 HANDOFF NOTE — Assentian-PQE (SNTI)
## Sesi Claude berikutnya — 24 Jun 2026

---

## IDENTITAS PROJECT
- Nama: Assentian-PQE (SNTI) — Asep + Sentia + Post Quantum Era
- Ticker: SNTI
- Email: assentianpqe@gmail.com | Copyright: Asep Mulya
- GitHub: https://github.com/asepganzu-svg/AssentianPQE-SNTI
- VPS IP: 104.234.26.7
- Working dir VPS: /root/Assentian-PQE/SNTI/

---

## INFRASTRUKTUR LIVE (VPS)

| Service | Status | Port |
|---|---|---|
| assentian-node.service | ✅ Active | P2P:39333, RPC:39332 |
| assentian-explorer.service | ✅ Active | HTTP:80 |
| assentian-stratum.service | ⚠️ Belum diupdate ke v2 | Stratum:3333 |

Node flags: `-walletcrosschain`

Wallets:
- snti_testnet — dibuat fresh (chain wipe 24 Jun 2026)
- Address mining: tq1qftvdv0xh4534talv2axxfp5fh57mn4gl7x2cpl

---

## GENESIS FINAL (PoUW v2)

nTime:  1782275807 (Jun 24 2026)
nBits:  0x2001a41a
nNonce: 0 (unused in PoUW v2)
hash:   d02122cd370f2f541406331ec72c4f527b46b07545d148abb940374baff9f756
powLimit: 01a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a41a4

---

## YANG SELESAI HARI INI (24 Jun 2026)

### PoUW v2 ✅ MAJOR MILESTONE
- SHA-256 nonce grinding DIHAPUS TOTAL
- XMSS tree building = proof of work
- Miner search SK_SEED sampai xmssRoot < target
- New field: CBlockHeader::xmssRoot
- EMA per-block difficulty (alpha=0.1)
- powLimit = 2^256/156
- pouw_v2.h: BuildAndSign(), CheckPoUWv2(), CalcNextTargetEMA()
- xmssmt_core_seed_keypair() di xmss_core_fast.c
- 2 blocks confirmed ✅

### Fix 2: XMSS on-chain leaf index tracking ✅
- Commit: 8837c72

### Whitepaper ✅
- WHITEPAPER.md v1.0 + section 7 PoUW v2
- whitepaper.html regenerated

### Explorer ✅
- Stats grid 12 items (mining + stratum data)
- whitepaper route added

### Comments ✅
- 147 occurrences // QNT → // SNTI

---

## YANG BELUM SELESAI ⚠️

### 1. 🔴 Stratum server belum support PoUW v2
- assentian-stratum.service masih PoUW v1 format
- cpuminer tidak bisa mine karena format block berubah
- Perlu update stratum untuk submit xmssRoot bukan nNonce

### 2. 🔴 WOTS+ verification di CheckPoUWv2() disabled
- Saat ini hanya cek root < target (PoW check)
- auth_path selalu zero karena BDS state issue
- Perlu fix BuildAndSign() untuk extract auth_path dengan benar
- File: src/pouw_v2.h fungsi BuildAndSign() dan CheckPoUWv2()

### 3. 🟠 Explorer stats masih PoUW v1 format
- fmtHashps function missing di index.html
- Mining stats perlu update untuk PoUW v2

### 4. 🟠 VM rumah mining
- Belum setup — butuh node sync dulu
- RPC port 39332 tidak dibuka ke publik (security)

### 5. 🟡 DNS Seeds
- Tunggu domain sendiri

### 6. 🟡 Audit Scope Document
- File: AUDIT_SCOPE_RFP.md (sudah dibuat, belum commit)

---

## INFO TEKNIS PENTING

### RPC Commands
```bash
# Cek node
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 getblockchaininfo

# Load wallet
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 loadwallet snti_testnet

# Mine blocks
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 \
  -rpcclienttimeout=300 \
  generatetoaddress 1 "tq1qftvdv0xh4534talv2axxfp5fh57mn4gl7x2cpl" 100
```

### Build
```bash
cd ~/Assentian-PQE/SNTI
make -j$(nproc) 2>&1 | tail -8
```

### PoUW v2 Key Files
- src/pouw_v2.h — core PoUW v2 implementation
- src/primitives/block.h — xmssRoot field
- src/pow.cpp — EMA difficulty
- src/rpc/mining.cpp — XMSS tree search loop
- src/validation.cpp — CheckPoUWv2()
- src/kernel/chainparams.cpp — genesis + powLimit

### WOTS+ Fix (priority utama)
Problem: auth_path selalu zero karena xmssmt_core_seed_keypair
tidak mengisi BDS state dengan benar setelah tree build.
Solusi kandidat:
1. Extract auth_path langsung dari treehash() output
2. Pakai xmss_sign() output langsung (sudah include auth_path)
3. Simpan auth_path saat keypair generation

---

## CATATAN UNTUK CLAUDE BERIKUTNYA

1. Selalu `cd ~/Assentian-PQE/SNTI` dulu
2. Load wallet setelah restart: `loadwallet snti_testnet`
3. Mine timeout panjang: `-rpcclienttimeout=300` (tree build ~6s/attempt)
4. Jangan gunakan stratum untuk mining — belum support v2
5. CheckPoUWv2 saat ini hanya cek root < target (WOTS verify disabled)
6. Chain wipe sudah terjadi — blocks dari sebelum 24 Jun hilang
7. Commit terbaru: dcdd3eb
