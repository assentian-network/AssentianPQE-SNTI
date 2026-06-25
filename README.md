# SNTI — Assentian-PQE Quantum Resistant Blockchain

> **The world's first mineable post-quantum cryptocurrency.**
> Bitcoin Core v27 fork with XMSS-SHA2_10_256 post-quantum signature scheme and XMSS Proof-of-Useful-Work (PoUW v2) mining.

## Overview

| Feature | Specification |
|---------|---------------|
| **Ticker** | SNTI |
| **Signature Scheme** | XMSS-SHA2_10_256 (NIST SP 800-208) |
| **Proof of Work** | PoUW v2 — XMSS tree building (no SHA-256 nonce) |
| **Block Time** | 60 seconds |
| **Max Supply** | ~210,000,000 SNTI |
| **Initial Block Reward** | 50 SNTI |
| **Halving Interval** | 2,100,000 blocks (~4 years at 60s/block) |
| **P2P Port** | 9333 (mainnet), 19333 (testnet), 29333 (regtest) |
| **RPC Port** | 8332 (mainnet), 18332 (testnet), 18443 (regtest) |
| **Address Prefix** | `qn1` (mainnet), `tq1` (testnet), `qnr1` (regtest) |
| **Script Types** | P2XMSS (pubkey known), P2XMSSHASH (hash-committed, mirip P2PKH) |

## Building from Source

### Dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libtool autotools-dev automake pkg-config \
  bsdmainutils python3 libevent-dev libboost-dev libsqlite3-dev libssl-dev git
```

### Build

```bash
git clone https://github.com/asepganzu-svg/AssentianPQE-SNTI.git
cd AssentianPQE-SNTI
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j$(nproc)
```

Build dari nol bisa 15–30+ menit tergantung spek mesin.

### Binaries

| Binary | Path | Fungsi |
|--------|------|--------|
| Node daemon | `src/bitcoind` | Full node |
| RPC client | `src/bitcoin-cli` | Interaksi RPC |
| Wallet tool | `src/bitcoin-wallet` | Manajemen wallet |
| TX builder | `src/bitcoin-tx` | Buat transaksi raw |

---

## Quick Start (Regtest)

```bash
./src/bitcoind -regtest -rpcport=18443 -daemon
./src/bitcoin-cli -regtest -rpcport=18443 createwallet "my_wallet"
ADDR=$(./src/bitcoin-cli -regtest -rpcport=18443 getnewaddress)
./src/bitcoin-cli -regtest -rpcport=18443 generatetoaddress 1 "$ADDR"
./src/bitcoin-cli -regtest -rpcport=18443 getbalance
```

### XMSS Address (Regtest)

```bash
# Generate alamat XMSS baru
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=my_wallet getnewxmssaddress

# Cek info alamat (ismine, pubkey, leaf_index, remaining)
XMSS_ADDR="<address dari output di atas>"
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=my_wallet getxmssaddressinfo "$XMSS_ADDR"

# Kirim ke alamat XMSS (via generic sendtoaddress — menghasilkan P2XMSSHASH)
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=my_wallet sendtoaddress "$XMSS_ADDR" 1.0

# Belanjakan dari alamat XMSS
# PENTING: setiap alamat XMSS hanya sekali pakai — otomatis "retired" setelah sign
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=my_wallet sendfromxmssaddress "$XMSS_ADDR" "<dest_addr>" 0.5
```

---

## Connect ke Testnet (VPS)

Node testnet berjalan di VPS `104.234.26.7`:

```bash
# Node listen di port 39333 (override dari default 19333)
./src/bitcoind -testnet \
  -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password \
  -rpcport=39332 -port=39333 \
  -rpcallowip=127.0.0.1 \
  -walletcrosschain \
  -daemon

# Cek status
./src/bitcoin-cli -testnet -datadir=/root/.assentian_testnet \
  -rpcuser=user -rpcpassword=password -rpcport=39332 \
  getblockchaininfo
```

Explorer: http://104.234.26.7
Stratum: `stratum+tcp://104.234.26.7:3333`

---

## Architecture

```
src/
├── pouw_v2.h               # PoUW v2: PoUWv2Proof, CheckPoUWv2(), CalcNextTargetEMA()
├── primitives/block.h      # CBlockHeader — xmssRoot, nLeafIndex, commitmentsRoot
├── pow.cpp                 # EMA difficulty adjustment
├── validation.cpp          # CheckPoUWv2() — verifikasi blok PoUW v2
├── rpc/mining.cpp          # GenerateBlock() — loop mining (SK_SEED search)
├── wallet/
│   ├── xmss_signer.h/cpp  # CXMSSSigner — signing, state, key retirement
│   └── rpc/xmss.h/cpp     # RPC: getnewxmssaddress, sendfromxmssaddress, dll
└── script/
    ├── interpreter.cpp     # OP_XMSS_CHECKSIG — verifikasi sig transaksi (5-chunk)
    └── sign.cpp            # SignStep() — signing transaksi XMSS
```

---

## PoUW v2 Algorithm

PoUW v2 menggantikan SHA-256 nonce grinding sepenuhnya. XMSS tree building **adalah** proof-of-work-nya.

1. Miner pilih SK_SEED acak (96 bytes: SK_SEED | SK_PRF | PUB_SEED)
2. Bangun XMSS-SHA2_10_256 tree tinggi 10 (~6 detik, 4 core CPU)
3. Ekstrak `xmssRoot` (32-byte Merkle root)
4. Cek: `xmssRoot < target` — jika tidak, ulangi dari langkah 1
5. Jika valid: sign hash blok dengan key di leaf index 0
6. Embed auth_path + WOTS+ signature di coinbase OP_RETURN (2660 bytes)
7. Broadcast blok

**`nNonce` selalu 0** — tidak ada nonce grinding di PoUW v2.

**EMA difficulty**: per-blok dengan alpha=0.1, target 60 detik.

### Key lifecycle mining

Setiap percobaan mining menghasilkan key XMSS baru dan hanya memakai index 0 dari kapasitas 1024 signature. Ini disengaja: menghindari risiko persistensi state yang crash-unsafe. Index 1023 tidak pernah dipakai (ada known bug di reference library — lihat DEVDOCS.md).

---

## XMSS Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | XMSS-SHA2_10_256 |
| Tree Height | 10 (1024 leaves) |
| Security Level | 256-bit post-quantum |
| Public Key | 64 bytes (root \|\| PUB_SEED) |
| Signature Size | ~2,500 bytes |
| OID | 0x00000001 |

---

## XMSS Address Model

SNTI menggunakan **swept one-time-address** untuk spending:
- Setiap alamat XMSS dipakai **paling banyak sekali** untuk spending (index 0)
- Setelah sign, key langsung `retired` — wallet menolak sign kedua kali di alamat yang sama
- Dana kembalian otomatis ke alamat XMSS baru

Dua jenis script output:
- **P2XMSS** — `<64-byte-pubkey> OP_XMSS_CHECKSIG` (pubkey diketahui sender)
- **P2XMSSHASH** — `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_XMSS_CHECKSIG` (seperti P2PKH — sender hanya punya hash, pubkey direveal saat spend)

`sendtoaddress` ke alamat XMSS menghasilkan P2XMSSHASH secara otomatis.

---

## Status Aktif (Jun 25 2026)

| Item | Status |
|------|--------|
| PoUW v2 mining | ✅ Berjalan |
| P2XMSS + P2XMSSHASH spending | ✅ Berjalan |
| XMSS key retirement | ✅ Berjalan |
| Stratum server (hybrid) | ✅ Berjalan |
| WOTS+ verification di CheckPoUWv2 | ✅ Berjalan (auth_path non-zero, result=1 di semua blok) |
| DNS seeds | 🟡 Belum (tunggu domain) |

Detail teknis lengkap: lihat [`DEVDOCS.md`](DEVDOCS.md).

---

## References

- [NIST SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) — XMSS Signature Scheme
- [XMSS Reference Implementation](https://github.com/XMSS/xmss-reference)
- [Bitcoin Core](https://github.com/bitcoin/bitcoin) — Base codebase (v27)

## License

BSL-1.1, konversi ke GPL-2.0 pada 15/Jun/2030.
