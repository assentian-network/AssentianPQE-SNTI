# QNT — Quantum Resistant Blockchain

> **The world's first mineable post-quantum cryptocurrency.**
> ⚠️ Nama/ticker "QNT" sedang dalam evaluasi ulang (bentrok dengan Quant Network yang sudah ada) — lihat [`PROJECT_STATUS.md`](PROJECT_STATUS.md) untuk status terkini.

QNT is a Bitcoin Core v27 fork with XMSS-SHA2_10_256 post-quantum signature scheme and SHA-256 Proof-of-Useful-Work (PoUW) mining.

**📍 Status project sebenarnya, real-time, ada di [`PROJECT_STATUS.md`](PROJECT_STATUS.md) — baca itu dulu sebelum file lain mana pun.**

## Overview

| Feature | Specification |
|---------|---------------|
| **Signature Scheme** | XMSS-SHA2_10_256 (NIST SP 800-208) |
| **Proof of Work** | SHA-256 + XMSS block signing (PoUW v1) |
| **Block Time** | 60 seconds |
| **Max Supply** | 21,000,000 QNT |
| **Halving Interval** | 210,000 blocks (~2 years, scaled for 60s blocks) |
| **P2P Port** | 9333 (mainnet), 19333 (testnet), 29333 (regtest, lokal) |
| **Address Prefix** | q (mainnet/testnet) |
| **Script Types** | (pubkey penuh), P2XMSSHASH (hash-commited, mirip P2PKH ) |

## Building from Source

**Catatan struktur folder:** repo ini nested — clone lalu `cd` ke subfolder:

```
bash
git clone https://github.com/asepganzu-svg/bitcoin-quant.git
# struktur sudah rata, tidak perlu cd ke subfolder

```

### Dependencies (Ubuntu/Debian)

```
bash
sudo apt update
sudo apt install -y build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 \
  libevent-dev libboost-dev libsqlite3-dev libssl-dev git

```
### Build

```
bash
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j$(nproc)

```
Build penuh dari nol bisa makan 15-30+ menit tergantung spek mesin. Hasil terverifikasi sukses di dua mesin independen (lihat `PROJECT_STATUS.md`).

### Binaries

- `src/bitcoind` — daemon node
- `src/bitcoin-cli` — RPC client
- `src/bitcoin-wallet` — wallet tool
- `src/bitcoin-tx` — transaction tool

## Quick Start (Regtest)

```
bash
./src/bitcoind -regtest -rpcport=18443 -daemon
./src/bitcoin-cli -regtest -rpcport=18443 createwallet "my_wallet"
ADDR=$(./src/bitcoin-cli -regtest -rpcport=18443 getnewaddress)
./src/bitcoin-cli -regtest -rpcport=18443 generatetoaddress 1 "$ADDR"
./src/bitcoin-cli -regtest -rpcport=18443 getbalance

```

## Quick Start (Regtest)

```
bash
./src/bitcoind -regtest -rpcport=18443 -daemon
./src/bitcoin-cli -regtest -rpcport=18443 createwallet "my_wallet"
ADDR=$(./src/bitcoin-cli -regtest -rpcport=18443 getnewaddress)
./src/bitcoin-cli -regtest -rpcport=18443 generatetoaddress 1 "$ADDR"
./src/bitcoin-cli -regtest -rpcport=18443 getbalance

```

### XMSS Address

```
bash
# Generate alamat XMSS baru
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=my_wallet getnewxmssaddress

# Cek info alamat (ismine, pubkey, leaf_index, remaining)
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=my_wallet getxmssaddressinfo ""

# Kirim ke alamat XMSS
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=my_wallet sendtoaddress "" 1.0

# Belanjakan dari alamat XMSS (PERHATIAN: setiap alamat XMSS cuma sekali pakai
# — otomatis "retired" setelah sign sekali, demi keamanan anti-reuse)
./src/bitcoin-cli -regtest -rpcport=18443 -rpcwallet=my_wallet sendfromxmssaddress "" "" 0.5

```

### Connect ke Testnet

```
bash
./src/bitcoind -testnet -connect=104.234.26.7:19333 -daemon
./src/bitcoin-cli -testnet getblockchaininfo

```

## Architecture

```
src/

├── wallet/

│   ├── xmss_signer.h/cpp	# CXMSSSigner — signing, state save/load, encryption at rest, key retirement

│   ├── xmss_address.h/cpp	# Address encoding (Base58Check)

│   └── rpc/xmss.h/cpp		# RPC commands (getnewxmssaddress, sendfromxmssaddress, dll)

├── script/

│   ├── interpreter.cpp	# OP_XMSS_CHECKSIG (0xBB) — verifikasi signature transaksi

│   └── sign.cpp		# CreateXMSSSig — signing transaksi

├── validation.cpp		# CheckPoUW() — verifikasi signature blok coinbase (BUKAN di pow.cpp)

└── rpc/

└── mining.cpp			# GenerateBlock() — loop mining PoUW

```


## XMSS Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | XMSS-SHA2_10_256 |
| Tree Height | 10 (maks 1024 signature per key — tapi wallet ini retire key setelah SEKALI pakai, demi keamanan) |
| Security Level | 256-bit |
| Public Key | 64 byte (root \|\| PUB_SEED) |
| Signature Size | ~2.500 byte |

## PoUW v1 Algorithm

1. Miner generate key pair XMSS baru per blok
2. Pubkey XMSS di-embed di coinbase OP_RETURN
3. Grinding nonce SHA-256 standar
4. Setelah PoW ketemu: sign hash blok pakai XMSS
5. Signature dimasukkan ke output OP_RETURN coinbase terpisah
6. Re-verifikasi PoW (merkle root berubah karena penambahan output signature)

Jangan percaya klaim status di file mana pun selain **[`PROJECT_STATUS.md`](PROJECT_STATUS.md)** — itu satu-satunya yang dijaga akurat & terverifikasi langsung. File historis (`AUDIT.md`, `FIX_LOG.md`, dll) punya banner penunjuk ke situ.

Belum ada audit eksternal independen. Lihat `MAINNET_LAUNCH_CHECKLIST.md` untuk daftar lengkap yang masih perlu dikerjakan sebelum mainnet.

## License

BSL-1.1, konversi ke GPL-2.0 pada 15/Jun/2030.

## References

- [NIST SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) — XMSS Signature Scheme
- [XMSS Reference Implementation](https://github.com/XMSS/xmss-reference)
- [Bitcoin Core](https://github.com/bitcoin/bitcoin) — Base codebase (v27)
