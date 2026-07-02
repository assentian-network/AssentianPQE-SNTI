# Assentian-PQE (SNTI) Mining Guide

> **Status**: Mainnet live sejak 26 Jun 2026. Mining menghasilkan SNTI yang sesungguhnya.
> Block reward: **50 SNTI/block**. Block time: **60 detik**.

## Daftar Isi

1. [Persyaratan](#1-persyaratan)
2. [Platform yang Didukung](#2-platform-yang-didukung)
3. [Instalasi & Build](#3-instalasi--build)
4. [Menjalankan Node](#4-menjalankan-node)
5. [CPU Mining (Solo)](#5-cpu-mining-solo)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Persyaratan

| Komponen | Minimum | Rekomendasi |
|---|---|---|
| CPU | 2 core | 4+ core |
| RAM | 2 GB | 4+ GB |
| Storage | 10 GB | 20+ GB |
| OS | Ubuntu 20.04+ | Ubuntu 22.04+ |
| Internet | Stabil | Stabil |

---

## 2. Platform yang Didukung

| Platform | Status | Catatan |
|---|---|---|
| **Ubuntu/Debian (native)** | ✅ Verified | Direkomendasikan |
| **WSL2 (Windows)** | ✅ Verified | Ubuntu layer di Windows |
| Windows native (MSVC) | ⚠️ Belum diuji | Mungkin perlu penyesuaian |
| macOS | ⚠️ Belum diuji | Mungkin perlu penyesuaian |
| Arch/Fedora/CentOS | ⚠️ Belum diuji | Dependency berbeda |

**Rekomendasi**: gunakan Ubuntu 22.04 native atau WSL2 untuk hasil terbaik.

---

## 3. Instalasi & Build

### Ubuntu/Debian & WSL2

**Install dependencies:**
```bash
sudo apt update
sudo apt install -y build-essential libtool autotools-dev automake \
  pkg-config bsdmainutils python3 libevent-dev libboost-dev \
  libsqlite3-dev libssl-dev git autoconf
```

**Clone & build:**
```bash
git clone https://github.com/assentian-network/snti.git
cd snti
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j$(nproc)
```

> ⚠️ Build memakan waktu 15-60 menit tergantung spek mesin.
> Kalau error `Killed` (kehabisan RAM), coba: `make -j1`

**Verifikasi build berhasil:**
```bash
./src/bitcoind --version
# Output: Bitcoin Core version v27.0.0
```

---

## 4. Menjalankan Node

### Connect ke Mainnet Assentian-PQE

```bash
./src/bitcoind \
  -addnode=seed.assentian.network \
  -daemon
```

**Cek status node:**
```bash
./src/bitcoin-cli getblockchaininfo
```

Output yang diharapkan:
```json
{
  "chain": "main",
  "blocks": 1170,
  "bestblockhash": "...",
  "verificationprogress": 1.0
}
```

**Tunggu sampai sync penuh** (`verificationprogress` = 1.0 dan `blocks` sama dengan node jaringan).

### Buat Wallet

```bash
./src/bitcoin-cli createwallet "snti_miner"
ADDR=$(./src/bitcoin-cli -rpcwallet=snti_miner getnewaddress)
echo "Alamat mining kamu: $ADDR"
```

Alamat SNTI dimulai dengan `snti1` (bech32m, post-quantum ready).

---

## 5. CPU Mining (Solo)

> **Catatan**: Pool mining (stratum) direncanakan Phase 3. Saat ini hanya solo mining yang tersedia.

### Method 1: Direct Mining (paling simpel)

```bash
# Mine 1 blok ke alamat kamu
./src/bitcoin-cli -rpcwallet=snti_miner generatetoaddress 1 "$ADDR"

# Mine terus-menerus (loop sederhana)
while true; do
  ./src/bitcoin-cli -rpcwallet=snti_miner generatetoaddress 1 "$ADDR"
  sleep 1
done
```

### Method 2: Mining Loop dengan Log

Simpan script ini sebagai `mine.sh`:
```bash
#!/bin/bash
ADDR=$1
if [ -z "$ADDR" ]; then
  echo "Usage: ./mine.sh <alamat_SNTI>"
  exit 1
fi

echo "Mining Assentian-PQE (SNTI) mainnet ke $ADDR"
echo "Ctrl+C untuk berhenti"
echo ""

BLOCKS=0
START=$(date +%s)

while true; do
  RESULT=$(./src/bitcoin-cli -rpcwallet=snti_miner generatetoaddress 1 "$ADDR" 2>&1)
  if echo "$RESULT" | grep -q '"'; then
    BLOCKS=$((BLOCKS + 1))
    NOW=$(date +%s)
    ELAPSED=$((NOW - START))
    echo "[$(date '+%H:%M:%S')] Blok #$BLOCKS ditemukan! Total waktu: ${ELAPSED}s"
  fi
done
```

Jalankan:
```bash
chmod +x mine.sh
./mine.sh "$ADDR"
```

### Cek Hasil Mining

```bash
# Cek saldo (butuh 100 konfirmasi sebelum bisa dipakai)
./src/bitcoin-cli -rpcwallet=snti_miner getbalance
./src/bitcoin-cli -rpcwallet=snti_miner getwalletinfo
```

### Generate Alamat XMSS (Post-Quantum Address)

```bash
# Generate alamat XMSS baru
./src/bitcoin-cli -rpcwallet=snti_miner getnewxmssaddress

# Cek info alamat XMSS
./src/bitcoin-cli -rpcwallet=snti_miner getxmssaddressinfo "<alamat_xmss>"
```

> ⚠️ **PENTING: JANGAN PERNAH jalankan `wallet.dat` yang sama di dua komputer/node sekaligus.**
> Alamat XMSS cuma aman dipakai signing **satu kali**. Proteksi "retired setelah signing" itu dicatat per-key di disk `wallet.dat` itu sendiri (dan untuk address hasil mining, juga di ledger terpadu terpisah di datadir — lihat [WHITEPAPER.md §13.1](WHITEPAPER.md)) — tapi kedua mekanisme itu TIDAK melindungi dari **backup yang basi**. Kalau kamu restore/copy snapshot `wallet.dat` yang diambil SEBELUM address itu pernah dipakai sign, lalu salinan asli DAN salinan restore-annya sama-sama sign pakai address XMSS yang sama (leaf_index sama), itu sama saja pakai one-time key dua kali. Secara matematis, attacker yang melihat dua signature dari key yang sama bisa merekonstruksi private key dan mencuri semua dana di alamat itu — ini bukan bug yang bisa dipatch, ini sifat dasar skema XMSS.
>
> **Ini TIDAK dideteksi oleh blockchain.** Pengecekan leaf-reuse di level consensus SNTI cuma melindungi proof mining yang nempel di tiap block (supaya 2 miner tidak bisa pakai leaf yang sama dari tree yang sama) — BUKAN transaksi kirim/spend biasa. Dua node independen yang sign transaksi kirim biasa dari address yang sama (hasil restore) akan sama-sama berhasil dan sama-sama diterima on-chain — tidak ada warning apapun dari jaringan.
>
> Perlakukan `wallet.dat` seperti seed phrase hardware wallet: restore ke **satu** node yang hidup, jangan simpan backup lalu dijalankan paralel "buat jaga-jaga", dan kalau migrasi ke mesin baru, matikan dulu node lama dan pastikan tetap offline sebelum menyalakan yang baru.

---

## 6. Troubleshooting

### Node tidak sync / 0 connections

```bash
# Cek koneksi
./src/bitcoin-cli getpeerinfo

# Tambah peer manual
./src/bitcoin-cli addnode "seed.assentian.network" "add"
./src/bitcoin-cli addnode "seed2.assentian.network" "add"
./src/bitcoin-cli addnode "seed3.assentian.network" "add"
```

### Build error: not enough RAM

```bash
# Build dengan 1 thread
make -j1
```

### RPC connection refused

Pastikan node sudah berjalan:
```bash
ps aux | grep bitcoind
# Kalau tidak ada, start ulang:
./src/bitcoind -daemon
```

### Lainnya

Buka GitHub Issues: https://github.com/assentian-network/snti/issues
