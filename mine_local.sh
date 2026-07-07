#!/bin/bash
# SNTI Local Mining Script
# Jalankan di PC/VirtualBox yang ada node SNTI-nya

# ============================================================
# EDIT DI SINI sesuai kebutuhan Anda
CLI_BIN_MANUAL=""        # Contoh: "/home/asep/snti-miner/bitcoin-cli"
DATADIR_MANUAL=""        # Contoh: "/home/asep/.snti_mainnet"
MINE_TO_ADDRESS=""       # Kosong = generate address baru lokal
                         # Isi dengan address web wallet Anda agar koin
                         # langsung masuk ke dashboard assentian.network/wallet/
                         # Contoh: "snti1zpygrxrn3mdt75a3epjjjh0y2c6dxgl4w2ne86t"
# ============================================================

DATADIR="${SNTI_DATADIR:-${DATADIR_MANUAL:-${HOME}/.snti_mainnet}}"
RPC_USER="${SNTI_RPC_USER:-snti}"
RPC_PASS="${SNTI_RPC_PASS:-test123}"
RPC_PORT="${SNTI_RPC_PORT:-9332}"
BLOCKS="${1:-10}"

# Auto-detect bitcoin-cli
SEARCH_PATHS=(
    "${CLI_BIN}"
    "bitcoin-cli"
    "./src/bitcoin-cli"
    "${HOME}/snti/bitcoin-cli"
    "${HOME}/bitcoin-cli"
    "${HOME}/bitcoind-snti/bitcoin-cli"
    "/usr/local/bin/bitcoin-cli"
    "/opt/snti/bitcoin-cli"
)

CLI_BIN="$CLI_BIN_MANUAL"
for p in "${SEARCH_PATHS[@]}"; do
    [ -z "$p" ] && continue
    if command -v "$p" &>/dev/null 2>&1 || [ -x "$p" ]; then
        CLI_BIN="$p"
        break
    fi
done

if [ -z "$CLI_BIN" ]; then
    echo "ERROR: bitcoin-cli tidak ditemukan"
    echo ""
    echo "Cari dulu dengan perintah ini:"
    echo "  find / -name 'bitcoin-cli' 2>/dev/null"
    echo ""
    echo "Lalu jalankan dengan path lengkap, contoh:"
    echo "  CLI_BIN=/home/user/bitcoin-cli bash mine_local.sh 10"
    exit 1
fi

CLI="$CLI_BIN -datadir=$DATADIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT"

echo "=== SNTI Local Miner ==="
echo "Datadir : $DATADIR"
echo "RPC port: $RPC_PORT"
echo "Blocks  : $BLOCKS"
echo ""

# Cek node running
echo "[1] Cek node..."
HEIGHT=$($CLI getblockcount 2>&1)
if ! [[ "$HEIGHT" =~ ^[0-9]+$ ]]; then
    echo "    ERROR: Node tidak bisa diakses"
    echo "    Detail: $HEIGHT"
    echo ""
    echo "    Cara start node:"
    echo "    bitcoind -datadir=$DATADIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT -daemon"
    exit 1
fi
echo "    Node OK, height: $HEIGHT"

# Tentukan address tujuan mining
echo ""
echo "[2] Address tujuan mining..."
if [ -n "$MINE_TO_ADDRESS" ]; then
    ADDRESS="$MINE_TO_ADDRESS"
    echo "    Pakai address web wallet : $ADDRESS"
    echo "    (koin langsung masuk dashboard assentian.network/wallet/)"
else
    # Generate address baru dari node lokal
    ADDR_JSON=$($CLI getnewxmssaddress 2>&1)
    if ! echo "$ADDR_JSON" | python3 -c "import sys,json; json.load(sys.stdin)" > /dev/null 2>&1; then
        echo "    ERROR: $ADDR_JSON"
        echo ""
        echo "    Wallet belum loaded. Coba:"
        echo "    $CLI createwallet snti_wallet"
        exit 1
    fi
    ADDRESS=$(echo "$ADDR_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['address'])")
    REMAINING=$(echo "$ADDR_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['remaining'])")
    echo "    Generate address lokal   : $ADDRESS"
    echo "    Remaining leaves         : $REMAINING"
    echo ""
    echo "    TIP: Isi MINE_TO_ADDRESS di atas dengan address web wallet Anda"
    echo "    agar koin langsung masuk ke assentian.network/wallet/"
fi

# Mine
echo ""
echo "[3] Mining $BLOCKS blok ke $ADDRESS..."
echo "    (ini bisa lama, tergantung difficulty)"
echo ""

RESULT=$($CLI generatetoaddress "$BLOCKS" "$ADDRESS" 2>&1)

if echo "$RESULT" | python3 -c "import sys,json; blocks=json.load(sys.stdin); [print('  Blok '+b[:16]+'...') for b in blocks]; print(f'\nTotal: {len(blocks)} blok mined!')" 2>/dev/null; then
    END_HEIGHT=$($CLI getblockcount)
    echo ""
    echo "=== SELESAI ==="
    echo "Height: $HEIGHT → $END_HEIGHT"
    BALANCE=$($CLI getbalances 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['mine']['immature'])" 2>/dev/null || echo "cek manual")
    echo "Balance immature: $BALANCE SNTI"
else
    echo "ERROR: $RESULT"
    echo ""
    echo "Kemungkinan penyebab:"
    echo "  1. Node belum sync penuh → tunggu sampai height=$HEIGHT stabil"
    echo "  2. XMSS state corrupted → hapus $DATADIR/xmss_miner_state.bin"
    echo "  3. Wallet tidak ada wallet loaded → $CLI createwallet snti_wallet"
fi
