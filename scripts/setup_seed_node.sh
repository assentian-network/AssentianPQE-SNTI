#!/bin/bash
# ============================================================
# SNTI Seed Node Setup — assentian.network
# Jalankan sebagai root di VPS baru (Ubuntu 22.04 x86_64)
# Usage: bash setup_seed_node.sh
# ============================================================
set -e

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; NC="\033[0m"
ok()  { echo -e "${GREEN}[OK]${NC} $1"; }
inf() { echo -e "${YELLOW}[..] $1${NC}"; }
err() { echo -e "${RED}[ERR] $1${NC}"; exit 1; }

MAIN_NODE="104.234.26.7"
BINARY_URL="https://assentian.network/bin/bitcoind"
DATADIR="/root/.bitcoin"
RPC_USER="snti"
RPC_PASS=$(tr -dc 'a-f0-9' </dev/urandom | head -c 48)
SERVICE="assentian-seed-node"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   SNTI Seed Node Installer               ║"
echo "  ║   Post-Quantum Blockchain — assentian    ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# ── 1. Dependencies ───────────────────────────────────────────
inf "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
    libminiupnpc17 libnatpmp1 libevent-2.1-7 libsqlite3-0 \
    libboost-filesystem1.74.0 libboost-thread1.74.0 \
    ufw curl wget 2>/dev/null || true
ok "Dependencies installed"

# ── 2. Download binary ────────────────────────────────────────
inf "Downloading sntid binary from $BINARY_URL..."
mkdir -p /usr/local/bin
wget -q --show-progress -O /usr/local/bin/sntid "$BINARY_URL"
chmod +x /usr/local/bin/sntid
ok "Binary installed: $(/usr/local/bin/sntid --version 2>/dev/null | head -1 || echo 'sntid')"

# ── 3. bitcoin.conf ───────────────────────────────────────────
inf "Creating config..."
mkdir -p "$DATADIR"
cat > "$DATADIR/bitcoin.conf" <<EOF
[main]
port=9333
rpcport=9332
rpcuser=$RPC_USER
rpcpassword=$RPC_PASS
rpcallowip=127.0.0.1
server=1
listen=1
maxconnections=125
dbcache=256
txindex=0

# Seed node: connect to main node on startup
addnode=$MAIN_NODE:9333
EOF
chmod 600 "$DATADIR/bitcoin.conf"
ok "Config created at $DATADIR/bitcoin.conf"

# ── 4. Systemd service ────────────────────────────────────────
inf "Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=SNTI Seed Node (Post-Quantum Blockchain)
After=network.target
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sntid \
  -datadir=$DATADIR \
  -rpcuser=$RPC_USER \
  -rpcpassword=$RPC_PASS \
  -rpcallowip=127.0.0.1 \
  -port=9333
ExecStop=/usr/local/bin/sntid \
  -datadir=$DATADIR \
  -rpcuser=$RPC_USER \
  -rpcpassword=$RPC_PASS stop
KillMode=none
TimeoutStopSec=120
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE"
ok "Systemd service created and enabled"

# ── 5. UFW firewall ───────────────────────────────────────────
inf "Configuring firewall..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp comment 'SSH'
ufw allow 9333/tcp comment 'SNTI P2P'
ufw --force enable >/dev/null
ok "UFW: 22/tcp + 9333/tcp open, all else denied"

# ── 6. Start node ─────────────────────────────────────────────
inf "Starting seed node..."
systemctl start "$SERVICE"
sleep 8

# Verify
BLOCKS=$(timeout 10 /usr/local/bin/sntid \
    -datadir="$DATADIR" \
    -rpcuser="$RPC_USER" \
    -rpcpassword="$RPC_PASS" \
    getblockcount 2>/dev/null || echo "syncing")
ok "Node started — blocks: $BLOCKS"

# ── 7. Summary ────────────────────────────────────────────────
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")
echo ""
echo "═══════════════════════════════════════════════"
echo "  SNTI Seed Node Setup Complete!"
echo "═══════════════════════════════════════════════"
echo "  Public IP  : $PUBLIC_IP"
echo "  P2P Port   : 9333"
echo "  Datadir    : $DATADIR"
echo "  Service    : $SERVICE"
echo "  RPC Pass   : $RPC_PASS  (simpan ini!)"
echo ""
echo "  Status check:"
echo "  systemctl status $SERVICE"
echo ""
echo "  Kirim IP ini ke operator VPS utama:"
echo "  >>> $PUBLIC_IP <<<"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Node akan sync dari $MAIN_NODE:9333"
echo "  Biasanya selesai dalam < 1 menit (chain masih kecil)"
echo ""
