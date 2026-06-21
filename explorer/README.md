# QNT Block Explorer

A lightweight web block explorer for **Quant (QNT)** — a Bitcoin Core-based post-quantum cryptocurrency.

## Features

- **Network stats** — block height, difficulty, connections, mempool size
- **Latest blocks** — browse the most recent 20 blocks
- **Block detail** — hash, height, timestamp, merkle root, nonce, difficulty, size, and all transactions
- **Transaction detail** — inputs, outputs, fees, size, block confirmation
- **Address detail** — balance, UTXO count, transaction history
- **Search** — accepts block hash/height, txid, or address
- **Dark theme** — easy on the eyes

## Architecture

```
index.html  <-- single-page frontend (HTML + CSS + vanilla JS)
    |
    | AJAX calls to /api/*
    |
server.py   <-- Flask backend (proxies bitcoind JSON-RPC)
    |
    | HTTP JSON-RPC
    |
bitcoind    <-- QNT node (Bitcoin Core-based)
```

## Prerequisites

- Python 3.7+
- Flask (`pip install flask`)
- requests (`pip install requests`)
- A running `bitcoind` instance with RPC enabled

## Installation

```bash
cd /root/Assentian-PQE/SNTI/explorer

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask requests
```

## Configuration

Configure the RPC connection using environment variables:

| Variable | Default | Description |
|---|---|---|
| `QNT_RPC_URL` | `http://127.0.0.1:29332` | Full RPC URL |
| `QNT_RPC_USER` | `user` | RPC username |
| `QNT_RPC_PASSWORD` | `password` | RPC password |
| `QNT_RPC_HOST` | `127.0.0.1` | RPC host (used if URL not set) |
| `QNT_RPC_PORT` | `29332` | RPC port (used if URL not set) |
| `QNT_EXPLORER_PORT` | `8080` | Explorer web port |
| `QNT_EXPLORER_DEBUG` | `0` | Set to `1` for Flask debug mode |

### Network Ports

| Network | P2P Port | RPC Port |
|---|---|---|
| mainnet | 9333 | 9332 |
| testnet | 19333 | 19332 |
| regtest | 29333 | 29332 |

## Running the Explorer

### 1. Start bitcoind (regtest example)

```bash
bitcoind -regtest -daemon -rpcuser=user -rpcpassword=password -rpcport=29332
```

### 2. Start the explorer

```bash
# Default (regtest on localhost:29332)
python3 server.py

# Custom RPC
QNT_RPC_URL=http://127.0.0.1:9332 QNT_RPC_USER=myuser QNT_RPC_PASSWORD=mypass python3 server.py

# Custom port
QNT_EXPLORER_PORT=3000 python3 server.py
```

### 3. Open in browser

Navigate to `http://localhost:8080`

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Serves the frontend (index.html) |
| `GET /api/status` | Network info, block height, difficulty, connections |
| `GET /api/blocks/latest?count=20` | Latest N blocks |
| `GET /api/block/<hash_or_height>` | Block detail with transactions |
| `GET /api/tx/<txid>` | Transaction detail |
| `GET /api/address/<address>` | Address info, balance, tx history |

## Notes

- The address page requires the address index to be enabled in bitcoind (`-addressindex=1`). Without it, balance and tx history will be empty.
- For regtest, you may need to generate some blocks first: `bitcoin-cli -regtest generate 101`
- The explorer does not write to the blockchain — it is read-only.
