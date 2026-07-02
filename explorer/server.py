#!/usr/bin/env python3
"""
Assentian-PQE Block Explorer - Flask Backend
Proxies bitcoind RPC calls for the Quant post-quantum cryptocurrency block explorer.
"""

import os
import re
import json
import sqlite3
import secrets
import time
import bcrypt
import requests
import jwt as pyjwt
from flask import Flask, jsonify, request, send_from_directory
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

_EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
_SNTI_ADDR_RE = re.compile(r'^(snti|tsnti|sntirt)1[ac-hj-np-z02-9]{38,87}$')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SNTI_DIR = os.path.dirname(BASE_DIR)
app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

JWT_EXP_HOURS = 24
DB_PATH = os.path.join(BASE_DIR, "wallet.db")
_JWT_SECRET_FILE = os.path.join(BASE_DIR, ".jwt_secret")

def _load_jwt_secret() -> str:
    """Return JWT secret from env var, falling back to a file-persisted secret.
    Using a random secret per-process-start (secrets.token_hex) would invalidate
    all existing tokens on every restart. The file ensures the secret survives
    restarts without requiring the operator to set an env var manually.
    Production deployments should set SNTI_JWT_SECRET via systemd Environment=.
    """
    env_secret = os.environ.get("SNTI_JWT_SECRET", "")
    if env_secret:
        return env_secret
    if os.path.exists(_JWT_SECRET_FILE):
        with open(_JWT_SECRET_FILE, "r") as f:
            stored = f.read().strip()
        if len(stored) >= 32:
            return stored
    new_secret = secrets.token_hex(32)
    try:
        with open(_JWT_SECRET_FILE, "w") as f:
            f.write(new_secret)
        os.chmod(_JWT_SECRET_FILE, 0o600)
    except OSError:
        pass
    return new_secret

JWT_SECRET = _load_jwt_secret()

# ---------------------------------------------------------------------------
# Wallet DB init
# ---------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        xmss_address TEXT,
        miner_rpc_pass TEXT,
        created_at INTEGER NOT NULL
    )""")
    # Migrate existing DB
    cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "miner_rpc_pass" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN miner_rpc_pass TEXT")
    if "miner_last_seen" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN miner_last_seen INTEGER DEFAULT 0")
    if "miner_hostname" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN miner_hostname TEXT")
    conn.execute("""CREATE TABLE IF NOT EXISTS watch_addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        address TEXT NOT NULL,
        label TEXT,
        created_at INTEGER NOT NULL,
        UNIQUE(user_id, address),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    conn.commit()
    conn.close()

init_db()

def _hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()

def _check_pw(pw: str, stored: str) -> bool:
    return bcrypt.checkpw(pw.encode(), stored.encode())

def _make_token(user_id, username, scope="full"):
    payload = {"sub": user_id, "usr": username, "scope": scope, "exp": int(time.time()) + JWT_EXP_HOURS * 3600}
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

def _decode_token():
    """Validate the bearer token and stash claims on `request`. Returns an
    error (jsonify, status) tuple on failure, or None on success."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401
    try:
        payload = pyjwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        return jsonify({"error": "token expired"}), 401
    except Exception:
        return jsonify({"error": "invalid token"}), 401
    request.user_id = payload["sub"]
    request.username = payload["usr"]
    # SNTI SECURITY FIX (2 Jul 2026): tokens minted before this fix have no
    # "scope" claim -- treat those as "full" so existing sessions don't get
    # logged out. Only newly-issued installer tokens carry scope="installer".
    request.token_scope = payload.get("scope", "full")
    return None

def jwt_required(f):
    """Accepts any valid token regardless of scope (installer or full)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        err = _decode_token()
        if err:
            return err
        return f(*args, **kwargs)
    return decorated

def jwt_required_full(f):
    """SNTI SECURITY FIX (2 Jul 2026): rejects the long-lived, narrow-purpose
    installer token (see _generate_install_script). That token is embedded in
    a plaintext .sh file users download and can easily leak/get shared
    (support tickets, gists, screen shares) -- it must only ever be able to
    call the miner heartbeat/watch endpoints it was actually issued for, never
    balance/send/export-key/backup-file/change-password."""
    @wraps(f)
    def decorated(*args, **kwargs):
        err = _decode_token()
        if err:
            return err
        if request.token_scope != "full":
            return jsonify({"error": "this token cannot access this endpoint"}), 403
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RPC_USER = os.environ.get("SNTI_RPC_USER", "snti")
RPC_PASSWORD = os.environ.get("SNTI_RPC_PASSWORD", "test123")
RPC_HOST = os.environ.get("QNT_RPC_HOST", "127.0.0.1")
RPC_PORT = os.environ.get("SNTI_RPC_PORT", "9332")
RPC_URL = os.environ.get(
    "SNTI_RPC_URL", f"http://{RPC_HOST}:{RPC_PORT}"
)

# ---------------------------------------------------------------------------
# RPC helper
# ---------------------------------------------------------------------------

def rpc_call(method, params=None):
    """Make a JSON-RPC call to bitcoind."""
    if params is None:
        params = []
    payload = {
        "jsonrpc": "1.0",
        "id": "qnt-explorer",
        "method": method,
        "params": params,
    }
    try:
        resp = requests.post(
            RPC_URL,
            auth=(RPC_USER, RPC_PASSWORD),
            json=payload,
            timeout=30,
        )
        # SNTI FIX (2 Jul 2026): bitcoind returns HTTP 500 (not 200) for many
        # normal JSON-RPC errors (insufficient funds, invalid address, etc.)
        # but still sends a proper {"error": {...}} JSON body. Calling
        # raise_for_status() before reading that body threw it away and
        # replaced it with a generic, useless "500 Server Error" string that
        # the frontend then showed users instead of the real reason.
        try:
            data = resp.json()
        except ValueError:
            resp.raise_for_status()
            raise
        if isinstance(data, dict) and data.get("error") is not None:
            return {"error": data["error"]}
        resp.raise_for_status()
        return data.get("result")
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to bitcoind at {RPC_URL}"}
    except requests.exceptions.Timeout:
        return {"error": "RPC call timed out"}
    except Exception as e:
        return {"error": str(e)}

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    return response

# ---------------------------------------------------------------------------
# Serve frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/dashboard")
def dashboard():
    import os
    qnt_dir = os.path.dirname(BASE_DIR)
    return send_from_directory(qnt_dir, "dashboard.html")

@app.route("/changelog")
def changelog():
    import os
    qnt_dir = os.path.dirname(BASE_DIR)
    return send_from_directory(qnt_dir, "changelog.html")

@app.route("/changelog.html")
def changelog_html():
    import os
    qnt_dir = os.path.dirname(BASE_DIR)
    return send_from_directory(qnt_dir, "changelog.html")

@app.route("/project-status")
@app.route("/project-status.html")
def project_status_html():
    import os
    qnt_dir = os.path.dirname(BASE_DIR)
    return send_from_directory(qnt_dir, "project-status.html")

# ---------------------------------------------------------------------------
# API: git commits (changelog)
# ---------------------------------------------------------------------------

@app.route("/api/commits")
def api_commits():
    """Return recent git commits from the SNTI repo."""
    import subprocess
    count = request.args.get("count", 10, type=int)
    count = min(max(count, 1), 50)
    try:
        result = subprocess.run(
            ["git", "log", f"--max-count={count}", "--format=%H|%s|%ai"],
            capture_output=True, text=True, timeout=10,
            cwd=os.path.dirname(BASE_DIR)
        )
        if result.returncode != 0:
            return jsonify({"error": result.stderr.strip(), "commits": []})
        commits = []
        for line in result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|", 2)
                commits.append({
                    "hash": parts[0].strip(),
                    "message": parts[1].strip(),
                    "date": parts[2].strip() if len(parts) > 2 else ""
                })
        return jsonify({"commits": commits})
    except Exception as e:
        return jsonify({"error": str(e), "commits": []})

# ---------------------------------------------------------------------------
# API: network status
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    info = rpc_call("getnetworkinfo")
    if "error" in info:
        return jsonify(info), 502

    mining = rpc_call("getmininginfo")
    mempool = rpc_call("getmempoolinfo")

    return jsonify({
        "version": info.get("version"),
        "subversion": info.get("subversion"),
        "protocolversion": info.get("protocolversion"),
        "connections": info.get("connections"),
        "connections_in": info.get("connections_in", 0),
        "connections_out": info.get("connections_out", 0),
        "networkactive": info.get("networkactive"),
        "relayfee": info.get("relayfee"),
        "blocks": mining.get("blocks"),
        "difficulty": mining.get("difficulty"),
        "networkhashps": mining.get("networkhashps"),
        "mempool_txs": mempool.get("size", 0),
        "mempool_bytes": mempool.get("bytes", 0),
        "chain": mining.get("chain"),
        "warnings": info.get("warnings", ""),
    })

# ---------------------------------------------------------------------------
# API: latest blocks
# ---------------------------------------------------------------------------

@app.route("/api/blocks/latest")
def api_blocks_latest():
    count = request.args.get("count", 20, type=int)
    count = min(max(count, 1), 100)

    info = rpc_call("getblockchaininfo")
    if "error" in info:
        return jsonify(info), 502

    tip_height = info.get("blocks", 0)
    blocks = []
    for h in range(tip_height, max(tip_height - count, -1), -1):
        if h < 0:
            break
        bh = rpc_call("getblockhash", [h])
        if isinstance(bh, dict) and "error" in bh:
            continue
        block = rpc_call("getblock", [bh, 1])
        if isinstance(block, dict) and "error" in block:
            continue
        blocks.append({
            "hash": block.get("hash"),
            "height": block.get("height"),
            "time": block.get("time"),
            "mediantime": block.get("mediantime"),
            "nonce": block.get("nonce"),
            "difficulty": block.get("difficulty"),
            "size": block.get("size"),
            "strippedsize": block.get("strippedsize"),
            "weight": block.get("weight"),
            "tx_count": len(block.get("tx", [])),
            "merkleroot": block.get("merkleroot"),
            "bits": block.get("bits"),
            "confirmations": block.get("confirmations"),
            "xmssRoot": block.get("xmssRoot"),
            "nLeafIndex": block.get("nLeafIndex"),
        })

    return jsonify({"blocks": blocks, "tip_height": tip_height})

# ---------------------------------------------------------------------------
# API: block detail
# ---------------------------------------------------------------------------

@app.route("/api/block/<identifier>")
def api_block(identifier):
    # Determine if identifier is a height or hash
    if identifier.isdigit():
        block_hash = rpc_call("getblockhash", [int(identifier)])
        if isinstance(block_hash, dict) and "error" in block_hash:
            return jsonify(block_hash), 404
    else:
        block_hash = identifier

    block = rpc_call("getblock", [block_hash, 2])
    if isinstance(block, dict) and "error" in block:
        return jsonify(block), 404

    # Summarise transactions (limit decoded txs to avoid huge payloads)
    txs = block.get("tx", [])
    tx_summaries = []
    for tx in txs[:50]:  # cap at 50 for performance
        txid = tx.get("txid", tx.get("hash"))
        vin_summary = []
        vout_summary = []
        for vin in tx.get("vin", []):
            if "coinbase" in vin:
                vin_summary.append({"coinbase": True, "value": 0})
            else:
                vin_summary.append({
                    "txid": vin.get("txid"),
                    "vout": vin.get("vout"),
                    "address": None,  # resolved below if possible
                    "value": None,
                })
        for vout in tx.get("vout", []):
            addrs = vout.get("scriptPubKey", {}).get("addresses", [])
            if not addrs:
                addrs = vout.get("scriptPubKey", {}).get("address", [])
                if isinstance(addrs, str):
                    addrs = [addrs]
            vout_summary.append({
                "value": vout.get("value"),
                "n": vout.get("n"),
                "addresses": addrs,
                "type": vout.get("scriptPubKey", {}).get("type"),
            })
        tx_summaries.append({
            "txid": txid,
            "size": tx.get("size"),
            "vsize": tx.get("vsize"),
            "weight": tx.get("weight"),
            "fee": tx.get("fee"),
            "vin": vin_summary,
            "vout": vout_summary,
        })

    return jsonify({
        "hash": block.get("hash"),
        "height": block.get("height"),
        "time": block.get("time"),
        "mediantime": block.get("mediantime"),
        "nonce": block.get("nonce"),
        "xmssRoot": block.get("xmssRoot"),
        "nLeafIndex": block.get("nLeafIndex"),
        "difficulty": block.get("difficulty"),
        "size": block.get("size"),
        "strippedsize": block.get("strippedsize"),
        "weight": block.get("weight"),
        "merkleroot": block.get("merkleroot"),
        "bits": block.get("bits"),
        "confirmations": block.get("confirmations"),
        "previousblockhash": block.get("previousblockhash"),
        "nextblockhash": block.get("nextblockhash"),
        "tx_count": len(txs),
        "transactions": tx_summaries,
    })

# ---------------------------------------------------------------------------
# API: transaction detail
# ---------------------------------------------------------------------------

@app.route("/api/tx/<txid>")
def api_tx(txid):
    tx = rpc_call("getrawtransaction", [txid, True])
    if isinstance(tx, dict) and "error" in tx:
        # Try mempool
        tx = rpc_call("getmempoolentry", [txid])
        if isinstance(tx, dict) and "error" in tx:
            return jsonify(tx), 404
        return jsonify({"txid": txid, "in_mempool": True, "mempool_data": tx})

    # Resolve input addresses/values from previous outputs
    for vin in tx.get("vin", []):
        if "coinbase" in vin:
            continue
        prev_tx = rpc_call("getrawtransaction", [vin["txid"], True])
        if isinstance(prev_tx, dict) and "error" not in prev_tx:
            for vout in prev_tx.get("vout", []):
                if vout.get("n") == vin.get("vout"):
                    addrs = vout.get("scriptPubKey", {}).get("addresses", [])
                    if not addrs:
                        addr = vout.get("scriptPubKey", {}).get("address")
                        if addr:
                            addrs = [addr]
                    vin["address"] = addrs[0] if addrs else None
                    vin["value"] = vout.get("value")
                    break

    # Compute fee
    total_out = sum(v.get("value", 0) for v in tx.get("vout", []))
    total_in = sum(vin.get("value", 0) for vin in tx.get("vin", []) if "coinbase" not in vin)
    fee = total_in - total_out if total_in else None

    return jsonify({
        "txid": tx.get("txid"),
        "hash": tx.get("hash"),
        "size": tx.get("size"),
        "vsize": tx.get("vsize"),
        "weight": tx.get("weight"),
        "version": tx.get("version"),
        "locktime": tx.get("locktime"),
        "vin": tx.get("vin", []),
        "vout": tx.get("vout", []),
        "fee": fee,
        "total_in": total_in if total_in else None,
        "total_out": total_out,
        "blockhash": tx.get("blockhash"),
        "confirmations": tx.get("confirmations"),
        "time": tx.get("time"),
        "blocktime": tx.get("blocktime"),
    })

# ---------------------------------------------------------------------------
# API: address detail
# ---------------------------------------------------------------------------

@app.route("/api/address/<address>")
def api_address(address):
    if not _SNTI_ADDR_RE.match(address):
        return jsonify({"address": address, "error": "invalid SNTI address format", "tx_count": 0, "balance": 0, "transactions": []}), 400
    # Get address info (requires address index enabled)
    info = rpc_call("getaddressinfo", [address])
    if isinstance(info, dict) and "error" in info:
        return jsonify({"address": address, "error": info["error"], "tx_count": 0, "balance": 0, "transactions": []})

    # Get UTXOs
    utxos = rpc_call("getaddressutxos", [{"addresses": [address]}])
    if isinstance(utxos, dict) and "error" in utxos:
        utxos = []

    balance = sum(u.get("satoshis", 0) for u in utxos) / 1e8

    # Get transactions (scan all blocks — limited for performance)
    tx_list = rpc_call("getaddresstxids", [{"addresses": [address]}])
    if isinstance(tx_list, dict) and "error" in tx_list:
        tx_list = []

    # Limit to last 50 transactions
    tx_list = tx_list[:50]
    transactions = []
    for txid in tx_list:
        tx = rpc_call("getrawtransaction", [txid, True])
        if isinstance(tx, dict) and "error" in tx:
            continue
        # Determine net effect on this address
        received = 0
        sent = 0
        for vout in tx.get("vout", []):
            addrs = vout.get("scriptPubKey", {}).get("addresses", [])
            if not addrs:
                addr = vout.get("scriptPubKey", {}).get("address")
                if addr:
                    addrs = [addr]
            if address in addrs:
                received += vout.get("value", 0)
        for vin in tx.get("vin", []):
            if vin.get("address") == address:
                sent += vin.get("value", 0)
        transactions.append({
            "txid": txid,
            "blockhash": tx.get("blockhash"),
            "confirmations": tx.get("confirmations"),
            "time": tx.get("time"),
            "blocktime": tx.get("blocktime"),
            "received": received,
            "sent": sent,
        })

    return jsonify({
        "address": address,
        "ismine": info.get("ismine", False),
        "iswatchonly": info.get("iswatchonly", False),
        "isscript": info.get("isscript", False),
        "iswitness": info.get("iswitness", False),
        "script": info.get("script", ""),
        "pubkey": info.get("pubkey", ""),
        "balance": balance,
        "tx_count": len(tx_list),
        "transactions": transactions,
        "utxo_count": len(utxos),
    })

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# API: mining status
# ---------------------------------------------------------------------------

@app.route("/api/mining/status")
def api_mining_status():
    import re as _re
    from datetime import datetime as _dt

    mining = rpc_call("getmininginfo")
    if isinstance(mining, dict) and "error" in mining:
        return jsonify(mining), 502

    info = rpc_call("getblockchaininfo")
    netinfo = rpc_call("getnetworkinfo")

    recent_logs = []
    log_path = os.path.expanduser("~/.bitcoin/regtest/debug.log")
    if not os.path.exists(log_path):
        log_path = os.path.expanduser("~/.bitcoin/debug.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, "r") as _f:
                _lines = _f.readlines()
            _pouw = [l.strip() for l in _lines if "PoUW" in l and ("signed successfully" in l or "key generated" in l or "Generating" in l)]
            for _l in _pouw[-20:]:
                _m = _re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(.*)", _l)
                if _m:
                    recent_logs.append({"timestamp": _m.group(1), "message": _m.group(2)})
                else:
                    recent_logs.append({"timestamp": "", "message": _l})
        except Exception:
            pass

    avg_block_time = 0.0
    blocks = []
    tip_height = int(info.get("blocks", 0)) if isinstance(info, dict) else 0
    if tip_height > 0:
        for _h in range(tip_height, max(tip_height - 10, -1), -1):
            if _h < 0: break
            _bh = rpc_call("getblockhash", [_h])
            if isinstance(_bh, dict) and "error" in _bh: continue
            _blk = rpc_call("getblock", [_bh, 1])
            if isinstance(_blk, dict) and "error" in _blk: continue
            blocks.append(_blk)
        if len(blocks) >= 2:
            times = [int(b.get("time", 0)) for b in blocks]
            diffs = [times[i] - times[i+1] for i in range(len(times)-1)]
            avg_block_time = sum(diffs) / len(diffs)

    uptime_sec = int(netinfo.get("uptime", 0)) if isinstance(netinfo, dict) else 0
    uptime_human = "\u2014"
    if uptime_sec > 0:
        _h, _m, _s = uptime_sec // 3600, (uptime_sec % 3600) // 60, uptime_sec % 60
        uptime_human = f"{_h}h {_m:02d}m {_s:02d}s" if _h > 0 else f"{_m}m {_s:02d}s"
    elif len(blocks) >= 2:
        _est = max(0, int(blocks[0].get("time", 0)) - int(blocks[-1].get("time", 0)))
        if _est > 0:
            _h, _m, _s = _est // 3600, (_est % 3600) // 60, _est % 60
            uptime_human = f"~{_h}h {_m:02d}m {_s:02d}s" if _h > 0 else f"~{_m}m {_s:02d}s"

    last_block_time = "\u2014"
    if blocks:
        _lt = int(blocks[0].get("time", 0))
        if _lt:
            last_block_time = _dt.utcfromtimestamp(_lt).strftime("%Y-%m-%d %H:%M:%S UTC")

    return jsonify({
        "mining_active": True,
        "pouw_enabled": mining.get("pouw_enabled", False),
        "blocks_mined": tip_height,
        "avg_block_time": avg_block_time,
        "uptime_seconds": uptime_sec,
        "uptime_human": uptime_human,
        "last_block_time": last_block_time,
        "sig_size": 2500,
        "recent_logs": recent_logs,
    })


@app.route("/api/stratum/stats")
def stratum_stats():
    """Proxy to stratum server stats (port 3334)."""
    try:
        resp = requests.get("http://127.0.0.1:3334/stats", timeout=5)
        resp.raise_for_status()
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({
            "stratum_active": False,
            "error": str(e),
            "port": 3333,
            "connections": 0,
            "workers": 0,
            "total_shares": 0,
            "accepted": 0,
            "rejected": 0,
            "blocks_found": 0,
            "worker_list": [],
        })


# ---------------------------------------------------------------------------
# Serve wallet pages
# ---------------------------------------------------------------------------

@app.route("/wallet/")
@app.route("/wallet")
def wallet_index():
    return send_from_directory(os.path.join(SNTI_DIR, "wallet"), "index.html")

@app.route("/wallet/nc")
@app.route("/wallet/nc/")
def wallet_nc():
    return send_from_directory(os.path.join(SNTI_DIR, "wallet"), "nc.html")

# ---------------------------------------------------------------------------
# API: Wallet auth
# ---------------------------------------------------------------------------

@app.route("/api/wallet/signup", methods=["POST"])
@limiter.limit("5 per minute; 20 per hour")
def wallet_signup():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    if not username or not email or not password:
        return jsonify({"error": "username, email, and password required"}), 400
    if len(username) < 3:
        return jsonify({"error": "username must be at least 3 characters"}), 400
    if not _EMAIL_RE.match(email):
        return jsonify({"error": "invalid email address"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    # Generate XMSS address via node RPC
    addr_result = rpc_call("getnewxmssaddress")
    if isinstance(addr_result, dict) and "error" in addr_result:
        return jsonify({"error": "node unavailable, cannot create wallet address"}), 503
    # getnewxmssaddress returns {"address": "tsnti1...", "pubkey": "..."}
    if isinstance(addr_result, dict):
        xmss_address = addr_result.get("address", "")
    else:
        xmss_address = str(addr_result)

    # SNTI SECURITY FIX (2 Jul 2026): jangan pernah simpan/reuse password login
    # asli user untuk kolom lain — kalau wallet.db bocor, ini akan expose
    # password asli (bukan cuma hash) yang mungkin dipakai ulang user di tempat
    # lain. Generate random independen, sama seperti pola backfill di bawah.
    miner_rpc_pass = secrets.token_hex(20)

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO users (username, email, password_hash, xmss_address, miner_rpc_pass, created_at) VALUES (?,?,?,?,?,?)",
            (username, email, _hash_pw(password), xmss_address, miner_rpc_pass, int(time.time()))
        )
        row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        conn.commit()
        conn.close()
        token = _make_token(row[0], username)
        return jsonify({"token": token, "username": username, "address": xmss_address})
    except sqlite3.IntegrityError:
        return jsonify({"error": "username or email already taken"}), 409

@app.route("/api/wallet/login", methods=["POST"])
@limiter.limit("10 per minute; 30 per hour")
def wallet_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, username, xmss_address, password_hash FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()
    if not row or not _check_pw(password, row[3]):
        return jsonify({"error": "invalid username or password"}), 401
    token = _make_token(row[0], row[1])
    return jsonify({"token": token, "username": row[1], "address": row[2]})

@app.route("/api/wallet/me")
@jwt_required_full
def wallet_me():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT username, email, xmss_address, created_at FROM users WHERE id=?",
        (request.user_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"username": row[0], "email": row[1], "address": row[2], "created_at": row[3]})

@app.route("/api/wallet/balance")
@jwt_required_full
def wallet_balance():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT xmss_address FROM users WHERE id=?", (request.user_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "user not found"}), 404
    address = row[0]
    # scantxoutset: reliable for any address, works regardless of wallet index
    scan = rpc_call("scantxoutset", ["start", [f"addr({address})"]])
    if isinstance(scan, dict) and "error" in scan:
        return jsonify({"error": scan["error"]}), 502
    utxos = scan.get("unspents", []) if isinstance(scan, dict) else []
    balance = scan.get("total_amount", 0) if isinstance(scan, dict) else 0
    # Separate mature vs immature coinbase
    chain_info = rpc_call("getblockchaininfo")
    tip_height = chain_info.get("blocks", 0) if isinstance(chain_info, dict) else 0
    immature = sum(u.get("amount", 0) for u in utxos
                   if u.get("coinbase") and (tip_height - u.get("height", 0)) < 100)
    mature = balance - immature
    # SNTI SECURITY FIX (2 Jul 2026): surface the wallet's own retired/warning
    # status to the frontend -- previously this was computed accurately by
    # the backend (getxmssaddressinfo) but never read by the explorer, so
    # users got no warning before hitting a dead address.
    addr_info = rpc_call("getxmssaddressinfo", [address])
    retired = bool(addr_info.get("retired")) if isinstance(addr_info, dict) else False
    warning = addr_info.get("warning", "") if isinstance(addr_info, dict) else ""
    return jsonify({
        "address": address,
        "balance": balance,
        "mature": mature,
        "immature": immature,
        "utxo_count": len(utxos),
        "tip_height": tip_height,
        "retired": retired,
        "warning": warning
    })

@app.route("/api/wallet/send", methods=["POST"])
@jwt_required_full
def wallet_send():
    data = request.get_json(silent=True) or {}
    to_address = (data.get("to") or "").strip()
    amount = data.get("amount")
    if not to_address or not amount:
        return jsonify({"error": "to and amount required"}), 400
    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify({"error": "invalid amount"}), 400

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT xmss_address FROM users WHERE id=?", (request.user_id,)).fetchone()
    conn.close()
    if not row or not row[0]:
        return jsonify({"error": "user not found"}), 404
    from_address = row[0]

    # SNTI SECURITY FIX (2 Jul 2026): precheck retired/blacklist status so the
    # user gets a clear explanation instead of a raw RPC error, and so we
    # don't even attempt a sign that the backend would refuse anyway.
    addr_info = rpc_call("getxmssaddressinfo", [from_address])
    if isinstance(addr_info, dict) and addr_info.get("retired"):
        return jsonify({
            "error": "Address pengirim ini sudah tidak bisa menandatangani transaksi lagi "
                     "(XMSS one-time-use sudah terpakai, atau address di-blacklist demi keamanan). "
                     + (addr_info.get("warning") or ""),
            "retired": True
        }), 409

    # SNTI SECURITY FIX (2 Jul 2026): sendtoxmssaddress does coin selection
    # across the ENTIRE shared node wallet (all users' XMSS UTXOs live in one
    # wallet, no per-user isolation) -- it could spend another user's UTXO to
    # fund this send. sendfromxmssaddress scopes selection to UTXOs actually
    # sitting at from_address (see SNTI FIX comment in src/wallet/rpc/xmss.cpp).
    result = rpc_call("sendfromxmssaddress", [from_address, to_address, amount])
    if isinstance(result, dict) and "error" in result:
        return jsonify(result), 400

    # XMSS keys are one-time-use: a wallet-native address (no mining ledger)
    # retires entirely after one signature. Rotate to a fresh address so
    # future incoming funds aren't received at a key that can no longer sign.
    # NOTE: this does NOT rescue funds left in OTHER unspent UTXOs still
    # sitting at from_address (the backend can only sign one UTXO per XMSS
    # address per send) -- see job_queue.md follow-up for a proper fix
    # (auto-sweep / ledger-backed wallet-native addresses).
    response = {"txid": result}
    new_addr = rpc_call("getnewxmssaddress")
    if isinstance(new_addr, dict) and new_addr.get("address"):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET xmss_address=? WHERE id=?", (new_addr["address"], request.user_id))
        conn.commit()
        conn.close()
        response["new_address"] = new_addr["address"]
        response["note"] = (
            "Address lama sudah dipakai untuk mengirim dan tidak bisa dipakai lagi (XMSS one-time-use). "
            "Address baru sudah otomatis dibuat untuk menerima dana berikutnya."
        )
    return jsonify(response)

@app.route("/api/wallet/txs")
@jwt_required_full
def wallet_txs():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT xmss_address FROM users WHERE id=?", (request.user_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "user not found"}), 404
    address = row[0]
    # SNTI FIX (2 Jul 2026): listunspent doesn't work for XMSS addresses
    # (same reason wallet_balance already switched to scantxoutset) -- this
    # tab was silently showing "No unspent outputs" even when the balance
    # tab correctly showed a positive balance.
    scan = rpc_call("scantxoutset", ["start", [f"addr({address})"]])
    if isinstance(scan, dict) and "error" in scan:
        return jsonify({"txs": []})
    utxos = scan.get("unspents", []) if isinstance(scan, dict) else []
    return jsonify({"txs": utxos})

# ---------------------------------------------------------------------------
# API: Non-custodial tools
# ---------------------------------------------------------------------------

@app.route("/api/nc/newaddress", methods=["POST"])
def nc_new_address():
    """Generate a fresh XMSS keypair — returned once, not stored server-side."""
    result = rpc_call("getnewxmssaddress")
    if isinstance(result, dict) and "error" in result:
        return jsonify(result), 503
    if isinstance(result, dict):
        return jsonify({"address": result.get("address", ""), "pubkey": result.get("pubkey", "")})
    return jsonify({"address": str(result)})

@app.route("/api/nc/balance/<address>")
def nc_balance(address):
    if not _SNTI_ADDR_RE.match(address):
        return jsonify({"error": "invalid SNTI address format"}), 400
    result = rpc_call("scantxoutset", ["start", [f"addr({address})"]])
    if isinstance(result, dict) and "error" in result:
        return jsonify(result), 502
    utxos = result.get("unspents", []) if isinstance(result, dict) else []
    balance = result.get("total_amount", 0) if isinstance(result, dict) else 0
    return jsonify({"address": address, "balance": balance, "utxos": utxos})

@app.route("/api/wallet/get-install-script", methods=["POST"])
@limiter.limit("10 per minute")
def wallet_get_install_script():
    """Download install.sh langsung dengan username+password — tanpa perlu token."""
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, password_hash FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if not row or not _check_pw(password, row[1]):
        return jsonify({"error": "invalid username or password"}), 401
    return _generate_install_script(row[0])

@app.route("/api/wallet/install-script")
@jwt_required_full
def wallet_install_script():
    """Return a personalized install.sh with user's JWT token embedded."""
    return _generate_install_script(request.user_id)

def _generate_install_script(user_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT username, xmss_address, miner_rpc_pass FROM users WHERE id=?", (user_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "user not found"}), 404
    username, wallet_address, miner_rpc_pass = row
    # Backfill: existing users created before this column existed get a random password now
    if not miner_rpc_pass:
        miner_rpc_pass = secrets.token_hex(20)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET miner_rpc_pass=? WHERE id=?", (miner_rpc_pass, user_id))
        conn.commit()
        conn.close()
    # Issue a long-lived token (7 days) specifically for the install script.
    # SNTI SECURITY FIX (2 Jul 2026): scope="installer" restricts this token
    # (embedded in plaintext in a downloadable .sh file, easy to leak/share)
    # to only the miner heartbeat/watch endpoints -- see jwt_required_full.
    # It can NEVER be used to read balance, send funds, export the private
    # key, download the backup, change the password, or mint another token.
    payload = {
        "sub": user_id,
        "usr": username,
        "scope": "installer",
        "exp": int(time.time()) + 7 * 24 * 3600
    }
    script_token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
    api_base = "https://assentian.network"
    script = f'''#!/bin/bash
# ============================================================
# SNTI Miner Installer — assentian.network
# User: {username}
# Generated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}
# ============================================================
set -e

SNTI_TOKEN="{script_token}"
SNTI_API="{api_base}"
INSTALL_DIR="$HOME/snti-miner"
DATADIR="$HOME/.snti_mainnet"
RPC_USER="{username}"
RPC_PASS="{miner_rpc_pass}"
RPC_PORT="9332"
P2P_PORT="9333"
WALLET_NAME="snti_wallet"

GREEN="\\033[0;32m"; YELLOW="\\033[0;33m"; RED="\\033[0;31m"; NC="\\033[0m"
ok()  {{ echo -e "${{GREEN}}[OK]${{NC}} $1"; }}
inf() {{ echo -e "${{YELLOW}}[..] $1${{NC}}"; }}
err() {{ echo -e "${{RED}}[ERR] $1${{NC}}"; exit 1; }}

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   SNTI Post-Quantum Miner Installer      ║"
echo "  ║   assentian.network                      ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  User    : {username}"
echo "  Datadir : $DATADIR"
echo "  API     : $SNTI_API"
echo ""

# -- 1. Dependencies
inf "Installing dependencies..."
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y -qq libevent-dev libssl-dev libminiupnpc-dev libnatpmp-dev libsqlite3-0 curl python3 2>/dev/null || \\
  err "apt install failed — run as sudo or check internet connection"
ok "Dependencies installed"

# -- 2. Download binaries
inf "Downloading SNTI node binaries..."
mkdir -p "$INSTALL_DIR" || err "Cannot create $INSTALL_DIR — check permissions"
if [ -x "$INSTALL_DIR/bitcoind" ] && [ -x "$INSTALL_DIR/bitcoin-cli" ] && "$INSTALL_DIR/bitcoind" -version >/dev/null 2>&1; then
  ok "Binaries already exist, skipping download"
else
  FREE_MB=$(df -m "$INSTALL_DIR" | awk 'NR==2{{print $4}}')
  [ "${{FREE_MB:-0}}" -lt 500 ] && err "Not enough disk space (need 500MB free, have ${{FREE_MB}}MB at $INSTALL_DIR)"
  _download() {{
    local url="$1" dest="$2" label="$3"
    pkill -f "$dest" >/dev/null 2>&1 || true
    sleep 1
    rm -f "$dest"
    curl -fSL --progress-bar "$url" -o "$dest" || {{ rm -f "$dest"; err "Failed to download $label (disk full? try: df -h)"; }}
  }}
  _download "$SNTI_API/bin/bitcoind"    "$INSTALL_DIR/bitcoind"    "bitcoind"
  _download "$SNTI_API/bin/bitcoin-cli" "$INSTALL_DIR/bitcoin-cli" "bitcoin-cli"
  chmod +x "$INSTALL_DIR/bitcoind" "$INSTALL_DIR/bitcoin-cli"
  ok "Binaries downloaded to $INSTALL_DIR"
fi

# Shortcut
CLI="$INSTALL_DIR/bitcoin-cli -datadir=$DATADIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT"

# -- 3. Setup datadir & config
inf "Setting up node configuration..."
mkdir -p "$DATADIR"
cat > "$DATADIR/bitcoin.conf" << EOF
rpcuser=$RPC_USER
rpcpassword=$RPC_PASS
rpcport=$RPC_PORT
port=$P2P_PORT
rpcallowip=127.0.0.1
walletcrosschain=1
addnode=104.234.26.7:9333
EOF
ok "Config written to $DATADIR/bitcoin.conf"

# -- 4. Start node
inf "Starting SNTI node..."
if pgrep -f "bitcoind.*snti_mainnet" > /dev/null 2>&1; then
  ok "Node already running"
else
  "$INSTALL_DIR/bitcoind" -datadir="$DATADIR" -daemon -wallet="$WALLET_NAME" \\
    -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcport="$RPC_PORT" \\
    -port="$P2P_PORT" -walletcrosschain
  inf "Waiting for node to start..."
  for i in $(seq 1 30); do
    H=$($CLI getblockcount 2>/dev/null) && [[ "$H" =~ ^[0-9]+$ ]] && break
    sleep 2
  done
fi

H=$($CLI getblockcount 2>/dev/null) || err "Node failed to start — check $DATADIR/debug.log"
ok "Node started (height: $H)"

# -- 5. Wait for initial sync
inf "Syncing blockchain (this may take a few minutes)..."
PREV_H=0
while true; do
  H=$($CLI getblockcount 2>/dev/null) || H=0
  IBD=$($CLI getblockchaininfo 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['initialblockdownload'])" 2>/dev/null || echo "true")
  echo -ne "\\r  Blocks: $H  "
  if [ "$IBD" = "False" ] || [ "$IBD" = "false" ]; then
    echo ""
    ok "Blockchain synced (height: $H)"
    break
  fi
  sleep 5
done

# -- 6. Create wallet if needed
WLIST=$($CLI listwallets 2>/dev/null | python3 -c "import sys,json; print(','.join(json.load(sys.stdin)))" 2>/dev/null || echo "")
if [[ "$WLIST" != *"$WALLET_NAME"* ]]; then
  $CLI createwallet "$WALLET_NAME" > /dev/null 2>&1 || true
fi
ok "Wallet ready"

# -- 7. Tentukan address tujuan mining
inf "Menentukan address mining..."
WALLET_ADDRESS="{wallet_address}"

if [ -n "$WALLET_ADDRESS" ]; then
  # Mine langsung ke address web wallet user — koin masuk ke dashboard
  ADDRESS="$WALLET_ADDRESS"
  ok "Mine ke address web wallet Anda: $ADDRESS"
  ok "Koin langsung masuk ke dashboard $SNTI_API/wallet/"
else
  # Fallback: generate address lokal
  ADDR_JSON=$($CLI getnewxmssaddress 2>&1)
  ADDRESS=$(echo "$ADDR_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['address'])" 2>/dev/null)
  [ -z "$ADDRESS" ] && err "Failed to generate address: $ADDR_JSON"
  ok "Address lokal: $ADDRESS"
  # Register sebagai watch address
  curl -sf -X POST "$SNTI_API/api/wallet/watch" \\
    -H "Authorization: Bearer $SNTI_TOKEN" \\
    -H "Content-Type: application/json" \\
    -d "{{\\\"address\\\":\\\"$ADDRESS\\\",\\\"label\\\":\\\"Miner — $(hostname)\\\"}}" > /dev/null 2>&1 || true
fi

# -- 8. Heartbeat background loop
_heartbeat() {{
  while true; do
    curl -sf -X POST "$SNTI_API/api/wallet/miner-heartbeat" \\
      -H "Authorization: Bearer $SNTI_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d "{{\\\"hostname\\\":\\\"$(hostname)\\\"}}" > /dev/null 2>&1 || true
    sleep 30
  done
}}
_heartbeat &
HEARTBEAT_PID=$!

# -- 9. Start mining
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Mining started!                        ║"
echo "  ║   Rewards → {username}                   ║"
echo "  ║   Cek saldo: $SNTI_API/wallet/           ║"
echo "  ║   Status online: $SNTI_API/wallet/       ║"
echo "  ║   Ctrl+C untuk berhenti                  ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

trap "kill $HEARTBEAT_PID 2>/dev/null; exit" INT TERM

BLOCK=0
while true; do
  RESULT=$($CLI generatetoaddress 1 "$ADDRESS" 2>&1)
  if echo "$RESULT" | python3 -c "import sys,json; blocks=json.load(sys.stdin); exit(0 if blocks else 1)" 2>/dev/null; then
    BLOCK=$((BLOCK+1))
    HASH=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)[0][:16])" 2>/dev/null)
    H=$($CLI getblockcount 2>/dev/null || echo "?")
    echo "  [$BLOCK] Blok #$H ditemukan: ${{HASH}}..."
  fi
done
'''
    from flask import Response
    return Response(
        script,
        mimetype="text/x-sh",
        headers={"Content-Disposition": f"attachment; filename=snti-install-{username}.sh"}
    )

@app.route("/api/wallet/change-password", methods=["POST"])
@jwt_required_full
def wallet_change_password():
    data = request.get_json(silent=True) or {}
    old_pw = data.get("old_password") or ""
    new_pw = data.get("new_password") or ""
    if not old_pw or not new_pw:
        return jsonify({"error": "old_password and new_password required"}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "Password baru minimal 8 karakter"}), 400
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE id=?", (request.user_id,)
    ).fetchone()
    if not row or not _check_pw(old_pw, row[0]):
        conn.close()
        return jsonify({"error": "Password lama salah"}), 401
    conn.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (_hash_pw(new_pw), request.user_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Password berhasil diubah"})

@app.route("/api/wallet/export-key")
@jwt_required_full
def wallet_export_key():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT username, xmss_address FROM users WHERE id=?", (request.user_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "user not found"}), 404
    username, address = row
    if not address:
        return jsonify({"error": "no XMSS address assigned to this account"}), 400
    result = rpc_call("exportxmsskey", [address])
    if isinstance(result, dict) and "error" in result:
        return jsonify({"error": result["error"]}), 502
    return jsonify({
        "username": username,
        "address": address,
        "pubkey": result.get("pubkey"),
        "seckey": result.get("seckey"),
        "leaf_index": result.get("leaf_index"),
        "remaining": result.get("remaining"),
        "exported_at": int(time.time()),
        "warning": "Keep this secret key safe. Anyone with it can spend your funds."
    })

@app.route("/api/wallet/backup-file")
@jwt_required_full
def wallet_backup_file():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT username, email, xmss_address, created_at FROM users WHERE id=?",
        (request.user_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "user not found"}), 404
    username, email, address, created_at = row
    if not address:
        return jsonify({"error": "no XMSS address on this account"}), 400
    result = rpc_call("exportxmsskey", [address])
    if isinstance(result, dict) and "error" in result:
        return jsonify({"error": result["error"]}), 502
    import json as _json
    backup = _json.dumps({
        "snti_wallet_backup": True,
        "version": 1,
        "network": "mainnet",
        "username": username,
        "email": email,
        "address": address,
        "pubkey": result.get("pubkey"),
        "seckey": result.get("seckey"),
        "leaf_index": result.get("leaf_index"),
        "remaining": result.get("remaining"),
        "account_created": created_at,
        "exported_at": int(time.time()),
        "warning": "KEEP THIS FILE SECRET. Anyone with the seckey can spend your funds."
    }, indent=2)
    from flask import Response
    safe_user = "".join(c for c in username if c.isalnum() or c in "-_")
    fname = f"snti-wallet-backup-{safe_user}-{time.strftime('%Y%m%d')}.json"
    return Response(
        backup,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )

@app.route("/api/wallet/watch", methods=["GET"])
@app.route("/api/wallet/watches", methods=["GET"])
@jwt_required
def watch_list():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT address, label, created_at FROM watch_addresses WHERE user_id=? ORDER BY created_at DESC",
        (request.user_id,)
    ).fetchall()
    conn.close()
    if not rows:
        return jsonify({"watches": []})
    # Single batched scantxoutset for all watch addresses
    descriptors = [f"addr({addr})" for addr, _, _ in rows]
    scan = rpc_call("scantxoutset", ["start", descriptors])
    scan_ok = isinstance(scan, dict) and "error" not in scan
    balance_map = {}
    if scan_ok:
        for utxo in scan.get("unspents", []):
            desc = utxo.get("desc", "")
            if desc.startswith("addr(") and desc.endswith(")"):
                addr = desc[5:-1]
                balance_map[addr] = balance_map.get(addr, 0) + utxo.get("amount", 0)
    result = []
    for address, label, created_at in rows:
        balance = balance_map.get(address, 0) if scan_ok else None
        result.append({"address": address, "label": label or "", "balance": balance, "created_at": created_at})
    return jsonify({"watches": result})

@app.route("/api/wallet/watch", methods=["POST"])
@jwt_required
def watch_add():
    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()
    label = (data.get("label") or "").strip()[:64]
    if not address:
        return jsonify({"error": "address required"}), 400
    info = rpc_call("validateaddress", [address])
    if isinstance(info, dict) and not info.get("isvalid"):
        return jsonify({"error": "invalid SNTI address"}), 400
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO watch_addresses (user_id, address, label, created_at) VALUES (?,?,?,?)",
            (request.user_id, address, label or None, int(time.time()))
        )
        conn.commit()
        return jsonify({"ok": True, "address": address, "label": label})
    except sqlite3.IntegrityError:
        return jsonify({"error": "address already watched"}), 409
    finally:
        conn.close()

@app.route("/api/wallet/watch/<address>", methods=["DELETE"])
@jwt_required
def watch_remove(address):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            "DELETE FROM watch_addresses WHERE user_id=? AND address=?",
            (request.user_id, address)
        )
        conn.commit()
    finally:
        conn.close()
    if cur.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})

@app.route("/api/wallet/miner-heartbeat", methods=["POST"])
@jwt_required
def miner_heartbeat():
    data = request.get_json(silent=True) or {}
    hostname = (data.get("hostname") or "unknown")[:64]
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE users SET miner_last_seen=?, miner_hostname=? WHERE id=?",
        (int(time.time()), hostname, request.user_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/wallet/miner-status")
@jwt_required
def miner_status():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT miner_last_seen, miner_hostname FROM users WHERE id=?", (request.user_id,)
    ).fetchone()
    conn.close()
    last_seen = row[0] or 0
    hostname = row[1] or ""
    now = int(time.time())
    online = (now - last_seen) < 120  # online jika heartbeat < 2 menit lalu
    return jsonify({
        "online": online,
        "last_seen": last_seen,
        "hostname": hostname,
        "seconds_ago": now - last_seen if last_seen else None
    })

@app.route("/api/nc/broadcast", methods=["POST"])
def nc_broadcast():
    data = request.get_json(silent=True) or {}
    rawtx = (data.get("hex") or "").strip()
    if not rawtx:
        return jsonify({"error": "hex required"}), 400
    result = rpc_call("sendrawtransaction", [rawtx])
    if isinstance(result, dict) and "error" in result:
        return jsonify(result), 400
    return jsonify({"txid": result})


if __name__ == "__main__":
    port = int(os.environ.get("QNT_EXPLORER_PORT", 8081))
    debug = os.environ.get("QNT_EXPLORER_DEBUG", "0") == "1"
    print(f"Assentian-PQE Block Explorer starting on http://127.0.0.1:{port}")
    print(f"RPC target: {RPC_URL}")
    app.run(host="127.0.0.1", port=port, debug=debug)
