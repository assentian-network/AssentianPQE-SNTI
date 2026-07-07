#!/usr/bin/env python3
"""
Assentian-PQE Block Explorer - Flask Backend
Proxies bitcoind RPC calls for the Quant post-quantum cryptocurrency block explorer.
"""

import os
import re
import json
import shlex
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
# SNTI SECURITY FIX (4 Jul 2026 internal audit): username is embedded verbatim
# (comment line + RPC_USER="...") into the generated install.sh in
# _generate_install_script(). Without a character whitelist, a username
# containing a literal newline or `"` breaks out of that context and injects
# arbitrary shell commands into a script other people (the user themselves,
# or support/admin debugging on their behalf) may download and run.
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]{3,32}$')

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
    # SNTI FIX (5 Jul 2026): mining rewards used to accumulate on a single
    # wallet-native address forever (getnewxmssaddress only rotated on the
    # NEXT send, after the address was already retired by the first spend --
    # see job_queue.md "koin dini hilang"). Wallet-native XMSS keys are
    # one-time-use by cryptographic design (xmss_signer.cpp), so an address
    # that received hundreds of separate block rewards can only ever have
    # ONE of them recovered; the rest become permanently unspendable the
    # moment the address signs anything. This table tracks every address
    # ever assigned to a user so mining can rotate to a fresh one after
    # EVERY block (each address then only ever holds the one UTXO its
    # one-time key can safely spend) and balance/send can be computed
    # across the user's full address history instead of just the latest one.
    conn.execute("""CREATE TABLE IF NOT EXISTS mining_addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        address TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(user_id, address),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    # Backfill: every existing user's current address predates this table --
    # register it now so balance/send aggregation (below) sees it too.
    for user_id, addr, created_at in conn.execute(
        "SELECT id, xmss_address, created_at FROM users WHERE xmss_address IS NOT NULL AND xmss_address != ''"
    ).fetchall():
        conn.execute(
            "INSERT OR IGNORE INTO mining_addresses (user_id, address, created_at) VALUES (?,?,?)",
            (user_id, addr, created_at)
        )
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

# SNTI FIX (5 Jul 2026): scantxoutset derives its search script from the
# address string alone, which can only ever produce the hash-committed
# P2XMSSHASH form -- it is structurally unable to find P2XMSS-pure
# (full-pubkey) outputs, the form sendfromxmssaddress emits for internal
# transfers between two addresses already known to this wallet (see
# xmss.cpp). Confirmed live: a real 49.9997448 SNTI P2XMSS-pure UTXO showed
# balance=0 via scantxoutset/nc_balance while gettxout/listunspent both saw
# it correctly. listunspent reads the wallet's own UTXO index (matches via
# IsMine, not a re-derived script) so it sees both forms, but only for
# addresses this wallet actually holds keys for -- for a genuinely external
# watched address it returns nothing. Combine both sources so watch-address
# balances stay correct whether the address is wallet-owned or truly
# external, deduplicated by (txid, vout).
def _scan_addresses(addresses):
    seen = set()
    combined = []
    lu = rpc_call("listunspent", [0, 9999999, addresses, True, {"include_immature_coinbase": True}])
    if isinstance(lu, list):
        for u in lu:
            key = (u.get("txid"), u.get("vout"))
            seen.add(key)
            combined.append(u)
    scan = rpc_call("scantxoutset", ["start", [f"addr({a})" for a in addresses]])
    if isinstance(scan, dict) and isinstance(scan.get("unspents"), list):
        for u in scan["unspents"]:
            key = (u.get("txid"), u.get("vout"))
            if key in seen:
                continue
            # SNTI FIX (5 Jul 2026): real descriptors always carry a checksum
            # suffix (e.g. "addr(snti1...)#gx3qfwd7"), so a bare
            # startswith/endswith(")") check never matched -- "address"
            # silently never got set for any scantxoutset-sourced entry,
            # which broke retired-address ("stuck") categorization in
            # wallet_balance (everything fell through to "spendable").
            m = re.match(r"addr\(([^)]+)\)", u.get("desc", ""))
            if m:
                u = dict(u)
                u["address"] = m.group(1)
            combined.append(u)
    return combined

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
    if not _USERNAME_RE.match(username):
        return jsonify({"error": "username must be 3-32 characters, letters/numbers/underscore/hyphen only"}), 400
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
        # SNTI FIX (5 Jul 2026): register in mining_addresses from birth so
        # balance/send aggregation (see wallet_balance/wallet_send) sees this
        # address without needing a separate backfill pass later.
        conn.execute(
            "INSERT OR IGNORE INTO mining_addresses (user_id, address, created_at) VALUES (?,?,?)",
            (row[0], xmss_address, int(time.time()))
        )
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

def _get_user_addresses(user_id):
    """SNTI FIX (5 Jul 2026): a user can now have many custodial addresses
    (mining rotates a fresh one every block -- see next_mining_address /
    _rotate_address in the miner loop). Returns every address ever assigned
    to this user, oldest first, so balance/txs/send can operate across all
    of them instead of just the single 'current' one.
    """
    conn = sqlite3.connect(DB_PATH)
    addrs = [r[0] for r in conn.execute(
        "SELECT address FROM mining_addresses WHERE user_id=? ORDER BY created_at ASC", (user_id,)
    ).fetchall()]
    legacy = conn.execute("SELECT xmss_address FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    # Defensive: cover accounts whose current address somehow predates the
    # mining_addresses backfill (should not happen after this fix, but the
    # column is still the source of truth for "current" elsewhere).
    if legacy and legacy[0] and legacy[0] not in addrs:
        addrs.append(legacy[0])
    return addrs

@app.route("/api/wallet/balance")
@jwt_required_full
def wallet_balance():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT xmss_address FROM users WHERE id=?", (request.user_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "user not found"}), 404
    current_address = row[0]
    addresses = _get_user_addresses(request.user_id)
    if not addresses:
        return jsonify({"error": "user not found"}), 404
    # SNTI FIX (5 Jul 2026, gap found during P2XMSS-pure recovery): scantxoutset
    # derives its search script from the address string alone, which can only
    # ever produce the hash-committed P2XMSSHASH form -- it is structurally
    # unable to find P2XMSS-pure (full-pubkey) outputs. listunspent instead
    # reads the wallet's own UTXO index (matches via IsMine), so it sees both
    # forms -- BUT it has the opposite gap: confirmed live (dini's account,
    # 5 Jul 2026) that once a one-time-use address's key is marked "retired"
    # (has signed once), listunspent stops listing ALL of that address's
    # remaining UTXOs -- not just the spent one -- even though scantxoutset
    # and gettxout both confirm they are still genuinely unspent on-chain.
    # This made the dashboard show a 0 balance for funds that were still
    # real, just permanently unspendable, which is exactly as alarming as
    # actually losing them. Use _scan_addresses() (merges both, deduped by
    # txid:vout) so either RPC's blind spot is covered by the other.
    utxos = _scan_addresses(addresses)
    tip_height = rpc_call("getblockchaininfo")
    tip_height = tip_height.get("blocks", 0) if isinstance(tip_height, dict) else 0

    # SNTI FIX (5 Jul 2026): "mature" used to mean only "not immature", which
    # silently lumped in UTXOs sitting at a RETIRED one-time-use address --
    # on-chain and confirmed, but permanently un-signable, not actually
    # spendable in any real sense. Labeling that "Spendable" (as the frontend
    # did) is actively misleading, not just imprecise -- surface it as its
    # own "stuck" bucket instead so users can tell real spendable funds apart
    # from funds that exist but can never move again.
    retired_addrs = set()
    for a in addresses:
        info = rpc_call("getxmssaddressinfo", [a])
        if isinstance(info, dict) and info.get("retired"):
            retired_addrs.add(a)
    balance = 0.0
    immature = 0.0
    stuck = 0.0
    for u in utxos:
        amt = u.get("amount", 0)
        balance += amt
        if u.get("coinbase") and (tip_height - u.get("height", 0)) < 100:
            immature += amt
        elif u.get("address") in retired_addrs:
            stuck += amt
    spendable = balance - immature - stuck
    # SNTI SECURITY FIX (2 Jul 2026): surface the wallet's own retired/warning
    # status to the frontend -- previously this was computed accurately by
    # the backend (getxmssaddressinfo) but never read by the explorer, so
    # users got no warning before hitting a dead address.
    # SNTI FIX (5 Jul 2026): this now only describes the CURRENT receiving
    # address (older rotated addresses are expected to retire once spent --
    # that is no longer a problem since each only ever holds one UTXO).
    addr_info = rpc_call("getxmssaddressinfo", [current_address])
    retired = bool(addr_info.get("retired")) if isinstance(addr_info, dict) else False
    warning = addr_info.get("warning", "") if isinstance(addr_info, dict) else ""
    return jsonify({
        "address": current_address,
        "balance": balance,
        "spendable": spendable,
        "stuck": stuck,
        "immature": immature,
        "mature": spendable + stuck,  # kept for older clients: "confirmed, not immature"
        "utxo_count": len(utxos),
        "address_count": len(addresses),
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
    current_address = row[0]

    addresses = _get_user_addresses(request.user_id)
    if not addresses:
        return jsonify({"error": "user not found"}), 404

    # SNTI SECURITY FIX (2 Jul 2026): sendtoxmssaddress does coin selection
    # across the ENTIRE shared node wallet (all users' XMSS UTXOs live in one
    # wallet, no per-user isolation) -- it could spend another user's UTXO to
    # fund this send. sendfromxmssaddress scopes selection to UTXOs actually
    # sitting at a specific address (see SNTI FIX comment in xmss.cpp).
    #
    # SNTI FIX (5 Jul 2026): a user's balance is now spread across many
    # one-time-use addresses (mining rotates a fresh one every block -- see
    # next_mining_address). Each address's XMSS key can safely sign exactly
    # ONE UTXO ever (xmss_signer.cpp: a WOTS+ leaf signing two different
    # messages leaks the private key), so a single sendfromxmssaddress call
    # can never move more than one address's balance. Drain addresses one at
    # a time (oldest first) until the requested amount is covered, instead of
    # requiring a single address to hold the full amount.
    remaining = amount
    sent_total = 0.0
    txids = []
    skipped = []
    for addr in addresses:
        if remaining <= 0:
            break
        addr_info = rpc_call("getxmssaddressinfo", [addr])
        if isinstance(addr_info, dict) and addr_info.get("retired"):
            continue  # already spent (or blacklisted) -- nothing left to move here
        # SNTI FIX (5 Jul 2026): listunspent (not scantxoutset -- see
        # wallet_balance for why) already excludes immature coinbase by
        # default, so its result IS the spendable set directly.
        spendable = rpc_call("listunspent", [0, 9999999, [addr]])
        if isinstance(spendable, dict) and "error" in spendable:
            continue
        if not isinstance(spendable, list) or not spendable:
            continue
        # Only ONE UTXO can ever be signed per address (see xmss.cpp) -- the
        # RPC itself always picks it; we only need the largest UTXO's value
        # to decide how much of `remaining` this address can contribute.
        cap = max(u.get("amount", 0) for u in spendable)
        if cap <= 0:
            continue
        if cap <= remaining:
            # Draining this address fully: subtract the fee from the amount
            # instead of requiring the UTXO to exceed its own value.
            send_amt = cap
            subtract_fee = True
        else:
            send_amt = remaining
            subtract_fee = False
        result = rpc_call("sendfromxmssaddress", [addr, to_address, send_amt, "", subtract_fee])
        if isinstance(result, dict) and "error" in result:
            skipped.append({"address": addr, "error": result["error"]})
            continue
        txids.append({"address": addr, "txid": result, "amount": send_amt})
        sent_total += send_amt
        remaining -= send_amt

    if not txids:
        return jsonify({
            "error": "No spendable funds found across any of your addresses",
            "skipped": skipped
        }), 409

    response = {
        "txid": txids[0]["txid"],       # backward compat: primary/first tx
        "txids": [t["txid"] for t in txids],
        "details": txids,
        "amount_requested": amount,
        "amount_sent": round(sent_total, 8),
        "fully_covered": remaining <= 1e-8
    }
    if remaining > 1e-8:
        response["note"] = (
            f"Hanya {round(sent_total, 8)} dari {amount} SNTI yang berhasil dikirim -- sisa "
            f"({round(remaining, 8)}) tidak cukup tersedia di address yang belum retired/matang."
        )

    # If the send happened to drain the account's CURRENT display address,
    # rotate it so future manual deposits/display don't point at a dead key.
    cur_info = rpc_call("getxmssaddressinfo", [current_address])
    if isinstance(cur_info, dict) and cur_info.get("retired"):
        new_addr = rpc_call("getnewxmssaddress")
        if isinstance(new_addr, dict) and new_addr.get("address"):
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT OR IGNORE INTO mining_addresses (user_id, address, created_at) VALUES (?,?,?)",
                (request.user_id, new_addr["address"], int(time.time()))
            )
            conn.execute("UPDATE users SET xmss_address=? WHERE id=?", (new_addr["address"], request.user_id))
            conn.commit()
            conn.close()
            response["new_address"] = new_addr["address"]
            response["note"] = (response.get("note", "") + " "
                "Address penerima Anda saat ini sudah terpakai untuk mengirim tadi -- "
                "address baru sudah otomatis dibuat untuk menerima dana berikutnya."
            ).strip()
    return jsonify(response)

@app.route("/api/wallet/txs")
@jwt_required_full
def wallet_txs():
    addresses = _get_user_addresses(request.user_id)
    if not addresses:
        return jsonify({"error": "user not found"}), 404
    # SNTI FIX (5 Jul 2026): use the merged scan -- see wallet_balance() for
    # why neither RPC alone is enough (scantxoutset misses P2XMSS-pure;
    # listunspent misses a retired one-time-use address's remaining UTXOs).
    return jsonify({"txs": _scan_addresses(addresses)})

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
    utxos = _scan_addresses([address])
    balance = sum(u.get("amount", 0) for u in utxos)
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
    # SNTI SECURITY FIX (4 Jul 2026 internal audit): username is embedded
    # into a generated bash script below. Signup now enforces _USERNAME_RE,
    # but accounts created before that check existed may still have an
    # unsafe username (spaces, quotes, embedded newlines) sitting in the DB.
    # Refuse to generate a script for those rather than risk command
    # injection into whatever machine downloads and runs it.
    if not _USERNAME_RE.match(username):
        return jsonify({"error": "username contains unsupported characters; please contact support to rename your account before installing"}), 400
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
    # Defense-in-depth on top of _USERNAME_RE / server-generated values above:
    # never interpolate a raw value into shell-assignment context unquoted.
    username_sh = shlex.quote(username)
    wallet_address_sh = shlex.quote(wallet_address or "")
    script_token_sh = shlex.quote(script_token)
    miner_rpc_pass_sh = shlex.quote(miner_rpc_pass)
    script = f'''#!/bin/bash
# ============================================================
# SNTI Miner Installer — assentian.network
# User: {username}
# Generated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}
# ============================================================
set -e

SNTI_TOKEN={script_token_sh}
SNTI_API="{api_base}"
INSTALL_DIR="$HOME/snti-miner"
DATADIR="$HOME/.snti_mainnet"
RPC_USER={username_sh}
RPC_PASS={miner_rpc_pass_sh}
RPC_PORT="9332"
P2P_PORT="9333"
WALLET_NAME="snti_wallet"
WALLET_ADDRESS={wallet_address_sh}
CUR_USER="$(whoami)"
SVC_NODE="snti-mainnet-node"
# SNTI FIX (multi-user-per-device, see job_queue.md): the node (bitcoind,
# port 9332/9333, $INSTALL_DIR/$DATADIR) is a SINGLETON PER MACHINE -- the
# first account that installs on a machine sets it up, every account after
# that just reuses it instead of restarting/reconfiguring it (which used
# to kill whichever OTHER account was already mining on that box). The
# mining LOOP stays per-account: its own directory and systemd service
# name, so N accounts can mine side-by-side on the same machine without
# stepping on each other.
MINER_DIR="$HOME/snti-miner-$RPC_USER"
SVC_MINER="snti-miner-$RPC_USER"

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
echo "  User      : {username}"
echo "  Miner dir : $MINER_DIR"
echo "  Node dir  : $DATADIR (shared, satu per mesin)"
echo "  API       : $SNTI_API"
echo ""

# -- 1. Dependencies
inf "Installing dependencies..."
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y -qq libevent-dev libssl-dev libminiupnpc-dev libnatpmp-dev libsqlite3-0 curl python3 cron 2>/dev/null || \\
  err "apt install failed — run as sudo or check internet connection"
ok "Dependencies installed"

# -- 2. Detect systemd (menentukan cara node/mining auto-restart)
HAS_SYSTEMD=false
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && sudo systemctl list-units >/dev/null 2>&1; then
  HAS_SYSTEMD=true
  ok "systemd terdeteksi — node & mining akan auto-restart kalau crash atau reboot"
else
  inf "systemd tidak terdeteksi (WSL1 / container minimal?) — pakai fallback cron watchdog"
fi

# -- 3. Deteksi apakah node sudah terpasang di mesin ini (oleh akun lain
# atau instalasi sebelumnya) -- kalau ya, JANGAN disentuh/restart sama sekali.
NODE_EXISTS=false
[ -f "$DATADIR/bitcoin.conf" ] && NODE_EXISTS=true

# Hentikan instalasi lama MILIK AKUN INI SAJA (bukan node atau miner akun lain)
pkill -f "$MINER_DIR/snti-miner-loop.sh" >/dev/null 2>&1 || true
if $HAS_SYSTEMD; then
  sudo systemctl stop "$SVC_MINER" >/dev/null 2>&1 || true
fi

# Migrasi dari versi installer LAMA (pre-multi-user: satu direktori/service
# global "$HOME/snti-miner" + "snti-miner.service" dipakai bareng node) --
# HANYA kalau instalasi lama itu kepunyaan akun yang SAMA (dicek dari
# RPC_USER di snti.env lama), supaya tidak pernah mematikan miner akun lain.
OLD_MINER_ENV="$HOME/snti-miner/snti.env"
if [ -f "$OLD_MINER_ENV" ]; then
  OLD_RPC_USER=$(sed -n 's/^RPC_USER="\\(.*\\)"$/\\1/p' "$OLD_MINER_ENV" 2>/dev/null | head -1)
  if [ "$OLD_RPC_USER" = "$RPC_USER" ]; then
    inf "Instalasi lama (pre-multi-user) akun ini terdeteksi — migrasi ke slot per-akun"
    pkill -f "$HOME/snti-miner/snti-miner-loop.sh" >/dev/null 2>&1 || true
    if $HAS_SYSTEMD; then
      sudo systemctl disable --now "snti-miner" >/dev/null 2>&1 || true
    fi
  fi
fi
sleep 1

# -- 4. Download binaries (shared, satu per mesin)
inf "Downloading SNTI node binaries..."
mkdir -p "$INSTALL_DIR" || err "Cannot create $INSTALL_DIR — check permissions"
if [ -x "$INSTALL_DIR/bitcoind" ] && [ -x "$INSTALL_DIR/bitcoin-cli" ] && "$INSTALL_DIR/bitcoind" -version >/dev/null 2>&1; then
  ok "Binaries already exist, skipping download"
else
  FREE_MB=$(df -m "$INSTALL_DIR" | awk 'NR==2{{print $4}}')
  [ "${{FREE_MB:-0}}" -lt 500 ] && err "Not enough disk space (need 500MB free, have ${{FREE_MB}}MB at $INSTALL_DIR)"
  _download() {{
    local url="$1" dest="$2" label="$3"
    rm -f "$dest"
    curl -fSL --progress-bar "$url" -o "$dest" || {{ rm -f "$dest"; err "Failed to download $label (disk full? try: df -h)"; }}
  }}
  _download "$SNTI_API/bin/bitcoind"    "$INSTALL_DIR/bitcoind"    "bitcoind"
  _download "$SNTI_API/bin/bitcoin-cli" "$INSTALL_DIR/bitcoin-cli" "bitcoin-cli"
  chmod +x "$INSTALL_DIR/bitcoind" "$INSTALL_DIR/bitcoin-cli"
  ok "Binaries downloaded to $INSTALL_DIR"
fi

# -- 5. Setup datadir & config -- HANYA kalau node belum ada di mesin ini
# (node shared per mesin, config-nya tidak boleh ditimpa akun lain). Kalau
# sudah ada, baca kredensial RPC yang SEBENARNYA dipakai node itu (bisa
# beda dari RPC_USER/RPC_PASS akun ini sendiri kalau node dipasang akun lain).
if ! $NODE_EXISTS; then
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
  NODE_RPC_USER="$RPC_USER"
  NODE_RPC_PASS="$RPC_PASS"
else
  inf "Node sudah terpasang di mesin ini (shared dengan akun lain) — reuse, tidak ditimpa"
  NODE_RPC_USER=$(sed -n 's/^rpcuser=\\(.*\\)$/\\1/p' "$DATADIR/bitcoin.conf" | head -1)
  NODE_RPC_PASS=$(sed -n 's/^rpcpassword=\\(.*\\)$/\\1/p' "$DATADIR/bitcoin.conf" | head -1)
fi

CLI="$INSTALL_DIR/bitcoin-cli -datadir=$DATADIR -rpcuser=$NODE_RPC_USER -rpcpassword=$NODE_RPC_PASS -rpcport=$RPC_PORT"

# -- 6. Tulis file env PER-AKUN (dibaca oleh loop mining di setiap start,
# termasuk sesudah reboot) -- RPC_USER/RPC_PASS di sini adalah kredensial
# NODE yang sedang aktif (bisa milik akun lain kalau mesin ini shared).
mkdir -p "$MINER_DIR"
cat > "$MINER_DIR/snti.env" << EOF
DATADIR="$DATADIR"
INSTALL_DIR="$INSTALL_DIR"
RPC_USER="$NODE_RPC_USER"
RPC_PASS="$NODE_RPC_PASS"
RPC_PORT="$RPC_PORT"
SNTI_API="$SNTI_API"
SNTI_TOKEN="$SNTI_TOKEN"
WALLET_NAME="$WALLET_NAME"
WALLET_ADDRESS="$WALLET_ADDRESS"
EOF
ok "Config akun ditulis ke $MINER_DIR/snti.env"

# -- 7. Tulis mining loop (wallet+address+heartbeat+generatetoaddress) — dipanggil oleh service/cron
cat > "$MINER_DIR/snti-miner-loop.sh" << 'MINERSCRIPT'
#!/bin/bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
source "$SCRIPT_DIR/snti.env"

CLI="$INSTALL_DIR/bitcoin-cli -datadir=$DATADIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT"

echo "[miner] waiting for node RPC..."
for i in $(seq 1 60); do
  $CLI getblockcount >/dev/null 2>&1 && break
  sleep 2
done

echo "[miner] waiting for sync..."
while true; do
  IBD=$($CLI getblockchaininfo 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['initialblockdownload'])" 2>/dev/null || echo "true")
  {{ [ "$IBD" = "False" ] || [ "$IBD" = "false" ]; }} && break
  sleep 5
done
echo "[miner] synced, height $($CLI getblockcount 2>/dev/null)"

WLIST=$($CLI listwallets 2>/dev/null | python3 -c "import sys,json; print(','.join(json.load(sys.stdin)))" 2>/dev/null || echo "")
if [[ "$WLIST" != *"$WALLET_NAME"* ]]; then
  $CLI loadwallet "$WALLET_NAME" >/dev/null 2>&1 || $CLI createwallet "$WALLET_NAME" >/dev/null 2>&1 || true
fi

if [ -n "$WALLET_ADDRESS" ]; then
  ADDRESS="$WALLET_ADDRESS"
else
  ADDR_JSON=$($CLI getnewxmssaddress 2>&1)
  ADDRESS=$(echo "$ADDR_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['address'])" 2>/dev/null)
  if [ -z "$ADDRESS" ]; then
    echo "[miner] failed to get mining address: $ADDR_JSON" >&2
    exit 1
  fi
  curl -sf -X POST "$SNTI_API/api/wallet/watch" \\
    -H "Authorization: Bearer $SNTI_TOKEN" \\
    -H "Content-Type: application/json" \\
    -d "{{\\"address\\":\\"$ADDRESS\\",\\"label\\":\\"Miner - $(hostname)\\"}}" > /dev/null 2>&1 || true
fi
echo "[miner] mining to $ADDRESS"

_heartbeat() {{
  while true; do
    curl -sf -X POST "$SNTI_API/api/wallet/miner-heartbeat" \\
      -H "Authorization: Bearer $SNTI_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d "{{\\"hostname\\":\\"$(hostname)\\"}}" > /dev/null 2>&1 || true
    sleep 30
  done
}}
_heartbeat &

# SNTI FIX (5 Jul 2026): wallet-native XMSS addresses are one-time-use by
# cryptographic design (a WOTS+ leaf signing two different messages leaks
# the private key -- see xmss_signer.cpp). Mining used to reuse the SAME
# address for every block forever, so an address could pile up hundreds of
# separate 50-SNTI UTXOs that only ONE could ever be recovered later (see
# job_queue.md "koin dini hilang"). Rotate to a fresh server-issued address
# after every block instead, so each address only ever holds the exact one
# UTXO its one-time key can safely spend.
_rotate_address() {{
  local resp addr
  resp=$(curl -sf -X POST "$SNTI_API/api/wallet/next-mining-address" \\
    -H "Authorization: Bearer $SNTI_TOKEN" \\
    -H "Content-Type: application/json" 2>&1)
  addr=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['address'])" 2>/dev/null)
  echo "$addr"
}}

BLOCK=0
while true; do
  RESULT=$($CLI generatetoaddress 1 "$ADDRESS" 2>&1)
  if echo "$RESULT" | python3 -c "import sys,json; b=json.load(sys.stdin); exit(0 if b else 1)" 2>/dev/null; then
    BLOCK=$((BLOCK+1))
    HASH=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)[0][:16])" 2>/dev/null)
    H=$($CLI getblockcount 2>/dev/null || echo "?")
    echo "  [$BLOCK] Blok #$H ditemukan: ${{HASH}}..."
    NEW_ADDR=$(_rotate_address)
    if [ -n "$NEW_ADDR" ]; then
      ADDRESS="$NEW_ADDR"
      echo "  [miner] rotasi ke address baru: $ADDRESS"
    else
      echo "  [warn] gagal ambil address baru dari server -- tetap mining ke $ADDRESS untuk sementara (dana tetap aman, cuma menumpuk di 1 address sampai rotasi berhasil)" >&2
    fi
  fi
done
MINERSCRIPT
chmod +x "$MINER_DIR/snti-miner-loop.sh"
ok "Mining loop script written to $MINER_DIR/snti-miner-loop.sh"

# -- 8. Jalankan node (kalau belum ada, shared) + miner (selalu, per akun):
# systemd kalau ada, fallback nohup+cron kalau tidak
if $HAS_SYSTEMD; then
  if ! $NODE_EXISTS; then
    inf "Mendaftarkan systemd service node (shared, sekali per mesin)..."
    sudo tee "/etc/systemd/system/$SVC_NODE.service" > /dev/null << EOF
[Unit]
Description=SNTI Mainnet Node (shared)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CUR_USER
WorkingDirectory=$DATADIR
ExecStart=$INSTALL_DIR/bitcoind -datadir=$DATADIR -wallet=$WALLET_NAME -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT -port=$P2P_PORT -walletcrosschain
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now "$SVC_NODE"
    ok "Node service terdaftar & aktif"
  else
    inf "Node service sudah ada di mesin ini — memastikan tetap jalan (tidak direstart)..."
    sudo systemctl is-active --quiet "$SVC_NODE" 2>/dev/null || sudo systemctl start "$SVC_NODE" >/dev/null 2>&1 || true
  fi

  inf "Mendaftarkan systemd service mining loop (akun ini: $RPC_USER)..."
  sudo tee "/etc/systemd/system/$SVC_MINER.service" > /dev/null << EOF
[Unit]
Description=SNTI Miner Loop ($RPC_USER)
After=$SVC_NODE.service network-online.target
Requires=$SVC_NODE.service

[Service]
Type=simple
User=$CUR_USER
WorkingDirectory=$MINER_DIR
ExecStart=$MINER_DIR/snti-miner-loop.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable --now "$SVC_MINER"
  ok "Service terdaftar & aktif — otomatis restart kalau crash, otomatis start lagi kalau mesin reboot"
else
  inf "Menjalankan node (kalau belum ada) + miner via nohup (fallback tanpa systemd)..."
  if ! $NODE_EXISTS; then
    nohup "$INSTALL_DIR/bitcoind" -datadir="$DATADIR" -wallet="$WALLET_NAME" \\
      -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcport="$RPC_PORT" \\
      -port="$P2P_PORT" -walletcrosschain > "$DATADIR/node.log" 2>&1 < /dev/null &
    disown
  fi
  nohup "$MINER_DIR/snti-miner-loop.sh" > "$MINER_DIR/miner.log" 2>&1 < /dev/null &
  disown

  cat > "$MINER_DIR/snti-watchdog.sh" << EOF
#!/bin/bash
pgrep -f "$INSTALL_DIR/bitcoind" > /dev/null 2>&1 || \\
  ( nohup "$INSTALL_DIR/bitcoind" -datadir="$DATADIR" -wallet="$WALLET_NAME" \\
    -rpcuser="$NODE_RPC_USER" -rpcpassword="$NODE_RPC_PASS" -rpcport="$RPC_PORT" \\
    -port="$P2P_PORT" -walletcrosschain > "$DATADIR/node.log" 2>&1 < /dev/null & )
sleep 5
pgrep -f "$MINER_DIR/snti-miner-loop.sh" > /dev/null 2>&1 || \\
  ( nohup "$MINER_DIR/snti-miner-loop.sh" > "$MINER_DIR/miner.log" 2>&1 < /dev/null & )
EOF
  chmod +x "$MINER_DIR/snti-watchdog.sh"

  ( crontab -l 2>/dev/null | grep -vF "$MINER_DIR/snti-watchdog.sh" ; \\
    echo "@reboot sleep 20 && $MINER_DIR/snti-watchdog.sh" ; \\
    echo "* * * * * $MINER_DIR/snti-watchdog.sh" ) | crontab -
  ok "Tidak ada systemd — pakai cron watchdog (cek tiap menit + @reboot) sebagai fallback auto-restart"
fi

# -- 9. Tunggu node sampai sinkron (feedback interaktif di sesi instalasi ini)
inf "Menunggu node online..."
for i in $(seq 1 60); do
  H=$($CLI getblockcount 2>/dev/null) && [[ "$H" =~ ^[0-9]+$ ]] && break
  sleep 2
done
H=$($CLI getblockcount 2>/dev/null) || err "Node gagal start — cek log: journalctl -u $SVC_NODE -n 50  (atau $DATADIR/node.log kalau tanpa systemd)"
ok "Node online (height: $H)"

inf "Sinkronisasi blockchain (bisa beberapa menit)..."
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

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Mining berjalan di background!         ║"
echo "  ║   Rewards → {username}                   ║"
echo "  ║   Cek saldo: $SNTI_API/wallet/           ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
if [ -n "$WALLET_ADDRESS" ]; then
  ok "Mining ke address web wallet Anda: $WALLET_ADDRESS"
else
  ok "Address mining akan dibuat otomatis — cek beberapa saat lagi via log di bawah"
fi
echo ""
if $HAS_SYSTEMD; then
  echo "  Mining ini JALAN TERUS walau terminal ditutup, dan OTOMATIS START LAGI kalau:"
  echo "    - proses crash              (systemd Restart=always)"
  echo "    - mesin reboot/mati-hidup   (systemd enabled di boot)"
  echo ""
  echo "  Perintah berguna:"
  echo "    systemctl status $SVC_NODE $SVC_MINER     # cek status"
  echo "    journalctl -u $SVC_MINER -f               # lihat blok ditemukan (live)"
  echo "    sudo systemctl disable --now $SVC_MINER   # STOP mining akun ini SAJA"
  echo "    (JANGAN stop $SVC_NODE kalau akun lain di mesin ini masih mining -- itu node shared)"
else
  echo "  Mining ini JALAN TERUS walau terminal ditutup, dan OTOMATIS START LAGI kalau:"
  echo "    - proses mati        (cron cek tiap menit)"
  echo "    - mesin reboot        (cron @reboot)"
  echo ""
  echo "  Perintah berguna:"
  echo "    tail -f $MINER_DIR/miner.log       # lihat blok ditemukan (live)"
  echo "    crontab -l                         # lihat jadwal watchdog"
  echo "    crontab -l | grep -vF $MINER_DIR | crontab -   # STOP watchdog akun ini, lalu: pkill -f $MINER_DIR/snti-miner-loop.sh"
fi
echo ""
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
    # SNTI FIX (5 Jul 2026): see _scan_addresses() -- batched scantxoutset
    # alone missed P2XMSS-pure outputs for watched addresses this wallet
    # also happens to hold keys for (common here since it's a shared node
    # wallet, e.g. watching another of your own rotated addresses).
    utxos = _scan_addresses([addr for addr, _, _ in rows])
    balance_map = {}
    for utxo in utxos:
        addr = utxo.get("address")
        if addr:
            balance_map[addr] = balance_map.get(addr, 0) + utxo.get("amount", 0)
    result = []
    for address, label, created_at in rows:
        balance = balance_map.get(address, 0)
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

@app.route("/api/wallet/next-mining-address", methods=["POST"])
@jwt_required
def next_mining_address():
    """SNTI FIX (5 Jul 2026): mints a fresh wallet-native address and records
    it in mining_addresses. Called by the miner loop before EVERY block
    (see _generate_install_script) instead of reusing one static address
    forever -- each wallet-native address is one-time-use by cryptographic
    design (xmss_signer.cpp), so an address that piles up many block rewards
    can only ever have ONE of them recovered later. Rotating per-block means
    every address this user ever mines to holds exactly the one UTXO its
    one-time key can safely spend.
    """
    addr_result = rpc_call("getnewxmssaddress")
    if isinstance(addr_result, dict) and "error" in addr_result:
        return jsonify({"error": "node unavailable, cannot create new address"}), 503
    address = addr_result.get("address", "") if isinstance(addr_result, dict) else str(addr_result)
    if not address:
        return jsonify({"error": "node returned no address"}), 502
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO mining_addresses (user_id, address, created_at) VALUES (?,?,?)",
        (request.user_id, address, int(time.time()))
    )
    conn.execute("UPDATE users SET xmss_address=? WHERE id=?", (address, request.user_id))
    conn.commit()
    conn.close()
    return jsonify({"address": address})

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
