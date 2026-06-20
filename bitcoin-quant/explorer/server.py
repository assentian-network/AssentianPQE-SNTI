#!/usr/bin/env python3
"""
QNT Block Explorer - Flask Backend
Proxies bitcoind RPC calls for the Quant post-quantum cryptocurrency block explorer.
"""

import os
import json
import requests
from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RPC_USER = os.environ.get("QNT_RPC_USER", "user")
RPC_PASSWORD = os.environ.get("QNT_RPC_PASSWORD", "password")
RPC_HOST = os.environ.get("QNT_RPC_HOST", "127.0.0.1")
RPC_PORT = os.environ.get("QNT_RPC_PORT", "29332")
RPC_URL = os.environ.get(
    "QNT_RPC_URL", f"http://{RPC_HOST}:{RPC_PORT}"
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
        resp.raise_for_status()
        data = resp.json()
        if "error" in data and data["error"] is not None:
            return {"error": data["error"]}
        return data.get("result")
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to bitcoind at {RPC_URL}"}
    except requests.exceptions.Timeout:
        return {"error": "RPC call timed out"}
    except Exception as e:
        return {"error": str(e)}

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
    """Return recent git commits from the QNT repo."""
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
        "blocks_mined": tip_height + 1,
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


if __name__ == "__main__":
    port = int(os.environ.get("QNT_EXPLORER_PORT", 8081))
    debug = os.environ.get("QNT_EXPLORER_DEBUG", "0") == "1"
    print(f"QNT Block Explorer starting on http://0.0.0.0:{port}")
    print(f"RPC target: {RPC_URL}")
    app.run(host="0.0.0.0", port=port, debug=debug)
