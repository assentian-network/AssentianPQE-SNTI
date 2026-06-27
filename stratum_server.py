#!/usr/bin/env python3
"""
Assentian-PQE (SNTI) Stratum Mining Server
===========================================
Stratum-to-RPC proxy for SNTI testnet (Wave 1: CPU mining).

Architecture notes:
  XMSS signing is performed INSIDE bitcoind (not externally constructable).
  Therefore this server uses a hybrid approach:
  - Send simplified SHA-256 proof-of-work jobs to miners
  - When a miner finds a valid share, trigger bitcoind's generatetoaddress
    (which handles XMSS keygen + signing + PoUW internally)
  - Mining reward goes to server's pool address
  
  This is intentional for Wave 1 (CPU testnet). A full getwork/submitblock
  flow requires exposing XMSS signing at RPC level (planned for Wave 2).

Usage:
    python3 stratum_server.py [options]

Options:
    --port        Stratum port (default: 3333)
    --rpc-port    bitcoind RPC port (default: 39332)
    --rpc-host    bitcoind RPC host (default: 127.0.0.1)
    --rpc-user    RPC username (default: user)
    --rpc-pass    RPC password (default: password)
    --address     Pool reward address (auto-generated if not set)
    --shares-per-block  Shares required before mining attempt (default: 5)
"""

import asyncio
import json
import hashlib
import struct
import time
import binascii
import logging
import argparse
import os
import sys
import threading
from decimal import Decimal

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_PORT = 3333
DEFAULT_RPC_PORT = 39332
DEFAULT_RPC_USER = os.environ.get("SNTI_RPC_USER", "user")
DEFAULT_RPC_PASS = os.environ.get("SNTI_RPC_PASS", "")  # N1 fix: never hardcode — set SNTI_RPC_PASS env var
DEFAULT_RPC_HOST = "127.0.0.1"
DEFAULT_MINER_ADDRESS = ""
DEFAULT_SHARES_PER_BLOCK = 5

# Share difficulty target (adjust for CPU mining speed)
# This is very easy - any CPU can find shares quickly
SHARE_DIFFICULTY = 0.001  # Very low for Wave 1 CPU mining
SHARE_TARGET = 0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

BLOCK_TEMPLATE_INTERVAL = 30  # seconds
STATS_INTERVAL = 60  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("snti-stratum")

# ---------------------------------------------------------------------------
# Bitcoin RPC helper
# ---------------------------------------------------------------------------
try:
    import requests
except ImportError:
    log.error("requests not installed. Run: pip3 install requests")
    sys.exit(1)


class BitcoinRPC:
    def __init__(self, host, port, user, password):
        self.url = f"http://{host}:{port}"
        self.auth = (user, password)
        self.id = 0

    def call(self, method, params=None, timeout=30):
        self.id += 1
        payload = {
            "jsonrpc": "1.0",
            "id": self.id,
            "method": method,
            "params": params or [],
        }
        try:
            resp = requests.post(
                self.url,
                json=payload,
                auth=self.auth,
                timeout=timeout,
            )
            data = resp.json()
            if data.get("error"):
                log.error(f"RPC error ({method}): {data['error']}")
                return None
            return data.get("result")
        except Exception as e:
            log.error(f"RPC call failed ({method}): {e}")
            return None

    def get_block_template(self):
        return self.call("getblocktemplate", [{"rules": ["segwit"]}])

    def get_blockchain_info(self):
        return self.call("getblockchaininfo")

    def get_mining_info(self):
        return self.call("getmininginfo")

    def get_new_address(self, wallet="snti_pool"):
        # Must use wallet-specific RPC path
        self.id += 1
        payload = {
            "jsonrpc": "1.0",
            "id": self.id,
            "method": "getnewaddress",
            "params": [],
        }
        try:
            resp = requests.post(
                f"{self.url}/wallet/{wallet}",
                json=payload,
                auth=self.auth,
                timeout=10,
            )
            data = resp.json()
            if data.get("error"):
                return None
            return data.get("result")
        except Exception as e:
            log.error(f"get_new_address failed: {e}")
            return None

    def get_block_count(self):
        return self.call("getblockcount")

    def generate_to_address(self, n_blocks, address):
        """Mine n_blocks to address. PoUW v2 XMSS tree building happens inside bitcoind."""
        # Do NOT use wallet endpoint — generatetoaddress works at root RPC level.
        # Timeout 180s: XMSS tree build takes ~6s/attempt, may need many attempts.
        return self.call("generatetoaddress", [n_blocks, address], timeout=180)

    def load_wallet(self, name):
        self.id += 1
        payload = {"jsonrpc": "1.0", "id": self.id, "method": "loadwallet", "params": [name]}
        try:
            resp = requests.post(self.url, json=payload, auth=self.auth, timeout=10)
            data = resp.json()
            err = data.get("error")
            if err and "already loaded" not in str(err.get("message", "")):
                log.warning(f"loadwallet {name}: {err}")
                return False
            return True
        except Exception as e:
            log.warning(f"loadwallet {name}: {e}")
            return False

    def create_wallet(self, name):
        """Create wallet, ignore error if already exists."""
        self.id += 1
        payload = {"jsonrpc": "1.0", "id": self.id, "method": "createwallet", "params": [name]}
        try:
            resp = requests.post(self.url, json=payload, auth=self.auth, timeout=10)
            data = resp.json()
            # Ignore "already exists" error
            if data.get("error") and "already exists" not in str(data["error"]):
                log.warning(f"createwallet: {data['error']}")
        except Exception as e:
            log.debug(f"createwallet: {e}")


# ---------------------------------------------------------------------------
# Job tracking
# ---------------------------------------------------------------------------
class Job:
    def __init__(self, job_id, prev_hash, version, bits, curtime, height):
        self.job_id = job_id
        self.prev_hash = prev_hash
        self.version = version
        self.bits = bits
        self.curtime = curtime
        self.height = height
        self.created_at = time.time()

    def to_notify_params(self, clean_jobs=False):
        """Return params for mining.notify message."""
        # Coinbase placeholder (miner doesn't need real coinbase for simplified flow)
        coinbase1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"
        coinbase2 = "ffffffff0100f2052a01000000434104"

        return [
            self.job_id,
            self.prev_hash,
            coinbase1,
            coinbase2,
            [],  # merkle branches (empty - simplified)
            "{:08x}".format(self.version),
            "{:08x}".format(self.bits),
            "{:08x}".format(self.curtime),
            clean_jobs,
        ]


# ---------------------------------------------------------------------------
# Stratum Server
# ---------------------------------------------------------------------------
class StratumServer:
    def __init__(self, rpc, port, pool_address=None, shares_per_block=5):
        self.rpc = rpc
        self.port = port
        self.pool_address = pool_address
        self.shares_per_block = shares_per_block
        self.active = True

        # State
        self.current_job = None
        self.template_lock = asyncio.Lock()
        self.last_template_update = 0
        self.last_block_height = 0
        self.mining_in_progress = False  # prevent concurrent PoUW attempts

        # Stats
        self.total_shares = 0
        self.accepted = 0
        self.rejected = 0
        self.blocks_found = 0
        self.workers = {}  # worker_id -> {total, accepted, rejected, last_share}
        self.connected_workers = 0
        self.start_time = time.time()

    def _make_job_id(self):
        return binascii.hexlify(os.urandom(4)).decode()

    def _make_job_from_template(self, template, clean=False):
        if not template:
            return None, False
        prev_hash = template.get("previousblockhash", "0" * 64)
        version = template.get("version", 0x20000000)
        bits = template.get("bits", "207fffff")
        if isinstance(bits, str):
            bits = int(bits, 16)
        curtime = int(time.time())
        height = template.get("height", 0)
        job_id = self._make_job_id()
        return Job(job_id, prev_hash, version, bits, curtime, height), clean

    async def update_template(self):
        """Periodically fetch new block template."""
        while self.active:
            try:
                await asyncio.sleep(BLOCK_TEMPLATE_INTERVAL)
                template = self.rpc.get_block_template()
                if template:
                    height = template.get("height", 0)
                    new_block = height != self.last_block_height
                    if new_block:
                        self.last_block_height = height
                        log.info(f"New block height: {height} — sending new work to all miners")
                    async with self.template_lock:
                        job, clean = self._make_job_from_template(template, clean=new_block)
                        if job:
                            self.current_job = job
            except Exception as e:
                log.error(f"Template update error: {e}")

    async def get_current_job(self):
        async with self.template_lock:
            if self.current_job is None:
                template = self.rpc.get_block_template()
                if template:
                    job, _ = self._make_job_from_template(template, clean=True)
                    self.current_job = job
                    self.last_block_height = template.get("height", 0)
            return self.current_job

    def _check_share(self, nonce_hex, job_id):
        """
        Validate share for Wave 1 CPU mining.
        
        Wave 1 approach: accept all shares with valid nonce format.
        The actual PoW difficulty is enforced by bitcoind's generatetoaddress.
        This allows cpuminer and other standard stratum miners to work
        without implementing full block header construction.
        
        Wave 2 will implement proper share validation against real block header.
        """
        try:
            # Validate nonce format (must be valid hex, 1-8 chars)
            nonce = int(nonce_hex, 16)
            if nonce < 0 or nonce > 0xFFFFFFFF:
                return False
            return True  # Accept all valid-format shares in Wave 1
        except (ValueError, TypeError):
            return False

    async def _try_mine_block(self, writer, worker_id):
        """
        Trigger PoUW v2 block mining via bitcoind's generatetoaddress.
        Bitcoind handles XMSS tree building and SK_SEED search internally.
        Called after every shares_per_block accepted shares.
        """
        if not (self.accepted > 0 and self.accepted % self.shares_per_block == 0):
            return

        # Prevent concurrent XMSS mining attempts — they're CPU-heavy
        if self.mining_in_progress:
            log.debug("Mining already in progress, skipping trigger")
            return
        self.mining_in_progress = True

        worker = self.workers.get(worker_id, {})
        address = worker.get("miner_address") or self.pool_address
        if not address:
            address = self.rpc.get_new_address()
        if not address:
            log.error("No address available for mining")
            self.mining_in_progress = False
            return

        log.info(f"⛏ PoUW v2 mining triggered (shares: {self.accepted}) → {address}")
        loop = asyncio.get_event_loop()
        try:
            hashes = await loop.run_in_executor(
                None, lambda: self.rpc.generate_to_address(1, address)
            )
            if hashes and len(hashes) > 0:
                self.blocks_found += 1
                log.info(f"✅ Block found! Hash: {hashes[0]} (total: {self.blocks_found})")
                async with self.template_lock:
                    self.current_job = None
                await self._send_work(writer, worker_id)
            else:
                log.warning("generatetoaddress returned no hashes")
        except Exception as e:
            log.error(f"Mining attempt failed: {e}")
        finally:
            self.mining_in_progress = False

    @staticmethod
    async def _send(writer, msg):
        data = json.dumps(msg) + "\n"
        try:
            writer.write(data.encode())
            await writer.drain()
        except Exception as e:
            log.debug(f"Send error: {e}")

    async def _send_difficulty(self, writer):
        msg = {
            "id": None,
            "method": "mining.set_difficulty",
            "params": [0.001],  # Very low for Wave 1 - cpuminer will submit shares frequently
        }
        await self._send(writer, msg)

    async def _send_work(self, writer, worker_id):
        job = await self.get_current_job()
        if not job:
            log.warning(f"No job available for worker {worker_id}")
            return
        msg = {
            "id": None,
            "method": "mining.notify",
            "params": job.to_notify_params(clean_jobs=True),
        }
        await self._send(writer, msg)

    async def _handle_message(self, msg, writer, worker_id):
        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", [])

        if method == "mining.subscribe":
            resp = {
                "id": msg_id,
                "result": [
                    [
                        ["mining.set_difficulty", "snti-stratum-v2"],
                        ["mining.notify", "snti-stratum-v2"],
                    ],
                    "00000000",  # extranonce1
                    4,           # extranonce2 size
                ],
                "error": None,
            }
            await self._send(writer, resp)

        elif method == "mining.authorize":
            username = params[0] if params else worker_id
            resp = {"id": msg_id, "result": True, "error": None}
            await self._send(writer, resp)
            log.info(f"Worker authorized: {username} (id: {worker_id})")
            # Wave 2: username IS the miner's SNTI address
            miner_address = username if username.startswith("tq1") or username.startswith("q1") or len(username) > 20 else None
            self.workers[worker_id] = {
                "username": username,
                "miner_address": miner_address,
                "total": 0,
                "accepted": 0,
                "rejected": 0,
                "last_share": None,
                "connected_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
            if miner_address:
                log.info(f"Wave 2: miner address set to {miner_address}")
            else:
                log.warning(f"Wave 2: username '{username}' is not a valid SNTI address — reward will go to pool address")
            await self._send_difficulty(writer)
            await self._send_work(writer, worker_id)

        elif method == "mining.submit":
            if len(params) >= 3:
                username = params[0]
                job_id = params[1]
                # Stratum standard format: [username, job_id, extranonce2, ntime, nonce]
                # cpuminer sends 5 params, nonce is params[4]
                # Fallback to params[2] for simple clients
                if len(params) >= 5:
                    nonce_hex = params[4]  # standard stratum nonce position
                else:
                    nonce_hex = params[2] if len(params) > 2 else "00000000"

                accepted = self._check_share(nonce_hex, job_id)
                self.total_shares += 1

                if accepted:
                    self.accepted += 1
                    if worker_id in self.workers:
                        self.workers[worker_id]["total"] += 1
                        self.workers[worker_id]["accepted"] += 1
                        self.workers[worker_id]["last_share"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                    resp = {"id": msg_id, "result": True, "error": None}
                    log.info(f"✅ Share accepted from {username} (accepted: {self.accepted})")
                else:
                    self.rejected += 1
                    if worker_id in self.workers:
                        self.workers[worker_id]["total"] += 1
                        self.workers[worker_id]["rejected"] += 1
                    resp = {"id": msg_id, "result": False, "error": [21, "Invalid share", None]}
                    log.warning(f"❌ Share rejected from {username}")

                await self._send(writer, resp)
                if accepted:
                    await self._try_mine_block(writer, worker_id)
            else:
                resp = {"id": msg_id, "result": False, "error": [20, "Invalid submit params", None]}
                await self._send(writer, resp)

        elif method == "mining.extranonce.subscribe":
            resp = {"id": msg_id, "result": True, "error": None}
            await self._send(writer, resp)

        elif method == "mining.get_transactions":
            resp = {"id": msg_id, "result": [], "error": None}
            await self._send(writer, resp)

        else:
            if msg_id is not None:
                resp = {"id": msg_id, "result": None, "error": [20, f"Unknown method: {method}", None]}
                await self._send(writer, resp)

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info("peername")
        worker_id = f"{addr[0]}:{addr[1]}"
        self.connected_workers += 1
        log.info(f"Miner connected: {worker_id} (total: {self.connected_workers})")

        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=600)
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    await self._handle_message(msg, writer, worker_id)
                except json.JSONDecodeError:
                    log.warning(f"Invalid JSON from {worker_id}: {line[:100]}")
        except asyncio.TimeoutError:
            log.info(f"Worker timeout: {worker_id}")
        except Exception as e:
            log.debug(f"Worker disconnected: {worker_id} ({e})")
        finally:
            self.connected_workers -= 1
            self.workers.pop(worker_id, None)
            log.info(f"Miner disconnected: {worker_id} (remaining: {self.connected_workers})")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def get_stats(self):
        uptime = int(time.time() - self.start_time)
        return {
            "uptime_seconds": uptime,
            "connected_workers": self.connected_workers,
            "total_shares": self.total_shares,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "blocks_found": self.blocks_found,
            "shares_per_block": self.shares_per_block,
            "pool_address": self.pool_address,
            "workers": self.workers,
        }

    async def _stats_reporter(self):
        while self.active:
            await asyncio.sleep(STATS_INTERVAL)
            info = self.rpc.get_blockchain_info()
            blocks = info.get("blocks", "?") if info else "?"
            mining_flag = " [mining]" if self.mining_in_progress else ""
            log.info(
                f"📊 Stats — workers: {self.connected_workers} | "
                f"shares: {self.accepted}/{self.total_shares} | "
                f"blocks found: {self.blocks_found} | "
                f"chain height: {blocks}{mining_flag}"
            )

    async def _http_stats(self):
        """Simple HTTP stats endpoint on port stratum+1."""
        stats_port = self.port + 1

        async def handler(reader, writer):
            try:
                await reader.read(1024)
                stats = self.get_stats()
                body = json.dumps(stats, indent=2)
                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Access-Control-Allow-Origin: *\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                    f"{body}"
                )
                writer.write(response.encode())
                await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        server = await asyncio.start_server(handler, "0.0.0.0", stats_port)
        log.info(f"📈 Stats HTTP endpoint: http://0.0.0.0:{stats_port}/")
        async with server:
            await server.serve_forever()

    async def start(self):
        # Load mining wallet — required for generatetoaddress when miner address
        # is not provided by the connecting worker.
        log.info("Loading snti_testnet wallet...")
        self.rpc.load_wallet("snti_testnet")

        # Setup pool wallet & address
        if not self.pool_address:
            log.info("Setting up pool wallet...")
            self.rpc.create_wallet("snti_pool")
            self.pool_address = self.rpc.get_new_address("snti_pool")
            if self.pool_address:
                log.info(f"Pool address: {self.pool_address}")
            else:
                log.warning("Could not get pool address — will retry on first share")

        # Initial template fetch
        template = self.rpc.get_block_template()
        if template:
            job, _ = self._make_job_from_template(template, clean=True)
            self.current_job = job
            self.last_block_height = template.get("height", 0)
            log.info(f"Initial block template: height={self.last_block_height}")
        else:
            log.warning("Could not fetch initial block template — node might not be ready")

        # Start background tasks
        asyncio.create_task(self.update_template())
        asyncio.create_task(self._stats_reporter())
        asyncio.create_task(self._http_stats())

        # Start stratum server
        server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.port)
        log.info(f"🚀 Assentian-PQE Stratum Server (PoUW v2) started on port {self.port}")
        log.info(f"   Connect miners to: stratum+tcp://YOUR_IP:{self.port}")
        log.info(f"   Network: testnet | RPC: {self.rpc.url}")
        log.info(f"   PoUW v2: XMSS tree building via bitcoind | Shares per block: {self.shares_per_block}")

        async with server:
            await server.serve_forever()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Assentian-PQE Stratum Mining Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Stratum port")
    parser.add_argument("--rpc-host", default=DEFAULT_RPC_HOST, help="bitcoind RPC host")
    parser.add_argument("--rpc-port", type=int, default=DEFAULT_RPC_PORT, help="bitcoind RPC port")
    parser.add_argument("--rpc-user", default=DEFAULT_RPC_USER, help="RPC username")
    parser.add_argument("--rpc-pass", default=DEFAULT_RPC_PASS, help="RPC password")
    parser.add_argument("--address", default=DEFAULT_MINER_ADDRESS, help="Pool reward address")
    parser.add_argument("--shares-per-block", type=int, default=DEFAULT_SHARES_PER_BLOCK,
                        help="Shares required before mining attempt")
    args = parser.parse_args()

    if not args.rpc_pass:
        log.error("RPC password not set. Use --rpc-pass or export SNTI_RPC_PASS=<password>")
        sys.exit(1)

    rpc = BitcoinRPC(args.rpc_host, args.rpc_port, args.rpc_user, args.rpc_pass)

    # Test RPC connection
    info = rpc.get_blockchain_info()
    if not info:
        log.error(f"Cannot connect to bitcoind at {rpc.url}")
        log.error("Make sure assentian-node.service is running")
        sys.exit(1)

    log.info(f"Connected to bitcoind: chain={info.get('chain')} blocks={info.get('blocks')}")

    server = StratumServer(
        rpc=rpc,
        port=args.port,
        pool_address=args.address or None,
        shares_per_block=args.shares_per_block,
    )

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        log.info("Stratum server stopped.")


if __name__ == "__main__":
    main()
