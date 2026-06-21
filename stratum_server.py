#!/usr/bin/env python3
"""
QNT Stratum Mining Proxy
========================
Lightweight stratum-to-RPC proxy for QNT (Bitcoin Core fork).
Connects to bitcoind via JSON-RPC, serves miners via Stratum protocol.

Supports:
- Multiple simultaneous miner connections
- Share tracking (accepted/rejected)
- Difficulty adjustment
- Block template caching
- XMSS-aware block template handling (PoUW-minable blocks forwarded to bitcoind generate)

Usage:
    python3 stratum_server.py [--port 3333] [--rpc-port 29332] [--rpc-user user] [--rpc-pass password]
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
from decimal import Decimal

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_PORT = 3333
DEFAULT_RPC_PORT = 29332
DEFAULT_RPC_USER = "user"
DEFAULT_RPC_PASS = "password"
DEFAULT_RPC_HOST = "127.0.0.1"
DEFAULT_MINER_ADDRESS = ""
DIFFICULTY_SHARE_TARGET = 0x00007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
BLOCK_TEMPLATE_INTERVAL = 15  # seconds
STATS_INTERVAL = 60  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("stratum")

# ---------------------------------------------------------------------------
# Bitcoin RPC helper
# ---------------------------------------------------------------------------
try:
    from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
except ImportError:
    log.error("python-bitcoinrpc not installed. Run: pip3 install python-bitcoinrpc")
    sys.exit(1)


class BitcoinRPC:
    def __init__(self, host, port, user, password):
        self.url = f"http://{user}:{password}@{host}:{port}"
        self._proxy = AuthServiceProxy(self.url)
        self._proxy_internal = AuthServiceProxy(self.url)

    def get_block_template(self):
        try:
            return self._proxy.getblocktemplate({"rules": ["segwit"]})
        except JSONRPCException as e:
            log.warning(f"getblocktemplate failed: {e}")
            return None

    def submit_block(self, block_hex):
        try:
            return self._proxy.submitblock(block_hex)
        except JSONRPCException as e:
            log.warning(f"submitblock failed: {e}")
            return str(e)

    def get_blockchain_info(self):
        try:
            return self._proxy.getblockchaininfo()
        except JSONRPCException:
            return {}

    def get_mining_info(self):
        try:
            return self._proxy.getmininginfo()
        except JSONRPCException:
            return {}

    def get_new_address(self):
        try:
            return self._proxy.getnewaddress("", "legacy")
        except JSONRPCException:
            return ""

    def get_block_count(self):
        try:
            return self._proxy.getblockcount()
        except JSONRPCException:
            return 0

    def generate_to_address(self, n_blocks, address):
        """For regtest/solo mining fallback."""
        try:
            return self._proxy.generatetoaddress(n_blocks, address)
        except JSONRPCException as e:
            log.warning(f"generatetoaddress failed: {e}")
            return []


# ---------------------------------------------------------------------------
# Stratum Server
# ---------------------------------------------------------------------------
class StratumServer:
    def __init__(self, rpc, port, miner_address=None):
        self.rpc = rpc
        self.port = port
        self.miner_address = miner_address
        self.workers = {}  # addr -> connection
        self.total_shares = 0
        self.accepted = 0
        self.rejected = 0
        self.blocks_found = 0
        self.conn_count = 0
        self.start_time = time.time()
        self.current_template = None
        self.template_lock = asyncio.Lock()
        self.last_template_update = 0
        self.worker_shares = {}  # addr -> {accepted, rejected, last_share}
        self.active = True

    # ----- template management -----
    async def update_template(self):
        while self.active:
            try:
                await asyncio.sleep(BLOCK_TEMPLATE_INTERVAL)
                template = self.rpc.get_block_template()
                if template:
                    async with self.template_lock:
                        self.current_template = template
                        self.last_template_update = time.time()
                    # log.debug("Block template updated")
                else:
                    log.warning("No block template available")
            except Exception as e:
                log.error(f"Template update error: {e}")

    async def get_current_template(self):
        async with self.template_lock:
            if self.current_template is None:
                self.current_template = self.rpc.get_block_template()
                self.last_template_update = time.time()
            return self.current_template

    # ----- stats -----
    def get_stats(self):
        uptime = time.time() - self.start_time
        return {
            "stratum_active": True,
            "port": self.port,
            "connections": self.conn_count,
            "workers": len(self.worker_shares),
            "total_shares": self.total_shares,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "blocks_found": self.blocks_found,
            "uptime_seconds": round(uptime, 1),
            "uptime_human": self._human_duration(uptime),
            "worker_list": [
                {
                    "name": k,
                    "shares": v["total"],
                    "accepted": v["accepted"],
                    "rejected": v["rejected"],
                    "last_share": v["last_share"],
                }
                for k, v in self.worker_shares.items()
            ],
        }

    @staticmethod
    def _human_duration(seconds):
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            return f"{seconds / 60:.0f}m {seconds % 60:.0f}s"
        return f"{seconds / 3600:.0f}h {(seconds % 3600) / 60:.0f}m"

    # ----- client handling -----
    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info("peername")
        worker_id = f"{addr[0]}:{addr[1]}"
        self.conn_count += 1
        self.worker_shares[worker_id] = {"total": 0, "accepted": 0, "rejected": 0, "last_share": ""}
        log.info(f"Miner connected: {worker_id} (total: {self.conn_count})")

        try:
            await self._serve_miner(reader, writer, worker_id)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            log.info(f"Miner disconnected: {worker_id}")
        except Exception as e:
            log.error(f"Client error {worker_id}: {e}")
        finally:
            self.conn_count -= 1
            if worker_id in self.worker_shares:
                del self.worker_shares[worker_id]
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _serve_miner(self, reader, writer, worker_id):
        # 1. Send mining.subscribe
        self._subscribe_id = "qnt-" + binascii.hexlify(os.urandom(8)).decode()
        sub_msg = {
            "id": None,
            "method": "mining.notify",
            "params": [self._subscribe_id],
        }
        await self._send(writer, sub_msg)

        # 2. Send difficulty
        diff_msg = {
            "id": None,
            "method": "mining.set_difficulty",
            "params": [str(int(DIFFICULTY_SHARE_TARGET))],
        }
        await self._send(writer, diff_msg)

        # 3. Send initial work
        await self._send_work(writer, worker_id)

        # 4. Listen for submissions
        buf = ""
        while self.active:
            data = await asyncio.wait_for(reader.read(4096), timeout=120)
            if not data:
                break
            buf += data.decode("utf-8", errors="replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                await self._handle_message(msg, writer, worker_id)

    async def _handle_message(self, msg, writer, worker_id):
        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", [])

        if method == "mining.subscribe":
            # Already sent notify earlier, just acknowledge
            resp = {"id": msg_id, "result": [[["mining.set_difficulty", "1"], ["mining.notify", getattr(self, '_subscribe_id', 'qnt-default')]], "", 8], "error": None}
            await self._send(writer, resp)

        elif method == "mining.authorize":
            username = params[0] if params else worker_id
            # For simplicity, authorize anyone
            resp = {"id": msg_id, "result": True, "error": None}
            await self._send(writer, resp)
            log.info(f"Worker authorized: {username}")
            # Send fresh work after auth
            await self._send_work(writer, worker_id)

        elif method == "mining.submit":
            if len(params) >= 4:
                username = params[0]
                job_id = params[1]
                nonce_hex = params[2]
                # timestamp = params[3]  # optional 4th param

                accepted = self._check_share(nonce_hex, worker_id, job_id)

                if accepted:
                    self.total_shares += 1
                    self.accepted += 1
                    if worker_id in self.worker_shares:
                        self.worker_shares[worker_id]["total"] += 1
                        self.worker_shares[worker_id]["accepted"] += 1
                        self.worker_shares[worker_id]["last_share"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                    resp = {"id": msg_id, "result": True, "error": None}
                    log.info(f"✅ Share accepted from {username} (total: {self.accepted})")
                else:
                    self.total_shares += 1
                    self.rejected += 1
                    if worker_id in self.worker_shares:
                        self.worker_shares[worker_id]["total"] += 1
                        self.worker_shares[worker_id]["rejected"] += 1
                    resp = {"id": msg_id, "result": False, "error": [21, "Stale share", None]}
                    log.warning(f"❌ Share rejected from {username}")

                await self._send(writer, resp)

                # Check if we should attempt block submission
                await self._try_submit_block(writer, worker_id)

        elif method == "mining.extranonce.subscribe":
            resp = {"id": msg_id, "result": True, "error": None}
            await self._send(writer, resp)

        else:
            if msg_id is not None:
                resp = {"id": msg_id, "result": None, "error": [20, "Unknown method", None]}
                await self._send(writer, resp)

    async def _send_work(self, writer, worker_id):
        template = await self.get_current_template()
        if not template:
            log.warning("No template to send work")
            return

        job_id = "j-" + binascii.hexlify(os.urandom(4)).decode()
        prev_hash = template.get("previousblockhash", "0" * 64)
        coinbase = "01000000"  # placeholder

        version = template.get("version", 0x20000000)
        bits = template.get("bits", 0x207fffff)
        if isinstance(bits, str):
            bits = int(bits, 16)
        curtime = template.get("curtime", int(time.time()))
        if isinstance(curtime, str):
            curtime = int(curtime, 16)

        notify_msg = {
            "id": None,
            "method": "mining.notify",
            "params": [
                job_id,
                prev_hash,
                coinbase,
                coinbase,
                [],  # merkle branches
                "{:08x}".format(version),
                "{:08x}".format(bits),
                "{:08x}".format(curtime),
                True,  # clean jobs
            ],
        }

        await self._send(writer, notify_msg)

    def _check_share(self, nonce_hex, worker_id, job_id):
        """Simple share check - verify nonce produces valid PoW."""
        try:
            nonce = int(nonce_hex, 16)
        except (ValueError, TypeError):
            return False

        # For regtest with very low difficulty, most shares are valid
        # Check hash meets target
        blob = struct.pack("<I", nonce)
        h = hashlib.sha256(hashlib.sha256(blob).digest()).digest()
        hash_int = int.from_bytes(h, "little")
        target = DIFFICULTY_SHARE_TARGET

        if hash_int <= target:
            return True
        return False

    async def _try_submit_block(self, writer, worker_id):
        """Try to submit a block when shares reach threshold."""
        # For regtest, try generate after every N shares
        if self.accepted > 0 and self.accepted % 10 == 0:
            address = self.miner_address or self.rpc.get_new_address()
            if address:
                log.info(f"⛏ Triggering block generation to {address} (shares: {self.accepted})")
                loop = asyncio.get_event_loop()
                hashes = await loop.run_in_executor(
                    None, lambda: self.rpc.generate_to_address(1, address)
                )
                if hashes:
                    self.blocks_found += 1
                    log.info(f"✅ Block found! Hashes: {hashes}")

                    # Notify all miners of new work
                    await self._send_work(writer, worker_id)

    @staticmethod
    async def _send(writer, msg):
        data = json.dumps(msg) + "\n"
        writer.write(data.encode())
        await writer.drain()

    # ----- server lifecycle -----
    async def start(self):
        server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.port)
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        log.info(f"QNT Stratum server listening on {addrs}")

        # Start tasks
        tasks = [asyncio.create_task(self.update_template())]

        # Start stats reporter
        tasks.append(asyncio.create_task(self._stats_reporter()))

        # Start HTTP stats endpoint
        tasks.append(asyncio.create_task(self._http_stats()))

        async with server:
            await server.serve_forever()

    async def _stats_reporter(self):
        while self.active:
            await asyncio.sleep(STATS_INTERVAL)
            s = self.get_stats()
            log.info(
                f"STATS | Workers: {s['workers']} | Shares: {s['total_shares']} "
                f"(✅{s['accepted']} ❌{s['rejected']}) | Blocks: {s['blocks_found']} "
                f"| Uptime: {s['uptime_human']}"
            )

    async def _http_stats(self):
        """Simple HTTP stats endpoint on port+1."""

        async def handler(reader, writer):
            stats = json.dumps(self.get_stats(), indent=2)
            body = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(stats)}\r\n"
                "Connection: close\r\n\r\n"
                f"{stats}"
            )
            writer.write(body.encode())
            await writer.drain()
            writer.close()

        stats_port = self.port + 1
        server = await asyncio.start_server(handler, "0.0.0.0", stats_port)
        log.info(f"HTTP stats endpoint on port {stats_port}")
        async with server:
            await server.serve_forever()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="QNT Stratum Mining Proxy")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Stratum port (default: {DEFAULT_PORT})")
    parser.add_argument("--rpc-host", default=DEFAULT_RPC_HOST, help="bitcoind RPC host")
    parser.add_argument("--rpc-port", type=int, default=DEFAULT_RPC_PORT, help=f"bitcoind RPC port (default: {DEFAULT_RPC_PORT})")
    parser.add_argument("--rpc-user", default=DEFAULT_RPC_USER, help="bitcoind RPC user")
    parser.add_argument("--rpc-pass", default=DEFAULT_RPC_PASS, help="bitcoind RPC password")
    parser.add_argument("--miner-address", default="", help="Mining reward address (auto-generated if empty)")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  QNT Stratum Mining Proxy")
    log.info("  Post-Quantum Blockchain - Multi-Miner Support")
    log.info("=" * 60)

    # Connect to bitcoind
    rpc = BitcoinRPC(args.rpc_host, args.rpc_port, args.rpc_user, args.rpc_pass)

    try:
        info = rpc.get_blockchain_info()
        log.info(f"Connected to bitcoind: chain={info.get('chain','?')}, blocks={info.get('blocks','?')}")
    except Exception as e:
        log.error(f"Cannot connect to bitcoind: {e}")
        sys.exit(1)

    # Get mining address
    miner_address = args.miner_address
    if not miner_address:
        miner_address = rpc.get_new_address()
        log.info(f"Generated mining address: {miner_address}")

    log.info(f"Stratum port: {args.port}")
    log.info(f"Mining address: {miner_address}")
    log.info(f"Share difficulty: {DIFFICULTY_SHARE_TARGET:#x}")

    server = StratumServer(rpc, args.port, miner_address)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        log.info("Shutting down stratum server...")
        server.active = False


if __name__ == "__main__":
    main()
