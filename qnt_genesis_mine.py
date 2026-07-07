#!/usr/bin/env python3
"""QNT Genesis Block Calculator — Ultra-low difficulty"""

import hashlib
import struct
import time

with open("qnt_genesis_key.txt", "r") as f:
    for line in f:
        if "pubkey (raw, 64-byte):" in line:
            genesis_pubkey_hex = line.split(":")[1].strip()
            break

genesis_pubkey = bytes.fromhex(genesis_pubkey_hex)
nTime = 1749600000
# Ultra-low difficulty: 0x20ffffff (much easier than regtest)
nBits = 0x20ffffff

exponent = (nBits >> 24) & 0xff
coefficient = nBits & 0x007fffff
target = coefficient * (256 ** (exponent - 3))
target_hex = format(target, '064x')
print(f"Target: {target_hex}")

pszTimestamp = b"Quant: First Mineable Post-Quantum Chain 11/Jun/2026"
scriptSig = bytes([1]) + pszTimestamp
genesis_output_script = bytes([64]) + genesis_pubkey + bytes([0xBB])

COIN = 100000000
value = 50 * COIN
tx = struct.pack('<I', 1) + bytes([1]) + bytes(32) + struct.pack('<I', 0)
tx += bytes([len(scriptSig)]) + scriptSig
tx += struct.pack('<I', 0xffffffff) + bytes([1])
tx += struct.pack('<q', value)
tx += bytes([len(genesis_output_script)]) + genesis_output_script
tx += struct.pack('<I', 0)

merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()

version = struct.pack('<I', 1)
prev_hash = bytes(32)
timestamp = struct.pack('<I', nTime)
nbits = struct.pack('<I', nBits)
target_bytes = bytes.fromhex(target_hex)

print(f"Mining genesis block (ultra-low difficulty 0x{nBits:08x})...")
nonce = 0
start = time.time()

while True:
    header = version + prev_hash + merkle_root + timestamp + nbits + struct.pack('<I', nonce)
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    if block_hash[::-1] < target_bytes[::-1]:
        break
    nonce += 1

elapsed = time.time() - start
block_hash_hex = block_hash[::-1].hex()

print(f"\n{'='*60}")
print(f"GENESIS BLOCK FOUND!")
print(f"{'='*60}")
print(f"  Hash:        {block_hash_hex}")
print(f"  Nonce:       {nonce}")
print(f"  Timestamp:   {nTime}")
print(f"  nBits:       0x{nBits:08x}")
print(f"  Merkle root: {merkle_root.hex()}")
print(f"  Mine time:   {elapsed:.1f}s")
print(f"  Hash rate:   {nonce/elapsed:.0f} H/s" if elapsed > 0 else "  Instant!")

with open("qnt_genesis_block.txt", "w") as f:
    f.write("="*60 + "\nQNT Genesis Block Parameters\n" + "="*60 + "\n")
    f.write(f"hashGenesisBlock: {block_hash_hex}\n")
    f.write(f"nTime: {nTime}\n")
    f.write(f"nNonce: {nonce}\n")
    f.write(f"nBits: 0x{nBits:08x}\n")
    f.write(f"hashMerkleRoot: {merkle_root.hex()}\n")
    f.write(f"genesisPubkey: {genesis_pubkey_hex}\n\n")
    f.write("/* For chainparams.cpp */\n")
    f.write(f"consensus.hashGenesisBlock = uint256S(\"{block_hash_hex}\");\n")
    f.write(f"genesis = CreateGenesisBlock({nTime}, {nonce}, 0x{nBits:08x}, 1, 50 * COIN);\n")
    f.write("="*60 + "\n")

print(f"\nSaved to qnt_genesis_block.txt")
