#!/bin/bash
# QNT Genesis Block Miner
# Mines a valid genesis block for the given chain
set -e

BITCOIND="./src/bitcoind"
BITCOIN_CLI="./src/bitcoind"

# Function to mine genesis for regtest (instant, low difficulty)
mine_genesis_regtest() {
    echo "=== Mining Regtest Genesis ==="
    $BITCOIND -regtest -daemon -rpcuser=test -rpcpassword=test -rpcport=29332
    sleep 3
    # Regtest genesis is already valid (difficulty 0x207fffff)
    $BITCOIN_CLI -regtest -rpcuser=test -rpcpassword=test getblockchaininfo
    $BITCOIND -regtest -rpcuser=test -rpcpassword=test stop 2>/dev/null || true
    echo "Regtest genesis ready"
}

# For testnet/mainnet, we need to find a valid nonce
# This is a placeholder - real genesis mining requires C code
echo "QNT Genesis Block Miner"
echo "========================"
echo ""
echo "Regtest: Already configured with low difficulty (0x207fffff)"
echo "Testnet: Needs genesis mining (difficulty 0x1d00ffff)"
echo "Mainnet: Needs genesis mining (difficulty 0x1d00ffff)"
echo ""
echo "For testnet/mainnet, run the genesis miner C program:"
echo "  cd /root/quant/bitcoin-quant && gcc -o genesis_miner src/genesis_miner.c -I src -L .libs -lbitcoin_consensus -lbitcoin_crypto_base -lpthread"
