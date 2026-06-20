> ⚠️ **Status terkini ada di [`PROJECT_STATUS.md`](./PROJECT_STATUS.md)** — file ini historis/berantakan, jangan dijadikan acuan kondisi terbaru.

# QNT Testnet Launch Checklist

## Pre-Launch (Code)
- [x] XMSS opcode implementation (OP_XMSS_CHECKSIG/VERIFY)
- [x] Wallet XMSS key store
- [x] Block explorer (Flask + HTML)
- [x] Build system working (all binaries compile)
- [ ] Genesis block mining (find valid nonce for testnet)
- [ ] Real XMSS keypair for genesis block (replace placeholder a1b2c3d4...)
- [ ] P2XMSS script type (Pay-to-XMSS-PubKey-Hash)
- [ ] Address encoding for XMSS public keys

## Genesis Block Mining
The testnet genesis block needs a valid nonce for difficulty target 0x1d00ffff.
This requires a genesis miner program that:
1. Constructs the genesis block with current timestamp
2. Iterates nonce values until SHA256(block_header) < target
3. Outputs the valid nonce and block hash

Estimated time: ~minutes on modern CPU (same as Bitcoin genesis difficulty)

## Network Infrastructure
- [ ] Deploy minimum 3 seed nodes (VPS in different regions)
- [ ] Configure DNS seeds (seed.qnt-testnet.org, etc.)
- [ ] Set up block explorer web server
- [ ] Configure mining pool software (if applicable)
- [ ] Set up monitoring/alerting

## Testnet Launch Sequence
1. Mine genesis block → get nonce + hash
2. Update chainparams.cpp with real genesis nonce/hash
3. Rebuild binaries
4. Deploy seed nodes with `-testnet` flag
5. Verify P2P connectivity between nodes
6. Mine first blocks, verify chain sync
7. Test wallet operations (create XMSS key, send/receive)
8. Launch block explorer
9. Publish testnet documentation + miner guide

## Post-Launch Monitoring
- Block time stability (target: 60s)
- Difficulty adjustment
- XMSS signature verification on all blocks
- Wallet sync correctness
- Explorer accuracy
