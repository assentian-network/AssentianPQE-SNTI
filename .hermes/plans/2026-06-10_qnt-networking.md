# QNT Networking & Full Node Plan
## Date: 2026-06-10
## Status: Phase 1-2 COMPLETE, Phase 3+ In Progress

## Phase 1: Build & Run Regtest Node ✅ COMPLETE
- bitcoind 274MB ELF binary compiled successfully
- bitcoin-cli compiled
- Regtest node running, genesis block created
- Block generation working (generatetoaddress)
- Address prefix: qnr (regtest), qn (testnet), Q (mainnet)

## Phase 2: Multi-Node P2P ✅ COMPLETE
- 2 nodes connected via P2P (port 29333, 29334)
- Block propagation verified (Node 1 mines → Node 2 syncs)
- Transaction broadcast verified (TXID: 00870a52...)
- Balance transfer: Node 1 → Node 2 (1.0 QNT, fee 0.000141)
- Confirmation after block mine: 1 confirmation

## Phase 3: Wallet + XMSS Integration (IN PROGRESS)
- Need to integrate XMSS key generation into wallet
- Need XMSS signing for transactions
- Need XMSS address format

## Phase 4: Block Explorer (PENDING)
## Phase 5: Testnet Launch (PENDING)
## Phase 6: Mining Pool (PENDING)

## Key Build Issues Resolved
1. src/hash.h was deleted — restored from git
2. src/key.h was overly modified (removed ECDSA) — restored original
3. src/pubkey.h was overly modified (removed XOnlyPubKey) — restored original
4. src/script/interpreter.cpp had orphan code — restored original
5. make_secure_unique with vector — fixed in key.h

## Key Decision: Additive XMSS Integration
- Keep Bitcoin Core ECDSA intact
- Add XMSS as parallel signing option
- Script can distinguish by key size
- This avoids breaking Bitcoin Core consensus code
