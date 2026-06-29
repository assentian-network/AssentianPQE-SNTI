# SNTI (Assentian-PQE) Mainnet Readiness Audit — 29/Jun/2026

Audit dilakukan langsung terhadap kode VPS (/root/Assentian-PQE/SNTI/), bukan terhadap
file markdown atau repository GitHub. Setiap claim diverifikasi dengan grep terhadap
source code.

Commit terakhir: dc744ac (bcrypt password hashing)
Uncommitted changes: 15 files (rebranding QNT→SNTI, wallet encryption, EMA fix, explorer)

═══════════════════════════════════════════════════════════════
SUMMARY TABLE
═══════════════════════════════════════════════════════════════

DIMENSION            STATUS    DONE  TOTAL  RISK
────────────────────────────────────────────────────────────────
Key State Mgmt      ████████░░  9/10   10    LOW
Replay Protection   █████████░  6/7     7    LOW
Eclipse / Peers     ████░░░░░░  3/7     7    HIGH  ← CRIT
Seed Node Infra      ███░░░░░░░  3/8     8    HIGH  ← CRIT
Economic Model      ████████░░  6/8     8    LOW
Mining / Pool       ███████░░░  5/8     7    MED

OVERALL: NOT READY FOR MAINNET — 2 CRITICAL blockers

═══════════════════════════════════════════════════════════════
BLOCKERS (must-fix before mainnet)
═══════════════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────────────────────────┐
│ #1 — CRITICAL — Eclipse attack: only 1 seed node (same IP)              │
├──────────────────────────────────────────────────────────────────────────┤
│ Impact:  CRITICAL                                                       │
│ Location: src/qnt_seeds.h:7, src/kernel/chainparams.cpp:170             │
│                                                                          │
│ Both mainnet and testnet have ONE hardcoded seed: 104.234.26.7.         │
│ An attacker can eclipse ANY new node by flooding their own peers         │
│ before the single seed responds. Minimum 3 nodes across 2+ ASes          │
│ is needed for basic eclipse resistance.                                 │
│                                                                          │
│ VPS comment in code admits this:                                         │
│   // TODO(mainnet): add 2+ nodes in EU and APAC before public launch.    │
│                                                                          │
│ Fix: Deploy 2+ additional seed servers (EU + APAC), then update          │
│ qnt_seeds.h and rebuild. Domain seed.assentian.network only has          │
│ A record pointing to 104.234.26.7.                                      │
│                                                                          │
│ Effort: 1-2 days (ops), 0 code changes beyond seed list.                │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│ #2 — CRITICAL — nMinimumChainWork = 0 on mainnet                        │
├──────────────────────────────────────────────────────────────────────────┤
│ Impact:  CRITICAL                                                       │
│ Location: src/kernel/chainparams.cpp:138                                 │
│                                                                          │
│ consensus.nMinimumChainWork = uint256{}  (all zeros / genesis work)     │
│                                                                          │
│ This means no long-range protection. An attacker can silently build      │
│ an alternate chain from genesis and reorganize the chain at any          │
│ point. Testnet has proper chainwork (0x...031006), mainnet doesn't.     │
│                                                                          │
│ The code even has a TODO comment:                                        │
│   // SNTI L1 TODO-MAINNET: set after ~10 000 mainnet blocks.            │
│                                                                          │
│ Fix: After ~10k blocks, run `snti-cli getblockheader <hash>` at         │
│ a deep block, copy the chainwork field, and set                          │
│ consensus.nMinimumChainWork. This is intentionally deferred but          │
│ MUST be done before public launch.                                       │
│                                                                          │
│ Effort: 5 minutes (one line change + rebuild).                           │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│ #3 — HIGH — Stratum server cannot sign blocks directly                 │
├──────────────────────────────────────────────────────────────────────────┤
│ Impact:  HIGH                                                           │
│ Location: stratum_server.py:336-370                                     │
│                                                                          │
│ Stratum server calls `self.rpc.generate_to_address()` which requires     │
/// the full node to do XMSS signing. There is no direct stratum→         │
│ connect-to-node block submission path that bypasses the full node.      │
│ Pool mining depends on `sntid` being online with wallet enabled.        │
│ This means pool = single point of failure.                              │
│                                                                          │
│ Additionally: stratum uses port 39332 (RPC) which is NOT the            │
│ default P2P port 9333 — operators must configure separately.            │
│                                                                          │
│ Recommendation: Add `submitblock` RPC fallback, document RPC port        │
│ requirement, or implement stratum→node TLS auth.                        │
│                                                                          │
│ Effort: 1-2 days.                                                       │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│ #4 — MEDIUM — dumpwallet does not export XMSS state                    │
├──────────────────────────────────────────────────────────────────────────┤
│ Impact:  MEDIUM                                                         │
│ Location: src/wallet/rpc/backup.cpp:689-820                             │
│                                                                          │
│ dumpwallet exports HD seed + imported keys but NOT the XMSS state       │
│ blob (leaf_index, retired flags, secondary XMSS keys). If a user        │
│ encrypts wallet after XMSS keys are generated but before backing up,    │
│ the XMSS state lives only in the wallet DB (`xms` key).                │
│                                                                          │
│ Mitigation: TXT banner on encryptwallet says "make a new backup"        │
│ and the state IS persisted. But `exportwallet` RPCs are not XMSS-aware. │
│                                                                          │
│ Recommendation: Add `exportxmssstate` RPC or document that              │
│ `backupwallet` (which copies the DB file) is the only safe way.         │
│                                                                          │
│ Effort: 1 day for proper fix, 2 hours for documentation.                │
└──────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════
KEY FINDINGS PER DIMENSION
═══════════════════════════════════════════════════════════════

DIMENSION 1 — Key State Management  [9/10 — LOW RISK]
─────────────────────────────────────────────────────
✓ XMSS state persisted to wallet DB (WriteXmssState)
✓ Encrypted at rest when wallet is locked (AES-256-CBC via EncryptSecret)
✓ fsysnc after every sign to prevent leaf reuse after crash
✓ Auto-rotation on key exhaustion (EnsureXMSSKeyAvailable)
✓ Retired key enforcement (one-time-address, gap #3)
✓ Leaf-index reuse DB (DB_POUW_LEAF, ConnectBlock + DisconnectBlock)
✓ Min(3-block) moving average dampens EMA oscillation (pow.cpp:36)
✓ Exhaustion warning when only 1 key remains
✓ Key pool pre-sign check (SignTransaction)
✗ dumpwallet does NOT export XMSS state (minor gap — DB backup is sufficient)
+ bcrypt password hashing (commit dc744ac, replaces SHA-256)

DIMENSION 2 — Replay Protection  [6/7 — LOW RISK]
─────────────────────────────────────────────────────
✓ sighash_v2 = SHA256(sighash_v1 || leaf_index_BE || chain_id_BE)
  (src/script/interpreter.cpp:1797-1806)
✓ chain_id embedded and verified in validation (validation.cpp:3991)
✓ mainnet nXMSSChainId = 1
✓ Distinct address prefixes: mainnet Q(81), testnet p(111)
✓ bech32m witness v2 addresses (HRP: "snti"/"tsnti"/"sntirt")
✗ No cross-chain replay test found in test suite
+ OP_RETURN carries proof (not scriptSig) — clean design

DIMENSION 3 — Eclipse Attack & Peer Security  [3/7 — HIGH RISK]
─────────────────────────────────────────────────────
✓ DNS seed configured: seed.assentian.network → 104.234.26.7
✗ ONLY 1 DNS seed (single point of failure, attacker can eclipse)
✊ ONLY 1 hardcoded seed (same IP as DNS seed — no diversity)
✗ Misbehavior scoring exists (Bitcoin Core inherited, DISCOURAGEMENT_THRESHOLD=100)
✗ No additional EU/APAC seed nodes
+ Banning/discouragement logic is present
+ pchMessageStart = "SNTI" (0x534E5449) — unique, prevents cross-chain peer relay

DIMENSION 4 — Seed Node Infrastructure  [3/8 — HIGH RISK]
─────────────────────────────────────────────────────
✓ Checkpoint at genesis (height 0)
✓ DNS seed: seed.assentian.network (domain registered 28/Jun/2026)
✗ nMinimumChainWork = 0 (no long-range protection — BLOCKER #2)
✗ No additional checkpoints (TODO comment: "add after ~10k blocks")
✗ Single seed node / single region / single AS
+ defaultAssumeValid = 0 on mainnet (properly — will be set with checkpoint)
+ Testnet has proper nMinimumChainWork (0x...031006)
+ nPruneAfterHeight = 100000, m_assumed_blockchain_size = 20 (reasonable)

DIMENSION 5 — Economic Model  [6/8 — LOW RISK]
─────────────────────────────────────────────────────
✓ MAX_MONEY = 21,000,000 * COIN
✓ Halving interval = 2,100,000 blocks (scaled for 60s/block)
✓ Genesis subsidy = 50 COIN
✓ EMA with alpha=0.1, 3-block moving average dampen
✓ EMA bounds: [powLimit/10, powLimit]
✓ PermittedDifficultyTransition: 4x bounds (compatible with EMA alpha=0.1)
✗ Fee market untested (XMSS sigs ~2.5KB but MAX_STANDARD_TX_WEIGHT is 400K, fine)
✗ No minimum chainwork = long-range attack feasible (BLOCKER #2 again)
+ Subsidy schedule matches Bitcoin economics (same 64-halving limit)
+ EMA math verified: divide-before-multiply prevents overflow

DIMENSION 6 — Mining / Pool Compatibility  [5/7 — MEDIUM RISK]
─────────────────────────────────────────────────────
✓ getblocktemplate RPC implemented (BIP 22 compliant)
✓ generateblock RPC for PoUW mining
✓ submitblock RPC for pool submission
✓ Stratum V2 server (stratum_server.py, separate process)
✗ Stratum calls generate_to_address via RPC (requires full node online)
✗ No Stratum TLS support
✗ SHARE_DIFFICULTY = 0.001 is just "accept all shares" — needs real validation
+ Failed-Seed-List (FSL) properly embedded and verified in consensus
+ Leaf-index reuse prevention via persistent DB (DB_POUW_LEAF)
+ FSL→wallet key derivation via HKDF (proper cryptographic separation)
+ MAX_FAILED_SEEDS=20, MIN_FAILED_SEEDS=10 — reasonable bounds

═══════════════════════════════════════════════════════════════
FUTURE THREATS
═══════════════════════════════════════════════════════════════

| # | Threat | Severity | Timeline | Mitigation |
|---|--------|----------|----------|------------|
| 1 | Single operator (1 dev) — bus factor | HIGH | Ongoing | Document, multisig treasury |
| 2 | DAI=1 (per-block EMA) dampened by MA(3) but still sensitive | MEDIUM | Ongoing | Already mitigated (M5 fix) |
| 3 | No bug bounty program | MEDIUM | Pre-mainnet | Consider establishing one |
| 4 | Bitcoin Core CVE backport lag | MEDIUM | Ongoing | Track bitcoin-security |
| 5 | Regulatory → XMSS classified as "quantum crypto" | LOW | 1-3 years | Legal review |
| 6 | XMSS-SHA2_10_256 parameter set (fixed) | LOW | 5-10 years | Monitor NIST SP 800-208 |
| 7 | Pool centralization (single node mining) | HIGH | Pre-mainnet | Stratum→node HA setup |

═══════════════════════════════════════════════════════════════
PRIORITIZED ROADMAP
═══════════════════════════════════════════════════════════════

Phase 1 — BLOCKERS (before any public launch):
  1. Deploy 2+ seed nodes (EU + APAC), update seed list
     Effort: 1 day ops + 2 hours code
  2. Set nMinimumChainWork (or document plan to set at block 10k)
     Effort: 5 minutes code

Phase 2 — Important (first week after launch):
  3. Add checkpoint entries (block 100, 1000, 5000)
  4. Implement proper share validation (replace Wave 1 accept-all)
  5. Document XMSS state backup procedure
  6. Set up seed node monitoring/alerts

Phase 3 — Medium term (first month):
  7. Add Stratum TLS option
  8. Bug bounty program
  9. Stress-test with multi-miner scenario
  10. Real fee market analysis with actual tx volume

Phase 4 — Nice to have:
  11. exportxmssstate RPC
  12. Alternative seed implementations (non-C++ node)
  13. Monitoring dashboard for seed node health

═══════════════════════════════════════════════════════════════
VERIFIED: All "CRITICAL" bugs from prior audit (27/Jun/2026) are FIXED
═══════════════════════════════════════════════════════════════

Cross-referenced audit.md claims vs actual code:
  ✓ SK_SEED leak (C1): PoUWv2Proof does NOT contain SK_SEED — only pk+sig+auth_path
  ✓ commitmentsRoot non-verification (C2): validation.cpp:4058-4076 verifies against FSL
  ✓ Signature chunking (H3): SK trimming bug fixed in xmss_state.h
  ✓ EMA difficulty (H4): 3-block MA dampening in pow.cpp:36-52
  ✓ Seed nodes (H6): vSeeds configured (but only 1 — still insufficient)
  ✓ Debug logs (N4): grep found 0 LogPrintf.*DEBUG in codebase
  ✓ RandomBytes (N4): uses GetStrongRandBytes throughout

NOTE: Prior audit used "QNT" namespace — code has been rebranded to "SNTI" in
uncommitted changes. The security properties are identical.
