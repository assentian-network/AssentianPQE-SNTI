# QNT Build Fix Strategy
## Problem: Bitcoin Core fork with XMSS modifications won't compile
## Root cause: pubkey.h, key.h were too aggressively modified (removed ECDSA types)
## Solution: Restore originals, re-apply XMSS changes minimally

## Plan:
1. Restore all modified files to original Bitcoin Core versions
2. Re-apply XMSS bridge as ADDITIVE changes (don't remove ECDSA)
3. Fix make_secure_unique issue in key.h
4. Build incrementally

## Key insight: QNT v1 should support BOTH ECDSA and XMSS
- ECDSA for backward compatibility / testing
- XMSS as the new quantum-resistant option
- Script can distinguish by key size (33/65 = ECDSA, 64 = XMSS)
