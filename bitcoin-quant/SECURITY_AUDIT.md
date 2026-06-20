> ⚠️ **Status terkini ada di [`PROJECT_STATUS.md`](./PROJECT_STATUS.md)** — file ini historis/berantakan, jangan dijadikan acuan kondisi terbaru.

# QNT Security Audit Preparation

## Overview
This document prepares the QNT codebase for a formal security audit.
Target audit firms: Trail of Bits, NCC Group, or similar.

## Critical Components to Audit

### 1. XMSS Implementation (HIGH PRIORITY)
**Files**: src/xmss.c, src/xmss_core.c, src/xmss_core_fast.c, src/xmss_hash.c, src/wots.c, src/xmss_commons.c, src/params.c, src/fips202.c

**What to verify:**
- XMSS signature correctness (RFC 8391 compliance)
- State management (leaf index tracking, no key reuse)
- Memory handling (secure key clearing, no leaks)
- Parameter validation (OID, tree height, hash function)
- WOTS+ chain computation
- Merkle tree construction

**Known concerns:**
- XMSS is stateful — key reuse breaks security
- 1024 signatures per key pair (2^10)
- Key serialization/deserialization correctness

### 2. XMSS Bridge (HIGH PRIORITY)
**Files**: src/xmss_bridge.cpp, src/xmss_bridge.h

**What to verify:**
- C/C++ boundary correctness
- Memory management (no leaks, no double-free)
- Secure memory clearing (SecureClear function)
- Exception safety
- Move semantics correctness

### 3. Script/Interpreter (HIGH PRIORITY)
**Files**: src/script/interpreter.cpp, src/script/script.cpp, src/script/script.h

**What to verify:**
- OP_XMSS_CHECKSIG/VERIFY correctness
- Stack handling (pop/push balance)
- Sigop counting
- Interaction with existing opcodes (no unintended side effects)
- Signature hash computation for XMSS

### 4. Wallet Key Store (MEDIUM PRIORITY)
**Files**: src/wallet/xmss_keystore.cpp, src/wallet/xmss_keystore.h

**What to verify:**
- Key generation randomness
- Leaf index persistence (critical for stateful XMSS)
- Thread safety (mutex usage)
- Import/export correctness

### 5. PoUW Consensus (MEDIUM PRIORITY)
**Files**: src/pouw.h

**What to verify:**
- Block signature verification
- Difficulty adjustment interaction
- Work score calculation

### 6. Chain Parameters (LOW PRIORITY)
**Files**: src/kernel/chainparams.cpp

**What to verify:**
- Magic bytes uniqueness (no collision with existing chains)
- Port numbers (no conflict)
- Address prefix uniqueness
- Genesis block validity

## Audit Deliverables Requested
1. Formal verification of XMSS signature/verify
2. Memory safety analysis (ASan, MSan, Valgrind)
3. Fuzz testing of script interpreter
4. Consensus bug review
5. Key management review
6. Written report with severity ratings

## Pre-Audit Checklist
- [ ] All unit tests pass
- [ ] Fuzz targets defined for script interpreter
- [ ] Memory safety tests (ASan build)
- [ ] Documentation of all consensus-critical code
- [ ] Threat model document
- [ ] List of all external dependencies and their versions
