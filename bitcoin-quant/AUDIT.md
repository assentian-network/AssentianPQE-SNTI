> ⚠️ **Status terkini ada di [`PROJECT_STATUS.md`](./PROJECT_STATUS.md)** — file ini historis/berantakan, jangan dijadikan acuan kondisi terbaru.

# QNT Security Audit Report — Phase 4 Self-Audit
**Date:** June 13, 2026  
**Auditor:** OWL (automated self-audit)  
**Scope:** XMSS integration, script engine, wallet keystore, transaction signing  
**Severity Levels:** CRITICAL | HIGH | MEDIUM | LOW | INFO

---

## Executive Summary

Self-audit dilakukan terhadap semua code XMSS yang diimplementasi di QNT blockchain. Fokus pada: key generation, state persistence, signing flow, script engine, wallet keystore, dan transaction validation.

**Overall Assessment:** ✅ **LULUS dengan catatan**  
Code XMSS secara umum solid. Ada beberapa issue MEDIUM yang perlu diperhatikan tapi tidak blocking untuk regtest/testing.

---

## 1. XMSS KEY GENERATION

### ✅ PASS: Randomness Source
- `CXMSSKey::Generate()` memanggil `xmss_keypair()` dari XMSS library
- XMSS library menggunakan `xmss_core_fast.c` yang pakai parametrik key generation
- Seed untuk key generation berasal dari XMSS library internal (OpenSSL RNG)
- **Verdict:** Aman — tidak ada hardcoded seed

### ✅ PASS: Zeroing on Failure
- `Clear()` dipanggil di semua error paths di `Generate()`
- `SecureClear()` menggunakan volatile pointer untuk prevent compiler optimization
- **Verdict:** Aman

### 📝 NOTE: Key Parameter Validation
- `xmss_parse_oid()` dipanggil sebelum key generation
- Jika OID invalid, generate gagal dengan benar
- Recommendation: Tambah logging saat key generation gagal

---

## 2. KEY STATE PERSISTENCE

### ✅ PASS: Serialize Format
- `CXMSSSigner::SaveState()`: Format [count][pubkey_size][pubkey][index][sk_size][sk]
- `CXMSSSigner::LoadState()`: Parse dan reconstruct dengan validasi bounds checking
- `WalletBatch::WriteXmssState()`: Menulis ke DB dengan key "xms"
- **Verdict:** Aman — bounds checking benar

### ✅ PASS: Anti-Reuse Protection
- Leaf index di-track per key
- `HasExhaustedKeys()` cek apakah index >= 1024
- State di-load saat wallet open, di-save setelah commit
- **Verdict:** Aman — key reuse harusnya impossible dengan implementasi ini

### 📝 NOTE: No Encryption at Rest
- XMSS secret keys disimpan di wallet DB sebagai plaintext (via `WriteXmssState`)
- Wallet DB sendiri bisa di-encrypt (BDB encryption) tapi XMSS state tidak double-encrypt
- Risika: Jika wallet DB file diakses langsung, XMSS private key bisa diekstrak
- **Severity:** MEDIUM
- **Recommendation:** Consider encrypting XMSS state blob sebelum write ke DB, atau rely on OS-level encryption (LUKS/dm-crypt)

---

## 3. SIGNING FLOW

### ✅ PASS: Index Advancement
- `Sign()` di `CXMSSKey` memanggil `xmss_sign()` yang advance index internally
- `Sign()` mengupdate `m_sk` dengan `sk_copy` (mutable copy) — correct pattern
- `SignXMSS()` di `CXMSSSigner` increment `leaf_index` terpisah sebagai tracking
- **Verdict:** Aman — dual tracking (internal XMSS + external leaf_index)

### ✅ PASS: Thread Safety
- `CXMSSSigner` pakai `RecursiveMutex cs_xmss_signer` dengan `LOCK()` macro
- Semua akses ke `xmss_keys` map di-lock
- **Verdict:** Aman untuk concurrent access

### ⚠️ ISSUE: No Sign Count Limit Check Before Sign
- `CXMSSSigner::Sign()` tidak cek remaining signatures SEBELUM signing
- `HasExhaustedKeys()` ada tapi tidak dipanggil otomatis sebelum sign
- `xmss_sign()` tetap akan gagal jika index exhausted (return error)
- Tapi error handling-nya return false tanpa explicit "key exhausted" message
- **Severity:** LOW
- **Recommendation:** Tambah explicit check di awal `Sign()`: if index >= 1024, return false dengan log "XMSS key exhausted"

---

## 4. SCRIPT ENGINE (OP_XMSS_CHECKSIG)

### ✅ PASS: Opcode Definition
- `OP_XMSS_CHECKSIG = 0xBB`, `OP_XMSS_CHECKSIGVERIFY = 0xBC`
- Tidak konflik dengan existing Bitcoin opcodes
- **`VERDICT:** Aman

### ✅ PASS: Stack Validation
- Interceptor cek `stack.size() < 2` sebelum pop
- Pubkey size validation: harus 64 bytes
- **Verdict:** Aman — no stack underflow/overflow

### ✅ PASS: SigOp Count
- `CScript::GetSigOpCount()` include XMSS opcodes in count
- Subject to MAX_BLOCK_SIGOPS_COST limit
- **Verdict:** Aman

### ⚠️ ISSUE: Signature Malleability
- XMSS signatures theoretically non-malleable (different from ECDSA)
- Tapi validator tidak verify bahwa signature minimal length
- Very short signatures (< 100 bytes) bisa pass stack validation tapi gagal di `CheckXMSSSignature()`
- **Severity:** LOW
- **Recommendation:** Tambah minimum signature length check di interpreter (e.g., sig.size() > 100)

---

## 5. WALLET KEYSTORE

### ✅ PASS: Thread Safety
- `CXMSSSigner` pakai `RecursiveMutex`
- `CXMSSKeyStore` pakai mutex internal
- **Verdict:** Aman

### 📝 NOTE: No Keystore Encryption Check
- `CXMSSKeyStore` menyimpan keys di memory sebagai plaintext
- Tidak ada encrypt/decrypt wrapper
- Untuk regtest ini acceptable
- **Severity:** MEDIUM
- **Recommendation:** Untuk mainnet, consider in-memory encryption (memcpy to/from encrypted buffer)

---

## 6. TRANSACTION VALIDATION

### ✅ PASS: Replay Protection
- XMSS signatures include sighash (SIGHASH_ALL)
- Sighash computation sama dengan Bitcoin standard
- **Verdict:** Aman — transaction replay harusnya impossible

### ⚠️ ISSUE: Sighash XMSS Tidak Include Key Index
- Standard XMSS best practice: sighash harus include key index untuk prevent cross-index recombination attack
- Current implementation: sighash = Hash(tx data saja), tidak include leaf_index
- Risiko: Teoretis — jika ada bug di index tracking, signature dari index N bisa valid untuk index M
- **Severity:** MEDIUM
- **Recommendation:** Include leaf_index dalam sighash computation untuk XMSS v2

---

## 7. PoUW MINING

### ✅ PASS: Per-Block Key Generation
- Mining generate fresh XMSS key per block — tidak reuse
- **Verdict:** Aman

### ⚠️ ISSUE: No Verification That Signed Block Matches Template
- `GenerateBlock()` insert signature ke coinbase scriptSig
- PoW re-verification dilakukan setelah sig insertion
- Tapi tidak ada verify bahwa signature benar-benar valid untuk block hash final
- `CheckPoW` di validation.cpp akan verify, tapi di mining flow sendiri tidak
- **Severity:** LOW
- **Recommendation:** Tambah explicit verify di mining flow setelah signature insertion (optional, for debugging)

---

## FINDINGS SUMMARY

| # | Severity | Area | Issue |
|---|----------|------|-------|
| 1 | MEDIUM | Persistence | XMSS state tidak di-encrypt sebelum write ke DB |
| 2 | MEDIUM | Signing | Sighash tidak include leaf_index (cross-index attack) |
| 3 | LOW | Signing | Tidak ada explicit "key exhausted" check sebelum sign |
| 4 | LOW | Script | Tidak ada minimum signature length validation |
| 5 | LOW | Mining | Tidak ada explicit signature verify di mining flow |

---

## RECOMMENDATIONS (Priority Order)

1. **[MEDIUM] Encrypt XMSS state** — Encrypt state blob sebelum write ke wallet DB
2. **[MEDIUM] Include leaf_index in sighash** — Untuk XMSS v2
3. **[LOW] Add key exhausted check** — Explicit check di awal `Sign()`
4. **[LOW] Add minimum sig length** — Check di interpreter sebelum verify
5. **[LOW] Add mining verify** — Optional signature verify di mining flow

---

## CONCLUSION

QNT XMSS implementation secara umum **solid dan aman** untuk tahap development/regtest. Tidak ada CRITICAL atau HIGH severity issues yang ditemukan. 2 MEDIUM issues (encryption at rest dan sighash composition) perlu di-address sebelum mainnet launch. 3 LOW issues bisa di-fix sebagai improvement.

**Status:** ✅ **PASS** — Ready untuk Phase 4.2 (Bug Bounty Prep) atau langsung Phase 5.
