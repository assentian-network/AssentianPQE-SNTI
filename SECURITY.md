
# Security Policy — Assentian-PQE (SNTI)

## Scope

This security policy covers the Assentian-PQE-specific code additions:
- XMSS wallet integration (`src/wallet/xmss_*.h/cpp`)
- PoUW consensus (`src/validation.cpp` — `CheckPoUW()`)
- P2XMSS / P2XMSSHASH script types (`src/script/interpreter.cpp`, `src/script/sign.cpp`)
- XMSS RPC commands (`src/wallet/rpc/xmss.cpp`)
- XMSS bridge (`src/xmss_bridge.h/cpp`)

Bitcoin Core upstream code (unmodified) is out of scope — report those
to https://bitcoincore.org/en/contact/.

## Severity Classification

| Severity | Examples | Response Target |
|---|---|---|
| **Critical** | Fund theft, private key extraction, consensus split | 24 hours |
| **High** | Denial of service, signature bypass, wallet corruption | 72 hours |
| **Medium** | Edge case bugs, non-exploitable logic errors | 7 days |
| **Low** | Best-practice improvements, cosmetic issues | 30 days |

## How to Report

**DO NOT open a public GitHub issue for security vulnerabilities.**

Report privately via email. Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. (Optional) Suggested fix

**Contact:** admin@assentian.network **.**

PGP encryption available on request.

## Bug Bounty

We currently do not have a formal bug bounty program. For Critical and
High severity findings that lead to a confirmed fix, we will acknowledge
you publicly (with your permission) in the changelog and project credits.

A formal bug bounty program via Immunefi is planned before mainnet launch.

## Known Limitations (Not Bugs)

The following are known design decisions, documented here to avoid
duplicate reports:

- **XMSS one-time address**: Each XMSS address is intentionally retired
  after one use. This is by design, not a bug.
- **Mainnet genesis not yet mined at production difficulty**: Testnet only.
- **No external security audit yet**: Self-audit completed (see `AUDIT.md`).
  External audit planned before mainnet.

## Disclosure Policy

We follow responsible disclosure: reporters are asked to give us reasonable
time to fix and release a patch before public disclosure. We will coordinate
timing with reporters and credit them in release notes.
