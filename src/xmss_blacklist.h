// Copyright (c) 2026 The Assentian-PQE developers
// SNTI: Permanent blacklist for XMSS trees with known-divergent leaf history.
//
// Before the unified ledger (xmss_tree_ledger.h) existed, mining and wallet
// spend-signing tracked leaf usage independently. Two SG mining trees were
// found, on manual audit (1 Jul 2026), to have had a wallet-side spend
// signing attempt after the miner had already used leaves from the same
// tree -- the wallet's copy could not prove which leaves were actually safe
// to reuse, so their true leaf history is unrecoverable. Rather than guess,
// these trees are burned permanently: never sign with them again, in any
// code path, for any reason. Funds already sent to these addresses are
// intentionally abandoned (accepted by the project owner, 1 Jul 2026).
//
// NOTE ON BYTE ORDER: entries below are the tree root in the SAME forward
// byte order as the 64-byte XMSS pubkey (root(32)||PUB_SEED(32)) shown by
// RPCs like listxmsskeys/getxmssaddressinfo (plain HexStr, not reversed).
// This is deliberately compared against uint256::data() (also forward
// order), NOT uint256::GetHex() (which reverses bytes for display) -- do
// not "fix" an apparent mismatch by swapping to GetHex() comparison.

#ifndef ASSENTIAN_XMSS_BLACKLIST_H
#define ASSENTIAN_XMSS_BLACKLIST_H

#include <uint256.h>
#include <util/strencodings.h>

#include <array>
#include <algorithm>

namespace PoUWv2 {

inline const std::array<const char*, 3> XMSS_BLACKLISTED_ROOTS_HEX = {
    // snti1zcaf64wa0tvsmeh6ew86q7jxrrd63q2au885rkg (SG, 67 mined blocks,
    // wallet SignXMSS retired it after 1 stale-key spend attempt 1 Jul 2026)
    "acb5d0c24eb38273f963955cb84469c17829e58fcbd59b0d685b2e439a26daf8",
    // snti1zwl2l59szgna4k4tyljs29923x64zceu3skkptg (SG, 44 mined blocks
    // during 30 Jun burst-mining event; miner state file was reset/rotated
    // afterwards so its true leaf progress can no longer be verified)
    "7bd2526260a2e8121ba93a0bd3088f4af631e69c330b467b318af8f544fb0964",
    // snti1zglkz7qluv98x6wxhkua8naq5s8j32ftg8c3xzn (KC/Seed-US, 1119+ mined
    // blocks). Discovered 1 Jul 2026 during deploy: this tree had already
    // rotated away from being the miner's "active" tree (xmss_miner_state.dat
    // now points at a different root) before the unified ledger existed to
    // adopt it via XMSSTreeLedgerSeedFromActive(). No wallet-side spend was
    // ever attempted on it (0 retired keys found on audit), so nothing is
    // known to be compromised yet -- but its true current leaf position is
    // unverifiable, so it is burned pre-emptively rather than risked.
    "f31f80e1428951e88a2562fe4dc7134e835c0cd2b10b1f5f3c7eb8f258a40a1f",
};

inline bool IsXMSSTreeBlacklisted(const uint256& root)
{
    for (const char* hex : XMSS_BLACKLISTED_ROOTS_HEX) {
        std::vector<unsigned char> raw = ParseHex(hex);
        if (raw.size() == 32 && std::equal(raw.begin(), raw.end(), root.data())) {
            return true;
        }
    }
    return false;
}

} // namespace PoUWv2

#endif // ASSENTIAN_XMSS_BLACKLIST_H
