// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLIENTVERSION_H
#define BITCOIN_CLIENTVERSION_H

#include <util/macros.h>

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif //HAVE_CONFIG_H

// Check that required client information is defined
#if !defined(CLIENT_VERSION_MAJOR) || !defined(CLIENT_VERSION_MINOR) || !defined(CLIENT_VERSION_BUILD) || !defined(CLIENT_VERSION_IS_RELEASE) || !defined(COPYRIGHT_YEAR)
#error Client version information missing: version is not defined by bitcoin-config.h or in any other way
#endif

//! Copyright string used in Windows .rc files
#define COPYRIGHT_STR "2009-" STRINGIZE(COPYRIGHT_YEAR) " " COPYRIGHT_HOLDERS_FINAL

/**
 * bitcoind-res.rc includes this file, but it cannot cope with real c++ code.
 * WINDRES_PREPROC is defined to indicate that its pre-processor is running.
 * Anything other than a define should be guarded below.
 */

#if !defined(WINDRES_PREPROC)

#include <string>
#include <vector>

static const int CLIENT_VERSION =
                             10000 * CLIENT_VERSION_MAJOR
                         +     100 * CLIENT_VERSION_MINOR
                         +       1 * CLIENT_VERSION_BUILD;

extern const std::string CLIENT_NAME;


std::string FormatFullVersion();
std::string FormatSubVersion(const std::string& name, int nClientVersion, const std::vector<std::string>& comments);

std::string CopyrightHolders(const std::string& strPrefix);

/** Returns licensing information (for -version) */
std::string LicenseInfo();

// ── SNTI R5: Protocol version constants and governance framework ──────────────
//
// SNTI protocol upgrades are gated by BIP9-style version bits defined in
// consensus/params.h (Consensus::DeploymentPos enum). To add a new protocol
// feature:
//
//   1. Add a new enum value to DeploymentPos (e.g. DEPLOYMENT_SNTI_POUW_V3).
//   2. Add VBDeploymentInfo entry to VersionBitsDeploymentInfo[] in
//      deploymentinfo.cpp (name, gbt_force flag).
//   3. Set nStartTime / nTimeout / min_activation_height in each network's
//      chainparams.cpp block.
//   4. Bump SNTI_PROTOCOL_VERSION below and document the change.
//
// Miner signaling: bits 0-28 in nVersion are available for BIP9 deployment
// signals. Miners signal readiness by setting the bit for each feature they
// support. Once 95% of blocks in a 2016-block window signal, the feature
// locks in after the next difficulty boundary.
//
// SNTI_PROTOCOL_VERSION history:
//   1 — genesis: PoUW v2 (XMSS tree building), sighash_v2 (chain ID replay
//       protection), EMA difficulty, 16 MB block weight (R1 fix).
//
static constexpr int SNTI_PROTOCOL_VERSION = 1;
//
// PLACEHOLDER: DEPLOYMENT_SNTI_POUW_V3 — future PoUW upgrade (not yet deployed)
// When ready, add to Consensus::DeploymentPos:
//   DEPLOYMENT_SNTI_POUW_V3,  // XMSS witness migration + compressed proof format

#endif // WINDRES_PREPROC

#endif // BITCOIN_CLIENTVERSION_H
