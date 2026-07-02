// Copyright (c) 2025 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#include <chainparams.h>
#endif

#include <wallet/rpc/xmss.h>

#include <addresstype.h>
#include <core_io.h>
#include <key_io.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/translation.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>
#include <wallet/xmss_address.h>
#include <wallet/xmss_signer.h>

#include <util/moneystr.h>
#include <interfaces/chain.h>
#include <wallet/receive.h>
#include <string>

namespace wallet {

// ---------------------------------------------------------------------------
// getnewxmssaddress
// ---------------------------------------------------------------------------
RPCHelpMan getnewxmssaddress()
{
    return RPCHelpMan{"getnewxmssaddress",
        "\nGenerates a new XMSS (post-quantum) key pair and returns the address.\n"
        "The key is stored in the wallet's XMSS keystore.\n"
        "XMSS keys are stateful — each signature consumes one leaf (1024 total).\n",
        {
            {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Label for the address."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "",
            "Information about the new XMSS address",
            {
                {RPCResult::Type::STR, "address", "The XMSS address (Base58Check encoded)"},
                {RPCResult::Type::STR_HEX, "pubkey", "The 64-byte XMSS public key (hex)"},
                {RPCResult::Type::NUM, "leaf_index", "Current leaf index (0 for new key)"},
                {RPCResult::Type::NUM, "remaining", "Remaining signatures (1024 for new key)"},
            },
        },
        RPCExamples{
            HelpExampleCli("getnewxmssaddress", "")
            + HelpExampleCli("getnewxmssaddress", "\"my_xmss_wallet\"")
            + HelpExampleRpc("getnewxmssaddress", "\"my_xmss_wallet\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        LOCK(pwallet->cs_wallet);

        if (!pwallet->CanGetAddresses()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
        }

        const std::string label{LabelFromValue(request.params[0])};

        auto* signer = pwallet->GetXMSSSigner();
        if (!signer) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: XMSS signer not initialized");
        }

        std::vector<uint8_t> pubkey = signer->GenerateKey(label);
        if (pubkey.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: XMSS key generation failed");
        }

        // Register this key with the ScriptPubKeyMan-level XMSS key map so
        // IsMine() recognizes funds sent here as spendable. We use the key
        // already generated above (do NOT call keystore->GenerateKey() which
        // would create a second, unrelated keypair — audit fix #6).
        uint160 new_addr_hash = XMSSAddr::Hash(pubkey);
        pwallet->AddXMSSKeyToKeystore(new_addr_hash, pubkey);
        // SNTI FIX (18/Jun/2026): persist immediately so the private key
        // survives a node crash or restart before any spending occurs.
        pwallet->PersistXMSSState();
        std::string addr = XMSSAddr::Encode(pubkey, Params().Bech32HRP());

        UniValue result(UniValue::VOBJ);
        result.pushKV("address", addr);
        result.pushKV("pubkey", HexStr(pubkey));
        result.pushKV("leaf_index", 0);
        result.pushKV("remaining", 1024);

        return result;
    },
    };
}

// ---------------------------------------------------------------------------
// listxmsskeys
// ---------------------------------------------------------------------------
RPCHelpMan listxmsskeys()
{
    return RPCHelpMan{"listxmsskeys",
        "\nLists all XMSS keys in the wallet with their status.\n"
        "Shows leaf index, remaining signatures, and address for each key.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "",
            "Array of XMSS key entries",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "XMSS address"},
                        {RPCResult::Type::STR_HEX, "pubkey", "64-byte public key (hex)"},
                        {RPCResult::Type::NUM, "leaf_index", "Current leaf index (signatures used)"},
                        {RPCResult::Type::NUM, "remaining", "Remaining signatures (1024 max per key)"},
                        {RPCResult::Type::BOOL, "retired", "True if key is one-time-spent (cannot sign again)"},
                        {RPCResult::Type::STR, "warning", "Non-empty when key is spent or near exhaustion"},
                        {RPCResult::Type::STR, "label", "Key label"},
                    },
                },
            },
        },
        RPCExamples{
            HelpExampleCli("listxmsskeys", "")
            + HelpExampleRpc("listxmsskeys", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        LOCK(pwallet->cs_wallet);

        UniValue result(UniValue::VARR);

        auto* signer = pwallet->GetXMSSSigner();
        if (!signer) {
            return result;
        }

        auto keys = signer->GetXMSSKeys();
        for (const auto& pubkey : keys) {
            if (pubkey.size() != 64) continue;

            std::string addr = XMSSAddr::Encode(pubkey, Params().Bech32HRP());
            uint32_t idx = signer->GetLeafIndex(pubkey);
            uint32_t remaining = (idx <= 1024) ? (1024 - idx) : 0;
            bool retired = signer->IsXMSSKeyRetired(pubkey);

            // SNTI L4: generate warning string for operator monitoring.
            std::string warning;
            if (retired) {
                warning = "SPENT: one-time address already used — key cannot sign again";
            } else if (remaining == 0) {
                warning = "CRITICAL: key fully exhausted (0 signatures remaining)";
            } else if (remaining < 10) {
                warning = strprintf("CRITICAL: only %u signature(s) remaining", remaining);
            } else if (remaining < 200) {
                warning = strprintf("WARNING: only %u signatures remaining — generate a new key soon", remaining);
            }

            UniValue entry(UniValue::VOBJ);
            entry.pushKV("address", addr);
            entry.pushKV("pubkey", HexStr(pubkey));
            entry.pushKV("leaf_index", (int)idx);
            entry.pushKV("remaining", (int)remaining);
            entry.pushKV("retired", retired);
            entry.pushKV("warning", warning);
            entry.pushKV("label", "");
            result.push_back(entry);
        }

        return result;
    },
    };
}

// ---------------------------------------------------------------------------
// getxmsskeypool  (SNTI R2: key lifecycle management)
// ---------------------------------------------------------------------------
RPCHelpMan getxmsskeypool()
{
    return RPCHelpMan{"getxmsskeypool",
        "\nReturns a summary of the XMSS key pool status.\n"
        "Use this to monitor available signing capacity before it is exhausted.\n"
        "When fresh_keys reaches 0, new transactions cannot be signed until\n"
        "a new XMSS key is generated via getnewxmssaddress.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "Key pool summary",
            {
                {RPCResult::Type::NUM, "total_keys",    "Total XMSS keys in wallet"},
                {RPCResult::Type::NUM, "fresh_keys",    "Keys that have never signed (available for use)"},
                {RPCResult::Type::NUM, "retired_keys",  "Keys that have signed once (one-time address model)"},
                {RPCResult::Type::NUM, "exhausted_keys","Keys with 0 remaining signatures"},
                {RPCResult::Type::STR, "pool_status",   "\"ok\", \"low\" (<=1 fresh key), or \"empty\" (0 fresh keys)"},
                {RPCResult::Type::STR_HEX, "next_fresh_pubkey", "Pubkey of the next available signing key, or empty"},
            },
        },
        RPCExamples{
            HelpExampleCli("getxmsskeypool", "")
            + HelpExampleRpc("getxmsskeypool", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        LOCK(pwallet->cs_wallet);

        auto* signer = pwallet->GetXMSSSigner();
        if (!signer) {
            throw JSONRPCError(RPC_WALLET_ERROR, "XMSS signer not initialized");
        }

        auto keys = signer->GetXMSSKeys();
        int total = 0, fresh = 0, retired = 0, exhausted = 0;
        std::string next_fresh_pubkey;

        for (const auto& pubkey : keys) {
            if (pubkey.size() != 64) continue;
            total++;
            uint32_t idx = signer->GetLeafIndex(pubkey);
            bool is_retired = signer->IsXMSSKeyRetired(pubkey);
            if (is_retired) {
                retired++;
            } else if (idx >= 1024) {
                exhausted++;
            } else {
                fresh++;
                if (next_fresh_pubkey.empty()) {
                    next_fresh_pubkey = HexStr(pubkey);
                }
            }
        }

        std::string status;
        if (fresh == 0)      status = "empty";
        else if (fresh <= 1) status = "low";
        else                 status = "ok";

        UniValue result(UniValue::VOBJ);
        result.pushKV("total_keys",     total);
        result.pushKV("fresh_keys",     fresh);
        result.pushKV("retired_keys",   retired);
        result.pushKV("exhausted_keys", exhausted);
        result.pushKV("pool_status",    status);
        result.pushKV("next_fresh_pubkey", next_fresh_pubkey);
        return result;
    },
    };
}

// ---------------------------------------------------------------------------
// getxmssaddressinfo
// ---------------------------------------------------------------------------
RPCHelpMan getxmssaddressinfo()
{
    return RPCHelpMan{"getxmssaddressinfo",
        "\nGet information about an XMSS address.\n"
        "Returns key status if the address belongs to this wallet.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The XMSS address to query."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "",
            "Address information",
            {
                {RPCResult::Type::BOOL, "ismine", "Whether this address belongs to the wallet"},
                {RPCResult::Type::STR_HEX, "pubkey", "The 64-byte XMSS public key (hex, if ismine)"},
                {RPCResult::Type::NUM, "leaf_index", "Current leaf index (if ismine)"},
                {RPCResult::Type::NUM, "remaining", "Remaining signatures (if ismine)"},
                {RPCResult::Type::BOOL, "retired", "True if key is one-time-spent or blacklisted (cannot sign again, if ismine)"},
                {RPCResult::Type::STR, "warning", "Non-empty when key is spent, blacklisted, or near exhaustion (if ismine)"},
            },
        },
        RPCExamples{
            HelpExampleCli("getxmssaddressinfo", "\"address\"")
            + HelpExampleRpc("getxmssaddressinfo", "\"address\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        LOCK(pwallet->cs_wallet);

        std::string addr_str = request.params[0].get_str();

        uint160 hash;
        bool is_xmss = XMSSAddr::Decode(addr_str, hash, Params().Bech32HRP());

        UniValue result(UniValue::VOBJ);

        if (!is_xmss) {
            result.pushKV("ismine", false);
            result.pushKV("error", "Not a valid XMSS address");
            return result;
        }

        bool found = false;
        std::vector<uint8_t> found_pubkey;
        uint32_t found_idx = 0;
        bool found_retired = false;

        auto* signer = pwallet->GetXMSSSigner();
        if (signer) {
            auto keys = signer->GetXMSSKeys();
            for (const auto& pubkey : keys) {
                if (pubkey.size() != 64) continue;
                uint160 h = XMSSAddr::Hash(pubkey);
                if (h == hash) {
                    found = true;
                    found_pubkey = pubkey;
                    found_idx = signer->GetLeafIndex(pubkey);
                    found_retired = signer->IsXMSSKeyRetired(pubkey);
                    break;
                }
            }
        }

        result.pushKV("ismine", found);
        if (found) {
            uint32_t remaining = (found_idx <= 1024) ? (1024 - found_idx) : 0;

            // SNTI: mirror listxmsskeys' warning logic so callers (e.g. a
            // miner script deciding whether to keep paying rewards to this
            // address) can rely on either RPC for the same status.
            std::string warning;
            if (found_retired) {
                warning = "SPENT: one-time address already used — key cannot sign again";
            } else if (remaining == 0) {
                warning = "CRITICAL: key fully exhausted (0 signatures remaining)";
            } else if (remaining < 10) {
                warning = strprintf("CRITICAL: only %u signature(s) remaining", remaining);
            } else if (remaining < 200) {
                warning = strprintf("WARNING: only %u signatures remaining — generate a new key soon", remaining);
            }

            result.pushKV("pubkey", HexStr(found_pubkey));
            result.pushKV("leaf_index", (int)found_idx);
            result.pushKV("remaining", (int)remaining);
            result.pushKV("retired", found_retired);
            result.pushKV("warning", warning);
        }

        return result;
    },
    };
}

// ---------------------------------------------------------------------------
// sendtoxmssaddress
// ---------------------------------------------------------------------------
// NOTE: For v1, this creates a standard P2PKH output to the XMSS address hash.
// The recipient can identify incoming payments by checking the address hash.
// Full P2XMSSHASH/P2XMSS support will be added in a future update when
// CTxDestination is extended to support XMSS destinations natively.
// ---------------------------------------------------------------------------
RPCHelpMan sendtoxmssaddress()
{
    return RPCHelpMan{"sendtoxmssaddress",
        "\nSend SNTI to an XMSS address.\n"
        "The recipient must have an XMSS key pair to spend the funds later.\n"
        "Uses bare P2XMSS if this wallet already knows the recipient's full\n"
        "pubkey (e.g. sending to its own address), otherwise the hash-committed\n"
        "P2XMSSHASH form (pubkey revealed only when the recipient spends).\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The XMSS address to send to."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to send."},
            {"comment", RPCArg::Type::STR, RPCArg::Default{""}, "A comment stored in the wallet (not on-chain)."},
            {"comment_to", RPCArg::Type::STR, RPCArg::Default{""}, "A comment about the recipient (not on-chain)."},
            {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "Deduct fee from amount."},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "txid", "The transaction id"
        },
        RPCExamples{
            HelpExampleCli("sendtoxmssaddress", "\"XmssAddress...\" 1.0")
            + HelpExampleCli("sendtoxmssaddress", "\"XmssAddress...\" 1.0 \"donation\" \"sean's outpost\"")
            + HelpExampleRpc("sendtoxmssaddress", "\"XmssAddress...\", 1.0, \"donation\", \"sean's outpost\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        pwallet->BlockUntilSyncedToCurrentChain();

        LOCK(pwallet->cs_wallet);

        std::string addr_str = request.params[0].get_str();

        uint160 hash;
        if (!XMSSAddr::Decode(addr_str, hash, Params().Bech32HRP())) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid XMSS address");
        }

        CAmount nAmount = AmountFromValue(request.params[1]);
        if (nAmount <= 0) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
        }

        bool fSubtractFeeFromAmount = false;
        if (!request.params[4].isNull()) {
            fSubtractFeeFromAmount = request.params[4].get_bool();
        }

        // Build wallet comments
        mapValue_t mapValue;
        if (!request.params[2].isNull() && !request.params[2].get_str().empty())
            mapValue["comment"] = request.params[2].get_str();
        if (!request.params[3].isNull() && !request.params[3].get_str().empty())
            mapValue["to"] = request.params[3].get_str();
// Create a P2XMSS recipient using the full 64-byte XMSS public key
        // Decode the XMSS address to get the hash, then look up full pubkey
        std::vector<uint8_t> pubkey;
        wallet::CXMSSSigner* signer = pwallet->GetXMSSSigner();
        if (signer) {
            pubkey = signer->GetPubKeyForHash(hash);
        }
        std::vector<CRecipient> recipients;
        if (pubkey.size() == 64) {
            // P2XMSS: <64-byte-pubkey> OP_XMSS_CHECKSIG -- we already know
            // the recipient's full pubkey (e.g. paying our own address),
            // so embed it directly for a slightly smaller/cheaper spend later.
            std::array<uint8_t, 64> pubkey_arr;
            std::copy(pubkey.begin(), pubkey.end(), pubkey_arr.begin());
            XMSSHash xmss_dest(pubkey_arr);
            CRecipient recipient{xmss_dest, nAmount, fSubtractFeeFromAmount};
            recipients.push_back(recipient);
        } else {
            // SNTI: pubkey unknown to this wallet (paying someone else's
            // XMSS address) -- use the real hash-committed P2XMSSHASH form
            // now that it's properly supported (OP_DUP OP_HASH160 <hash>
            // OP_EQUALVERIFY OP_XMSS_CHECKSIG), instead of the old fake-P2PKH
            // "v1 compat" placeholder which produced a non-XMSS-spendable output.
            XMSSHash xmss_hash_dest(hash);
            CRecipient recipient{xmss_hash_dest, nAmount, fSubtractFeeFromAmount};
            recipients.push_back(recipient);
        }

        CCoinControl coin_control;

        // Use SendMoney which handles CreateTransaction + Sign + Commit
        EnsureWalletIsUnlocked(*pwallet);

        // Shuffle recipients
        std::shuffle(recipients.begin(), recipients.end(), FastRandomContext());

        auto res = CreateTransaction(*pwallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/true);
        if (!res) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(res).original);
        }
        const CTransactionRef& tx = res->tx;
        pwallet->CommitTransaction(tx, std::move(mapValue), /*orderForm=*/{});

        return tx->GetHash().GetHex();
    },
    };
}

// ---------------------------------------------------------------------------
// sendfromxmssaddress
// ---------------------------------------------------------------------------
// Sends SNTI from an XMSS address to a destination address.
// The XMSS key must be available in the wallet keystore.
// ---------------------------------------------------------------------------
RPCHelpMan sendfromxmssaddress()
{
    return RPCHelpMan{"sendfromxmssaddress",
        "\nSend SNTI from an XMSS address to any destination address.\n"
        "The XMSS private key must be loaded in the wallet.\n",
        {
            {"from_xmss_address", RPCArg::Type::STR, RPCArg::Optional::NO, "The XMSS address to send from."},
            {"to_address", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination address (legacy or XMSS)."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to send."},
            {"comment", RPCArg::Type::STR, RPCArg::Default{""}, "A comment stored in the wallet (not on-chain)."},
            {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "Deduct fee from amount."},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "txid", "The transaction id"
        },
        RPCExamples{
            HelpExampleCli("sendfromxmssaddress", "\"XmSSAddr...\" \"destAddr\" 1.0")
            + HelpExampleRpc("sendfromxmssaddress", "\"XmSSAddr...\", \"destAddr\", 1.0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        pwallet->BlockUntilSyncedToCurrentChain();

        LOCK(pwallet->cs_wallet);

        std::string from_addr_str = request.params[0].get_str();
        std::string to_addr_str = request.params[1].get_str();
        CAmount nAmount = AmountFromValue(request.params[2]);
        if (nAmount <= 0) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
        }
        bool fSubtractFeeFromAmount = false;
        if (!request.params[4].isNull()) {
            fSubtractFeeFromAmount = request.params[4].get_bool();
        }

        // Decode source XMSS address
        uint160 from_hash;
        if (!XMSSAddr::Decode(from_addr_str, from_hash, Params().Bech32HRP())) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid source XMSS address");
        }

// Determine destination type and build output
        CTxDestination dest;
        uint160 to_hash;
        bool to_xmss = XMSSAddr::Decode(to_addr_str, to_hash, Params().Bech32HRP());

        if (to_xmss) {
            // Try to get full pubkey for P2XMSS output
            std::vector<uint8_t> to_pubkey;
            wallet::CXMSSSigner* signer = pwallet->GetXMSSSigner();
            if (signer) {
                // Use the wallet's XMSS signer to get pubkey for this address
                uint160 to_hash_copy = to_hash;
                to_pubkey = signer->GetPubKeyForHash(to_hash_copy);
            }
            if (to_pubkey.size() == 64) {
                std::array<uint8_t, 64> pubkey_arr;
                std::copy(to_pubkey.begin(), to_pubkey.end(), pubkey_arr.begin());
                dest = XMSSHash(pubkey_arr);
            } else {
                // Fallback to P2PKH if full pubkey not known
                dest = PKHash(to_hash);
            }
        } else {
            // Try as legacy address
            dest = DecodeDestination(to_addr_str);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");
            }
        }

        // Build wallet comments
        mapValue_t mapValue;
        if (!request.params[3].isNull() && !request.params[3].get_str().empty())
            mapValue["comment"] = request.params[3].get_str();

        // Get XMSS signer
        CXMSSSigner* signer = pwallet->GetXMSSSigner();
        if (!signer) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                "No XMSS key loaded in wallet. Import an XMSS key first.");
        }

        // Check wallet balance
        const auto bal = GetBalance(*pwallet);
        CAmount nBalance = bal.m_mine_trusted;
        if (nBalance < nAmount) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient funds (have %s, need %s)",
                    FormatMoney(nBalance), FormatMoney(nAmount)));
        }

        // Build transaction output
        CRecipient recipient{std::move(dest), nAmount, fSubtractFeeFromAmount};
        std::vector<CRecipient> recipients;
        recipients.push_back(recipient);

        CCoinControl coin_control;
        EnsureWalletIsUnlocked(*pwallet);

        // SNTI FIX (18/Jun/2026): from_hash was decoded above purely to
        // validate the address format, then never used again — the empty
        // CCoinControl left automatic coin selection completely free to
        // pick ANY spendable UTXO in the wallet, silently ignoring the
        // caller's chosen source address (confirmed via end-to-end
        // testing: this RPC was sending real funds, just not from the
        // XMSS address it claimed to send from). Explicitly select every
        // UTXO whose scriptPubKey is a P2XMSS output matching this exact
        // address's pubkey hash, and disallow pulling in unrelated inputs.
        {
            // SNTI FIX (per Design Decision Record): AvailableCoinsListUnspent()
            // filters through IsMine(), which does not recognize P2XMSS outputs
            // for descriptor wallets (the LegacyScriptPubKeyMan bridge is inert
            // here -- see DEVDOCS.md). Bypass it with a manual mapWallet scan,
            // the same approach getxmssaddressinfo's separate ismine check uses.
            //
            // SNTI: XMSS keys are one-time-use per signing. Selecting multiple
            // UTXOs from the same address would require signing multiple inputs
            // with the same key — impossible once the key is retired after the
            // first use. Select only ONE UTXO at a time; the wallet can
            // collect change back to a non-XMSS address for further spending.
            // We pick the smallest UTXO that is >= nAmount + estimated fee, or
            // if none exists, the largest available UTXO.
            struct XMSSUtxo {
                COutPoint outpoint;
                CAmount   value;
            };
            std::vector<XMSSUtxo> xmss_utxos;
            for (const auto& [txid, wtx] : pwallet->mapWallet) {
                if (pwallet->GetTxDepthInMainChain(wtx) < 1) continue;
                const CTransactionRef& wtx_tx = wtx.tx;
                for (unsigned int n = 0; n < wtx_tx->vout.size(); n++) {
                    COutPoint outpoint(wtx.GetHash(), n);
                    if (pwallet->IsSpent(outpoint)) continue;
                    const CTxOut& txout = wtx_tx->vout[n];
                    std::vector<std::vector<unsigned char>> solutions;
                    TxoutType type = Solver(txout.scriptPubKey, solutions);
                    bool matches = false;
                    if (type == TxoutType::P2XMSS && solutions.size() == 1 && solutions[0].size() == 64) {
                        matches = (XMSSAddr::Hash(solutions[0]) == from_hash);
                    } else if (type == TxoutType::P2XMSSHASH && solutions.size() == 1 && solutions[0].size() == 20) {
                        matches = (uint160(solutions[0]) == from_hash);
                    }
                    if (matches) {
                        xmss_utxos.push_back({outpoint, txout.nValue});
                    }
                }
            }
            if (xmss_utxos.empty()) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    "No spendable funds found at this XMSS address");
            }
            // Pick the best single UTXO: smallest that covers nAmount, else largest.
            // XMSS scriptSig is ~2.5 kB; estimate fee from current fee rate (audit fix #11).
            // Approximate tx size: 10 (header) + 41 (input) + 2500 (XMSS scriptSig) + 34 (output) ~= 2600 bytes.
            FeeCalculation fee_calc;
            CFeeRate fee_rate = GetMinimumFeeRate(*pwallet, coin_control, &fee_calc);
            const CAmount fee_estimate = fee_rate.GetFee(2600);
            const CAmount needed = nAmount + fee_estimate;
            std::sort(xmss_utxos.begin(), xmss_utxos.end(), [](const XMSSUtxo& a, const XMSSUtxo& b){ return a.value < b.value; });
            COutPoint chosen = xmss_utxos.back().outpoint; // default: largest
            for (const auto& u : xmss_utxos) {
                if (u.value >= needed) { chosen = u.outpoint; break; }
            }
            coin_control.Select(chosen);
            coin_control.m_allow_other_inputs = false; // only spend the chosen XMSS UTXO
        }

        // Create and sign transaction with XMSS
        auto res = CreateTransaction(*pwallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/true);
        if (!res) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(res).original);
        }
        const CTransactionRef& tx = res->tx;
        pwallet->CommitTransaction(tx, std::move(mapValue), /*orderForm=*/{});

        return tx->GetHash().GetHex();
    },
    };
}

// ---------------------------------------------------------------------------
// importxmsskey
// ---------------------------------------------------------------------------
// Import an XMSS private key into the wallet.
// Format: hex-encoded 64-byte pubkey + hex-encoded secret key
// ---------------------------------------------------------------------------
RPCHelpMan importxmsskey()
{
    return RPCHelpMan{"importxmsskey",
        "\nImport an XMSS private key into the wallet.\n"
        "The key can later be used to sign transactions from the corresponding XMSS address.\n",
        {
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte XMSS public key (hex)."},
            {"seckey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The XMSS secret key (hex)."},
            {"label", RPCArg::Type::STR, RPCArg::Default{""}, "A label for the key."},
            {"rescan", RPCArg::Type::BOOL, RPCArg::Default{true}, "Rescan the wallet for transactions."},
        },
        RPCResult{
            RPCResult::Type::STR, "address", "The XMSS address corresponding to the imported key"
        },
        RPCExamples{
            HelpExampleCli("importxmsskey", "\"<64-byte-pubkey-hex>\" \"<seckey-hex>\" \"my-key\"")
            + HelpExampleRpc("importxmsskey", "\"<64-byte-pubkey-hex>\", \"<seckey-hex>\", \"my-key\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        pwallet->BlockUntilSyncedToCurrentChain();
        LOCK(pwallet->cs_wallet);

        // Decode pubkey
        std::vector<uint8_t> pubkey = ParseHex(request.params[0].get_str());
        if (pubkey.size() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid XMSS public key: must be 64 bytes");
        }

        // Decode seckey
        std::vector<uint8_t> seckey = ParseHex(request.params[1].get_str());
        if (seckey.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid XMSS secret key: empty");
        }

        // SNTI FIX (importxmsskey default-parameter bug, 21/Jun/2026): the
        // original code called .get_str()/.get_bool() directly on
        // request.params[2]/[3] without checking isNull() first, even
        // though both are declared as optional with defaults above. Any
        // call omitting label/rescan crashed with a generic "JSON value
        // of type null is not of expected type X" instead of using the
        // declared defaults.
        std::string label = request.params[2].isNull() ? "" : request.params[2].get_str();
        bool rescan = request.params[3].isNull() ? true : request.params[3].get_bool();

        // Add key to wallet's XMSS signer
        wallet::CXMSSSigner* signer = pwallet->GetXMSSSigner();
        if (!signer) {
            throw JSONRPCError(RPC_WALLET_ERROR, "XMSS signer not available");
        }

        if (!signer->AddXMSSKey(pubkey, seckey)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import XMSS key (key may already exist)");
        }

        // Compute address from pubkey
        uint160 hash = XMSSAddr::Hash(pubkey);
        std::string addr = XMSSAddr::Encode(pubkey, Params().Bech32HRP());

        // Store in keystore for IsMine detection
        pwallet->AddXMSSKeyToKeystore(hash, pubkey);

        // Persist XMSS state to wallet DB immediately so the key survives
        // wallet unload/reload without needing to re-import.
        pwallet->PersistXMSSState();

        // Rescan if requested
        if (rescan) {
            wallet::WalletRescanReserver reserver(*pwallet);
            reserver.reserve();
            pwallet->RescanFromTime(0, reserver, true);
        }

        return addr;
    },
    };
}

// ---------------------------------------------------------------------------
// exportxmsskey
// ---------------------------------------------------------------------------
// Export an XMSS private key from the wallet.
// Returns hex-encoded pubkey + seckey for backup/import.
// ---------------------------------------------------------------------------
RPCHelpMan exportxmsskey()
{
    return RPCHelpMan{"exportxmsskey",
        "\nExport an XMSS private key from the wallet.\n"
        "Returns the public and secret key in hex format for backup.\n"
        "WARNING: Handle with extreme care — anyone with the secret key can spend funds.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The XMSS address to export the key for."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Key export data",
            {
                {RPCResult::Type::STR_HEX, "pubkey", "The 64-byte XMSS public key (hex)"},
                {RPCResult::Type::STR_HEX, "seckey", "The XMSS secret key (hex)"},
                {RPCResult::Type::STR, "address", "The XMSS address"},
                {RPCResult::Type::NUM, "leaf_index", "Current leaf index (signatures used)"},
                {RPCResult::Type::NUM, "remaining", "Remaining signatures available"},
            }
        },
        RPCExamples{
            HelpExampleCli("exportxmsskey", "\"XmSSAddr...\"")
            + HelpExampleRpc("exportxmsskey", "\"XmSSAddr...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        pwallet->BlockUntilSyncedToCurrentChain();
        LOCK(pwallet->cs_wallet);

        std::string addr_str = request.params[0].get_str();

        // Decode address to get hash
        uint160 hash;
        if (!XMSSAddr::Decode(addr_str, hash, Params().Bech32HRP())) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid XMSS address");
        }

        // Get pubkey from keystore
        std::vector<uint8_t> pubkey;
        if (!pwallet->GetXMSSPubKey(hash, pubkey) || pubkey.size() != 64) {
            throw JSONRPCError(RPC_WALLET_ERROR, "XMSS key not found for this address");
        }

        // Get full key data from signer
        wallet::CXMSSSigner* signer = pwallet->GetXMSSSigner();
        if (!signer) {
            throw JSONRPCError(RPC_WALLET_ERROR, "XMSS signer not available");
        }

        // Get secret key (this is sensitive!)
        std::vector<uint8_t> seckey = signer->GetSecKeyForPubkey(pubkey);
        if (seckey.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Secret key not available (watch-only wallet?)");
        }

        uint32_t leaf_index = signer->GetLeafIndex(pubkey);
        uint32_t remaining = (leaf_index < 1024) ? (1024 - leaf_index) : 0;

        UniValue result(UniValue::VOBJ);
        result.pushKV("pubkey", HexStr(pubkey));
        result.pushKV("seckey", HexStr(seckey));
        result.pushKV("address", addr_str);
        result.pushKV("leaf_index", (int64_t)leaf_index);
        result.pushKV("remaining", (int64_t)remaining);

        return result;
    },
    };
}

} // namespace wallet
