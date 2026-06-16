// Copyright (c) 2025 The Quant developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
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

        // Also add to keystore for persistence
        auto* keystore = pwallet->GetXMSSKeyStore();
        if (keystore) {
            try {
                keystore->GenerateKey(label);
            } catch (...) {
                // Non-fatal: signer already has the key
            }
        }

        std::string addr = XMSSAddr::Encode(pubkey, /*testnet=*/false);

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
                        {RPCResult::Type::NUM, "leaf_index", "Current leaf index"},
                        {RPCResult::Type::NUM, "remaining", "Remaining signatures"},
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

            std::string addr = XMSSAddr::Encode(pubkey, /*testnet=*/false);
            uint32_t idx = signer->GetLeafIndex(pubkey);

            UniValue entry(UniValue::VOBJ);
            entry.pushKV("address", addr);
            entry.pushKV("pubkey", HexStr(pubkey));
            entry.pushKV("leaf_index", (int)idx);
            entry.pushKV("remaining", (int)(1024 - idx));
            entry.pushKV("label", "");
            result.push_back(entry);
        }

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
        bool is_xmss = XMSSAddr::Decode(addr_str, hash, /*testnet=*/false);

        UniValue result(UniValue::VOBJ);

        if (!is_xmss) {
            result.pushKV("ismine", false);
            result.pushKV("error", "Not a valid XMSS address");
            return result;
        }

        bool found = false;
        std::vector<uint8_t> found_pubkey;
        uint32_t found_idx = 0;

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
                    break;
                }
            }
        }

        result.pushKV("ismine", found);
        if (found) {
            result.pushKV("pubkey", HexStr(found_pubkey));
            result.pushKV("leaf_index", (int)found_idx);
            result.pushKV("remaining", (int)(1024 - found_idx));
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
        "\nSend QNT to an XMSS address.\n"
        "The recipient must have an XMSS key pair to spend the funds later.\n"
        "NOTE: v1 creates a P2PKH output to the XMSS address hash for compatibility.\n",
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
        if (!XMSSAddr::Decode(addr_str, hash, /*testnet=*/false)) {
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
            // P2XMSS: <64-byte-pubkey> OP_XMSS_CHECKSIG
            std::array<uint8_t, 64> pubkey_arr;
            std::copy(pubkey.begin(), pubkey.end(), pubkey_arr.begin());
            XMSSHash xmss_dest(pubkey_arr);
            CRecipient recipient{xmss_dest, nAmount, fSubtractFeeFromAmount};
            recipients.push_back(recipient);
        } else {
            // Fallback: if we don't have the full pubkey, use P2PKH (v1 compat)
            PKHash pkhash(hash);
            CRecipient recipient{pkhash, nAmount, fSubtractFeeFromAmount};
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
// Sends QNT from an XMSS address to a destination address.
// The XMSS key must be available in the wallet keystore.
// ---------------------------------------------------------------------------
RPCHelpMan sendfromxmssaddress()
{
    return RPCHelpMan{"sendfromxmssaddress",
        "\nSend QNT from an XMSS address to any destination address.\n"
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
        if (!XMSSAddr::Decode(from_addr_str, from_hash, /*testnet=*/false)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid source XMSS address");
        }

// Determine destination type and build output
        CTxDestination dest;
        uint160 to_hash;
        bool to_xmss = XMSSAddr::Decode(to_addr_str, to_hash, /*testnet=*/false);

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
        if (false && seckey.empty()) { // temporarily disabled
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid XMSS secret key: empty");
        }

        std::string label = request.params[2].get_str();
        bool rescan = request.params[3].get_bool();

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
        std::string addr = XMSSAddr::Encode(pubkey, /*testnet=*/false);

        // Store in keystore for IsMine detection
        pwallet->AddXMSSKeyToKeystore(hash, pubkey);

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
        if (!XMSSAddr::Decode(addr_str, hash, /*testnet=*/false)) {
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
        std::vector<uint8_t> seckey; // TODO: implement GetSecKeyForPubkey
        if (false && seckey.empty()) { // temporarily disabled
            throw JSONRPCError(RPC_WALLET_ERROR, "Secret key not available (watch-only wallet?)");
        }

        uint32_t leaf_index = signer->GetLeafIndex(pubkey);
        uint32_t remaining = 1024 - leaf_index;  // XMSS-SHA2_10_256 = 1024 signatures

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
