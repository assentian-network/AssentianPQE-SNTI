// Copyright (c) 2025 The Assentian-PQE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPC_XMSS_H
#define BITCOIN_WALLET_RPC_XMSS_H

#include <rpc/util.h>

namespace wallet {

// SNTI XMSS RPC commands
RPCHelpMan getnewxmssaddress();
RPCHelpMan listxmsskeys();
RPCHelpMan getxmsskeypool();
RPCHelpMan getxmssaddressinfo();
RPCHelpMan sendtoxmssaddress();
RPCHelpMan sendfromxmssaddress();
RPCHelpMan importxmsskey();
RPCHelpMan exportxmsskey();

} // namespace wallet

#endif // BITCOIN_WALLET_RPC_XMSS_H
