 sleep 5
root@Nurilma:~/AssentianPQE-SNTI# ./src/bitcoin-cli -testnet -datadir=$HOME/.assentian_vm \
> -rpcuser=user -rpcpassword=password -rpcport=39332 \
> getblockchaininfo | grep -E "bestblockhash|blocks|headers"
  "blocks": 456,
  "headers": 456,
  "bestblockhash": "f80a5bf3322abe0295634085c39ea5e2d48042239c4fd3c25181a9f10f270390",
root@Nurilma:~/AssentianPQE-SNTI#