#!/bin/bash
CLEOS=/mnt/disk/epid/eosio_src/build/bin/cleos
WALLET_URL="unix:///mnt/disk/epid/wallet/keosd.sock"
$CLEOS --wallet-url="$WALLET_URL" -u http://127.0.0.1:9898 "$@"

