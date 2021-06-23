#!/bin/bash
CLEOS=/usr/bin/cleos
WALLET_URL="unix://keosd.sock"
$CLEOS --wallet-url="$WALLET_URL" -u http://127.0.0.1:9898 "$@"

