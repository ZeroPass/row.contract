#!/bin/bash
CLEOS=/mnt/disk/row/cleos.sh

contract_dir='/mnt/disk/row/contracts'
contract_name='eosio.token'

function transfer_to() {
    $CLEOS transfer -c eosio.token eosio.token $1 "$2" "Here's some tokens"
}

$CLEOS set contract 'eosio.token' $contract_dir ${contract_name}.wasm ${contract_name}.abi
$CLEOS push action eosio.token create '["eosio.token", "10000000000.0000 EOS"]' -p eosio.token@active
$CLEOS push action eosio.token issue '["eosio.token", "10000000000.0000 EOS", "issuing EOS"]' -p eosio.token@active

transfer_to 'rowuseruser1' '10000.0000 EOS'
transfer_to 'rowuseruser2' '10000.0000 EOS'
transfer_to 'rowuseruser3' '10000.0000 EOS'