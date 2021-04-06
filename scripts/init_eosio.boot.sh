#!/bin/bash
CLEOS=/mnt/disk/row/cleos.sh

contract_dir='/mnt/disk/row/contracts'
contract_name='eosio.boot'

$CLEOS set contract eosio $contract_dir ${contract_name}.wasm ${contract_name}.abi
