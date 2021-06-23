#!/bin/bash
CLEOS=cleos.sh

contract_dir='contracts'
contract_name='eosio.boot'

$CLEOS set contract eosio $contract_dir ${contract_name}.wasm ${contract_name}.abi
