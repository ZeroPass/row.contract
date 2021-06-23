#!/bin/bash
CLEOS=cleos.sh

row_contract_account='irowyourboat'
contract_dir='contracts'
contract_name='row'

$CLEOS set contract $row_contract_account $contract_dir ${contract_name}.wasm ${contract_name}.abi
