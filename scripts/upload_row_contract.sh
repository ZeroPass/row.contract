#!/bin/bash
CLEOS=/mnt/disk/row/cleos.sh

row_contract_account='irowyourboat'
contract_dir='/mnt/disk/row/contracts'
contract_name='row'

$CLEOS set contract $row_contract_account $contract_dir ${contract_name}.wasm ${contract_name}.abi
