#!/bin/bash
CLEOS=/mnt/disk/row/cleos.sh

contract_account='irowyourboat'
contract_key='EOS66kac59Fm7tUBcm2yYZ4DExYLgPjoSptHYQZdJHCKyH8pa2dsw'
user_key='EOS7ieV7mwNgnYcoQ5r6yKdfwuCg1UuP6GUucXULnM6QK5byx3qzD'

create_account () {
  $CLEOS create account eosio $1 $2 $2
}

create_user() {
    create_account $1 ${user_key}
    $CLEOS set account permission $1 'active' '{
        "threshold": 1,
        "keys": [
            {
            "key": "'${user_key}'",
            "weight": 1
            }
        ],
        "accounts": [
            {
            "permission": {
                "actor": "'${contract_account}'",
                "permission": "active"
            },
            "weight": 1
            },
            {
            "permission": {
                "actor": "'${contract_account}'",
                "permission": "eosio.code"
            },
            "weight": 1
            }
        ]
    }'

    $CLEOS set account permission $1 'wamsig' '{
        "threshold": 1,
        "keys": [
            {
            "key": "'${user_key}'",
            "weight": 1
            }
        ]
    }'

    $CLEOS set action permission $1 ${contract_account} 'propose' 'wamsig'
    $CLEOS set action permission $1 ${contract_account} 'approve' 'wamsig'
    $CLEOS set action permission $1 ${contract_account} 'exec' 'wamsig'
}

create_account 'eosio.token' $contract_key
create_account $contract_account $contract_key
create_user 'rowuseruser1'
create_user 'rowuseruser2'
create_user 'rowuseruser3'