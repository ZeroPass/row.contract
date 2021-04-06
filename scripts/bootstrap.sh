#!/bin/bash
#activate protocol features, create all account, init eosio.token contract and upload row contract

curl -X POST http://127.0.0.1:9898/v1/producer/schedule_protocol_feature_activations -d '{"protocol_features_to_activate": ["0ec7e080177b2c02b278d5088611686b49d739925a92d9bfcacd7fc6b74053bd"]}' # PREACTIVATE_FEATURE


./init_eosio.boot.sh
./create_accounts.sh
./init_eosio.token.sh
./upload_row_contract.sh

# activate WEBAUTHN_KEY protocol feature
./cleos.sh push action eosio activate ["4fca8bd82bbd181e714e283f83e1b45d95ca5af40fb89ad3977b653c448f78c2"] -p eosio@active
#curl -X POST http://127.0.0.1:9898/v1/producer/schedule_protocol_feature_activations -d '{"protocol_features_to_activate": ["4fca8bd82bbd181e714e283f83e1b45d95ca5af40fb89ad3977b653c448f78c2"]}' # WEBAUTHN_KEY