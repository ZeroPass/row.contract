# row.contract
Short demo https://youtu.be/1TeMFoVr95A

This repository contains ROW EOSIO smart contract which handles WebAuthn multisig transaction executions. 
The contract manages user authorization permissions (authorities table), transaction proposals, proposed transaction approvals via WebAuthn signature and executes proposed transaction.
Contract also stores WebAuthn keyhandles (credentialID) for every stored authority key.

There are 2 signature algorithms supported, the RSA PKCS v1.5 (RS256) signature algorithm and ECDSA P-256 (ES256) signature algorithm, using SHA-256 for hash algorithm.
The RSA PKCS v1.5 algorithm is [written in the contract](https://github.com/ZeroPass/row.contract/blob/bca79998c947455826bd56e0855581df7aa75e41/include/row/crypto.hpp#L155-L230). 


# Requirements
Installed EOSIO nodeos v2.0
Installed eosio.cdt 1.8

# How to build
1. `git clone https://github.com/ZeroPass/row.contract.git row.contract`
2. `cd row.contract`
3. `mkdir build`
4. `cd build`
5. `cmake ..`
6. `make`

# How to install
Start `nodeos` with `--eos-vm-oc-enable` flag (due to RSA **)
In folder [scripts](https://github.com/ZeroPass/row.contract/tree/master/scripts) modify any script to point to valid nodeos and change account keys as needed,
then execute script `bootstrap.sh`.

# Testnet
Contract with RSA support enabled is uploaded to Jungle 3 testnet under the [irowyourboat](https://jungle3.bloks.io/account/irowyourboat) account.

# Copyright
 © 2021 ZeroPass <zeropass@pm.me>