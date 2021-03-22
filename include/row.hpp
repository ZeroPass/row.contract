#pragma once
#include <optional>
#include <vector>

#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/singleton.hpp>
#include <eosio/string.hpp>
#include <eosio/transaction.hpp>

#include "types.hpp"

using namespace eosio;

class [[eosio::contract]] row : public contract
{
public:
    struct authkey {
        name                          key_name;
        public_key                    key; // due to bug in eosio.cdt key type can't be of type webauthn_public_key.
        std::optional<time_point_sec> wait;
        uint16_t                      weight;
        bytes                         keyid; // webauthn credential ID
        uint64_t primary_key() const { return key_name.value; }
    };

    struct [[eosio::table]] authority {
        uint32_t             threshold = 1;
        std::vector<authkey> keys;
    };
    using authority_db = singleton< "authority"_n, authority >;

    using contract::contract;

    [[eosio::action]]
    void propose(name proposer, name proposal_name, ignore<transaction> trx);

    [[eosio::action]]
    void approve( name proposer, name proposal_name );

    [[eosio::action]]
    void cancel(name proposer, name proposal_name, name canceler);

    [[eosio::action]]
    void exec(name proposer, name proposal_name, name executer);

    /**
     * Action adds key to the account's authority.
     * @param account - the name of account to remove key
     * @param authkey - authority key
    */
    [[eosio::action]]
    void addkey(name account, authkey key);

    /**
     * Action removes key from account's authority.
     * @note if after removing key the threshold is greater than the sum of weights of remaining keys,
     *       the threshold is lowered to the sum of weights.
     * @note if no keys remains after removal the account0s authority entry is removed.
     * @param account - the name of account to remove key
     * @param key_name - the name of key to remove
    */
    [[eosio::action]]
    void removekey(name account, name key_name);

    /**
     * Action sets threshold for the account's authority.
     * @param account - the name of account
     * @param threshold - the new account threshold.
     *                    Treshold can be zero or greater than sum of weights of all keys.
     */
    [[eosio::action]]
    void sethreshold(name account, uint32_t threshold);

    [[eosio::action]]
    void hi(name nm);

    //[[eosio::action]] std::pair<int, std::string> checkwithrv(name nm);

    using hi_action = action_wrapper<"hi"_n, &row::hi>;
    //using checkwithrv_action = action_wrapper<"checkwithrv"_n, &row::checkwithrv>;

    struct [[eosio::table]] proposal {
        name                      proposal_name;
        std::vector<char>         packed_transaction;
        std::optional<time_point> earliest_exec_time;
        uint64_t primary_key()const { return proposal_name.value; }
    };
    using proposals = multi_index< "proposals"_n, proposal >;

    struct approval {
        permission_level level;
        time_point       time;
    };

    struct [[eosio::table]] approvals_info {
        uint8_t version = 1;
        name    proposal_name;
        //requested approval doesn't need to cointain time, but we want requested approval
        //to be of exact the same size ad provided approval, in this case approve/unapprove
        //doesn't change serialized data size. So, we use the same type.
        //std::vector<approval>   requested_approvals;
        std::vector<approval>  provided_approvals;

        uint64_t primary_key()const { return proposal_name.value; }
    };
    using approvals = multi_index< "approvals"_n, approvals_info >;
};
