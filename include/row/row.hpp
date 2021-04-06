#pragma once
#include <optional>
#include <vector>

#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/singleton.hpp>
#include <eosio/string.hpp>
#include <eosio/transaction.hpp>

#include <row/crypto.hpp>
#include <row/types.hpp>

using namespace eosio;

class [[eosio::contract]] row : public contract
{
public:
    struct authkey {
        name                    key_name;
        wa_public_key           key;
        std::optional<uint32_t> wait_sec;
        uint16_t                weight;
        bytes                   keyid;    // webauthn credential ID
    };

    struct [[eosio::table("authorities")]] authority {
        uint32_t             threshold = 1;
        std::vector<authkey> keys;
    };
    using authorities = singleton< "authorities"_n, authority >;

    using contract::contract;

    [[eosio::action]]
    void propose(name account, name proposal_name, std::vector<name> requested_approvals, ignore<transaction> tx);

    [[eosio::action]]
    void approve(name account, name proposal_name, name key_name, const wa_signature& signature);

    [[eosio::action]]
    void cancel(name account, name proposal_name);

    [[eosio::action]]
    void exec(name account, name proposal_name);

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
    void clrproptbl(name account)
    {
        require_auth(account);
        proposals proptable( get_self(), account.value );
        auto pit = proptable.begin();
        while(pit != proptable.end()) {
            pit = proptable.erase(pit);
        }

        approvals appdb( get_self(), account.value );
        auto ait = appdb.begin();
        while(ait != appdb.end()) {
            ait = appdb.erase(ait);
        }
    }

    [[eosio::action]]
    void testwasig(wa_public_key pubkey, eosio::checksum256 signed_hash, wa_signature sig)
    {
        assert_wa_signature(pubkey, signed_hash, sig, "WA signature verification failed");
    }

    [[eosio::action]]
    void hi(name nm);
    using hi_action = action_wrapper<"hi"_n, &row::hi>;

    struct [[eosio::table]] proposal {
        name                      proposal_name;
        time_point                create_time;
        std::vector<char>         packed_transaction;
        std::optional<time_point> earliest_exec_time;
        uint64_t primary_key() const { return proposal_name.value; }
    };
    using proposals = multi_index< "proposals"_n, proposal >;

    struct [[eosio::table]] approvals_info {
        name proposal_name;
        std::vector<name> requested_approvals; // list of key_names
        std::vector<name> provided_approvals; // list of key_names
        uint64_t primary_key() const { return proposal_name.value; }
    };
    using approvals = multi_index< "approvals"_n, approvals_info >;
};
