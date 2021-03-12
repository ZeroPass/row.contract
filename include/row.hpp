#include <optional>

#include <eosio/eosio.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/string.hpp>
#include <eosio/transaction.hpp>

using namespace eosio;

class [[eosio::contract]] row : public contract
{
public:
    using contract::contract;

    [[eosio::action]]
    void propose(name proposer, name proposal_name, ignore<transaction> trx);

    [[eosio::action]]
    void approve( name proposer, name proposal_name );

    [[eosio::action]]
    void cancel( name proposer, name proposal_name, name canceler );

    [[eosio::action]]
    void exec( name proposer, name proposal_name, name executer );

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

    typedef eosio::multi_index< "proposals"_n, proposal > proposals;

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
    typedef eosio::multi_index< "approvals"_n, approvals_info > approvals;
};
