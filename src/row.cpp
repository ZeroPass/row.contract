#include <eosio/action.hpp>
#include <eosio/permission.hpp>

#include <numeric>

#include <row.hpp>
#include <span.hpp>


transaction_header get_tx_header(const char* ptr, size_t sz) {
    datastream<const char*> ds = {ptr, sz};
    transaction_header tx_header;
    ds >> tx_header;
    return tx_header;
}

bool is_tx_authorized(const std::vector<permission_level>& approvals, const std::vector<char>& packed_trx) {
    auto packed_approvals = pack(approvals);
    return check_transaction_authorization(
        packed_trx.data(), packed_trx.size(),
        (const char*)0, 0,
        packed_approvals.data(), packed_approvals.size()
    );
}

template<typename Function>
std::vector<permission_level> get_approvals_and_adjust_table(name self, name proposer, name proposal_name, Function&& table_op) {
    row::approvals apptable( self, proposer.value );
    auto& auths = apptable.get( proposal_name.value, "proposal not found" );
    std::vector<permission_level> auth_list;
    //invalidations invalidations_table( self, self.value );


    auth_list.reserve( auths.provided_approvals.size() );
    for ( const auto& permission : auths.provided_approvals ) {
        //auto iter = invalidations_table.find( permission.level.actor.value );
        //if ( iter == invalidations_table.end() || iter->last_invalidation_time < permission.time ) {
            auth_list.push_back(permission.level);
        //}
    }
    table_op( apptable, auths );
    return auth_list;
}


void row::propose(name proposer, name proposal_name, ignore<transaction> trx)
{
    require_auth(proposer);
    check( proposer != _self, "I can't make proposal by myself" );

    auto& ds = get_datastream();

    const char*  tx_pos  = ds.pos();
    const size_t tx_size = ds.remaining();

    transaction_header tx_header;
    ds >> tx_header;
    check( tx_header.expiration >= eosio::time_point_sec(current_time_point()), "transaction has expired" );

    std::vector<action> ctx_free_actions;
    ds >> ctx_free_actions;
    check( ctx_free_actions.empty(), "not allowed to `propose` a transaction with context-free actions" );

    proposals proptable( get_self(), proposer.value );
    check( proptable.find( proposal_name.value ) == proptable.end(), "proposal with the same name exists" );

    auto packed_requested = pack(std::vector{permission_level{ _self, "active"_n }});
    auto has_auth =  check_transaction_authorization(
        tx_pos, tx_size,
        (const char*)0, 0,
        packed_requested.data(), packed_requested.size()
    );

    std::vector<char> raw_tx;
    raw_tx.resize(tx_size);
    memcpy((char*)raw_tx.data(), tx_pos, tx_size);
    //check( is_tx_authorized( std::vector{permission_level{ proposer, "active"_n }}, raw_tx ), "transaction authorization failed" );

    proptable.emplace( proposer, [&]( auto& p ) {
        p.proposal_name      = proposal_name;
        p.packed_transaction = raw_tx;
        p.earliest_exec_time = std::optional<time_point>{};
    });

    approvals apptable( get_self(), proposer.value );
    apptable.emplace( proposer, [&]( auto& a ) {
        a.proposal_name = proposal_name;
        // a.requested_approvals.reserve( requested.size() );
        // for ( auto& level : requested ) {
        //     a.requested_approvals.push_back( approval{ level, time_point{ microseconds{0} } } );
        // }
    });
}

void row::approve( name proposer, name proposal_name)
{
    require_auth(proposer);
    // if ( level.permission == "eosio.code"_n ) {
    //     check( get_sender() == level.actor, "wrong contract sent `approve` action for eosio.code permmission" );
    // }
    // else {
    //     require_auth( level );
    // }

    proposals proptable( get_self(), proposer.value );
    auto& proposal = proptable.get( proposal_name.value, "proposal not found" );

//    if( proposal_hash ) {
//       assert_sha256( prop.packed_transaction.data(), prop.packed_transaction.size(), *proposal_hash );
//    }

    approvals apptable( get_self(), proposer.value );
    auto& auths = apptable.get( proposal_name.value );
    //auto it = std::find_if( apps_it->requested_approvals.begin(), apps_it->requested_approvals.end(), [&](const approval& a) { return a.level == level; } );
    //check( it != apps_it->requested_approvals.end(), "approval is not on the list of requested approvals" );

    auto level = permission_level{ _self, "active"_n };
    auto it = std::find_if(
        auths.provided_approvals.begin(),
        auths.provided_approvals.end(),
        [&](const approval& a) { return a.level == level; }
    );
    check( it == auths.provided_approvals.end(), "already in the list of approvals" );
    apptable.modify( auths, proposer, [&]( auto& a ) {
        a.provided_approvals.push_back( approval{ level, current_time_point() } );
        //a.requested_approvals.erase( itr );
    });

    // set execution delay to time of first approval + transaction delay
    transaction_header tx_header = unpack<transaction_header>( proposal.packed_transaction );//get_trx_header(proposal.packed_transaction.data(), proposal.packed_transaction.size());
    if ( !proposal.earliest_exec_time.has_value() ) {
        auto table_op = [](auto&&, auto&&){};
        if ( is_tx_authorized(get_approvals_and_adjust_table(get_self(), proposer, proposal_name, table_op), proposal.packed_transaction) ) {
            proptable.modify( proposal, proposer, [&]( auto& p ) {
                p.earliest_exec_time = std::optional<time_point>{ current_time_point() + eosio::seconds(tx_header.delay_sec.value)};
            });
        }
    }
}

void row::cancel( name proposer, name proposal_name, name canceler )
{
    require_auth( canceler );

    proposals proptable( get_self(), proposer.value );
    auto& prop = proptable.get( proposal_name.value, "proposal not found" );

    if( canceler != proposer ) {
        check( unpack<transaction_header>( prop.packed_transaction ).expiration < eosio::time_point_sec(current_time_point()), "cannot cancel until expiration" );
    }
    proptable.erase(prop);

    approvals apptable( get_self(), proposer.value );
    auto& auths = apptable.get( proposal_name.value, "proposal not found" );
    apptable.erase(auths);
}

void row::exec( name proposer, name proposal_name, name executer )
{
    require_auth( executer );

    proposals proptable( get_self(), proposer.value );
    auto& proposal = proptable.get( proposal_name.value, "proposal not found" );

    datastream<const char*> ds = { proposal.packed_transaction.data(), proposal.packed_transaction.size() };
    transaction_header trx_header;
    ds >> trx_header;
    check( trx_header.expiration >= eosio::time_point_sec(current_time_point()), "transaction expired" );

    std::vector<action> ctx_free_actions;
    ds >> ctx_free_actions;
    check( ctx_free_actions.empty(), "not allowed to `exec` a transaction with context-free actions" );

    std::vector<action> actions;
    ds >> actions;

    auto table_op = [](auto&& table, auto&& table_iter) { table.erase(table_iter); };
    bool is_auth = is_tx_authorized(get_approvals_and_adjust_table(get_self(), proposer, proposal_name, table_op), proposal.packed_transaction);
    check( is_auth, "transaction authorization failed" );

    if ( proposal.earliest_exec_time.has_value() ) {
        check( proposal.earliest_exec_time.value() <= current_time_point(), "too early to execute" );
    } else {
        check( trx_header.delay_sec.value == 0, "old proposals are not allowed to have non-zero `delay_sec`; cancel and retry" );
    }

    for (const auto& a : actions) {
        a.send();
    }

    proptable.erase(proposal);
}

void row::addkey(name account, authkey key)
{
    //TODO: pin key to webauthn_public_key.
    //      e.g. check(std::holds_alternative<webauthn_public_key>(key.key), "only webauthn_public_key allowed");
    static_assert( std::is_same_v<decltype(std::declval<authority>().threshold), uint32_t> &&
        std::is_same_v<decltype(std::declval<authority>().keys)::value_type, authkey> &&
        std::is_same_v<decltype(std::declval<authkey>().weight), uint16_t>
    );

    require_auth(account);
    authorities db(_self, account.value);
    auto auth = db.get_or_default();

    check( auth.keys.size() + 1 <= (1 << 16), "too many authority keys" );
    check( key.weight != 0, "key weight can't be zero" );
    check( key.keyid.empty() == false, "keyid mast nopt be empty" );
    for (const auto& k : auth.keys) {
        check( k.key_name != key.key_name, "key already exists" );
        check( k.key != key.key, "key already exists" );
    }

    auth.keys.push_back(std::move(key));
    db.set(auth, account);
}

void row::removekey(name account, name key_name)
{
    require_auth(account);
    authorities db(_self, account.value);
    check( db.exists(), "account permission authority doesn't exist" );
    auto auth = db.get();

    auto it = auth.keys.end();
    uint32_t weights = 0;
    for ( auto eit = auth.keys.begin(); eit != auth.keys.end(); ++eit ) {
        if ( it->key_name == key_name ) {
            it = eit;
        }
        else {
            weights += eit->weight;
        }
    }

    check( it != auth.keys.end(), "key doesn't exist" );
    auth.keys.erase(it);
    if ( auth.keys.empty() ) {
        db.remove();
    }
    else {
        if ( auth.threshold > weights ) {
            auth.threshold = weights;
        }
        db.set(auth, key_name);
    }
}

void row::sethreshold(name account, uint32_t threshold)
{
    require_auth(account);
    check( threshold != 0, "threshold can't be zero" );

    authorities db(_self, account.value);
    auto auth = db.get_or_default();
    const auto weights = std::accumulate( auth.keys.begin(), auth.keys.end(), 0UL,
    [](const auto result, const auto& a){
        return result + a.weight;
    });
    check( threshold <= weights, "invalid threshold" );

    auth.threshold = threshold;
    db.set(auth, account);
}

[[eosio::action]] void row::hi(name nm)
{
    require_auth(nm);
    print_f("Name : %\n", nm);
}

