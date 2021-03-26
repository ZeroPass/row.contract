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

bool is_tx_authorized(const std::vector<char>& packed_tx, const std::vector<permission_level>& permissions) {
    auto packed_permissions = pack(permissions);
    return check_transaction_authorization(
        packed_tx.data(), packed_tx.size(),
        (const char*)0, 0,
        packed_permissions.data(), packed_permissions.size()
    );
}

decltype(row::authority::threshold) get_approval_weights(const row::authority& auth, const std::vector<name>& approvals)
{
    decltype(auth.threshold) weights = 0;
    for (const auto key_name : approvals) {
        auto it = std::find_if(auth.keys.begin(), auth.keys.end(), [key_name](const auto& k) { return k.key_name == key_name; });
        check( it != auth.keys.end(), "invalid auth key name in the list" );
        weights += it->weight;
    }
    return weights;
}

bool is_tx_authorized(const std::vector<char>& packed_tx, const std::vector<permission_level>& permissions, const row::authority& auth, const std::vector<name>& approvals) {
    if (is_tx_authorized( packed_tx, permissions )) {
        return get_approval_weights(auth, approvals) >= auth.threshold;
    }
    return false;
}

std::vector<permission_level> get_default_permissions(name account) {
    return std::vector{permission_level{ account, "active"_n }};
}


void row::propose(name account, name proposal_name, std::vector<name> requested_approvals, ignore<transaction> tx)
{
    require_auth(account);
    check( account != _self, "I can't make proposal by myself" );
    authorities authdb(_self, account.value);
    check( authdb.exists(), "account permission authority doesn't exist" );

    auto& ds = get_datastream();
    const char*  tx_pos  = ds.pos();
    const size_t tx_size = ds.remaining();

    transaction_header tx_header;
    ds >> tx_header;
    check( tx_header.expiration >= eosio::time_point_sec(current_time_point()), "transaction has expired" );

    std::vector<action> ctx_free_actions;
    ds >> ctx_free_actions;
    check( ctx_free_actions.empty(), "not allowed to `propose` a transaction with context-free actions" );

    proposals proptable( get_self(), account.value );
    check( proptable.find( proposal_name.value ) == proptable.end(), "proposal with the same name exists" );

    std::vector<char> raw_tx;
    raw_tx.resize(tx_size);
    memcpy((char*)raw_tx.data(), tx_pos, tx_size);
    check( is_tx_authorized( raw_tx, get_default_permissions(account) ), "transaction authorization failed" );

    proptable.emplace( account, [&]( auto& p ) {
        p.proposal_name      = proposal_name;
        p.create_time        = current_time_point();
        p.packed_transaction = raw_tx;
        p.earliest_exec_time = std::optional<time_point>{};
    });

    auto auth = authdb.get();
    const auto weights = get_approval_weights( auth, requested_approvals );
    check( weights >= auth.threshold, "requested approvals don't overweight threshold" );

    approvals appdb( get_self(), account.value );
    appdb.emplace( account, [&]( auto& a ) {
        a.proposal_name       = proposal_name;
        a.requested_approvals = std::move(requested_approvals);
    });
}

void row::approve(name account, name proposal_name, name key_name, const signature& signature)
{
    require_auth(account);

    authorities authdb(_self, account.value);
    check( authdb.exists(), "account permission authority doesn't exist" );

    proposals proptable( get_self(), account.value );
    auto& proposal = proptable.get( proposal_name.value, "proposal not found" );

    approvals appdb( get_self(), account.value );
    auto& app = appdb.get( proposal_name.value, "approvals not found" );

    auto itreq = std::find( app.requested_approvals.begin(), app.requested_approvals.end(), key_name );
    check( itreq != app.requested_approvals.end(), "approval is not on the list of requested approvals" );

    auto itapp = std::find(app.provided_approvals.begin(), app.provided_approvals.end(), key_name );
    check( itapp == app.provided_approvals.end(), "already in the list of approvals" );

    auto auth = authdb.get();
    auto itkey = std::find_if(auth.keys.begin(), auth.keys.end(), [key_name](const auto& k) { return k.key_name == key_name; });
    check( itkey != auth.keys.end(), "missing authority key for provided approval" );
    check( (proposal.create_time + seconds(itkey->wait_sec.value_or(0U))) < current_time_point(), "approval doesn't satisfy reqired wait time" );
    assert_recover_key( sha256(proposal.packed_transaction.data(), proposal.packed_transaction.size()), signature, itkey->key );

    appdb.modify( app, account, [&]( auto& a ) {
        a.provided_approvals.push_back( key_name );
        a.requested_approvals.erase( itreq );
    });

    // set execution delay to time of first approval + transaction delay
    transaction_header tx_header = unpack<transaction_header>( proposal.packed_transaction );//get_trx_header(proposal.packed_transaction.data(), proposal.packed_transaction.size());
    if ( !proposal.earliest_exec_time.has_value() ) {
        if ( is_tx_authorized( proposal.packed_transaction, get_default_permissions(account), auth, app.provided_approvals )) {
            proptable.modify( proposal, account, [&]( auto& p ) {
                p.earliest_exec_time = std::optional<time_point>{ current_time_point() + eosio::seconds(tx_header.delay_sec.value)};
            });
        }
    }
}

void row::cancel(name account, name proposal_name)
{
    require_auth(account);

    proposals proptable( get_self(), account.value );
    auto& prop = proptable.get( proposal_name.value, "proposal not found" );
    proptable.erase(prop);

    approvals appdb( get_self(), account.value );
    auto& app = appdb.get( proposal_name.value, "proposal not found" );
    appdb.erase(app);
}

void row::exec(name account, name proposal_name)
{
    require_auth( account );
    authorities authdb(_self, account.value);
    check( authdb.exists(), "account permission authority doesn't exist" );
    auto auth = authdb.get();

    proposals proptable( get_self(), account.value );
    auto& proposal = proptable.get( proposal_name.value, "proposal not found" );

    datastream<const char*> ds = { proposal.packed_transaction.data(), proposal.packed_transaction.size() };
    transaction_header tx_header;
    ds >> tx_header;
    check( tx_header.expiration >= eosio::time_point_sec(current_time_point()), "transaction expired" );

    std::vector<action> ctx_free_actions;
    ds >> ctx_free_actions;
    check( ctx_free_actions.empty(), "not allowed to `exec` a transaction with context-free actions" );

    std::vector<action> actions;
    ds >> actions;

    approvals appdb( get_self(), account.value );
    auto& app = appdb.get( proposal_name.value, "approvals not found" );
    bool has_auth = is_tx_authorized( proposal.packed_transaction, get_default_permissions(account), auth, app.provided_approvals );
    check( has_auth, "transaction authorization failed" );

    check( proposal.earliest_exec_time.value_or(proposal.create_time + eosio::seconds(tx_header.delay_sec.value)) <= current_time_point(), "too early to execute" );
    for (const auto& a : actions) {
        a.send();
    }

    proptable.erase(proposal);
    appdb.erase(app);
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
    authorities authdb(_self, account.value);
    auto auth = authdb.get_or_default();

    check( auth.keys.size() + 1 <= (1 << 16), "too many authority keys" );
    check( key.weight != 0, "key weight can't be zero" );
    check( key.keyid.empty() == false, "keyid mast nopt be empty" );
    for (const auto& k : auth.keys) {
        check( k.key_name != key.key_name, "key already exists" );
        check( k.key != key.key, "key already exists" );
    }

    auth.keys.push_back(std::move(key));
    authdb.set(auth, account);
}

void row::removekey(name account, name key_name)
{
    require_auth(account);
    authorities authdb(_self, account.value);
    check( authdb.exists(), "account permission authority doesn't exist" );
    auto auth = authdb.get();

    auto it = auth.keys.end();
    uint32_t weights = 0;
    for ( auto eit = auth.keys.begin(); eit != auth.keys.end(); ++eit ) {
        if ( eit->key_name == key_name ) {
            it = eit;
        }
        else {
            weights += eit->weight;
        }
    }

    check( it != auth.keys.end(), "key doesn't exist" );
    auth.keys.erase(it);
    if ( auth.keys.empty() ) {
        authdb.remove();
    }
    else {
        if ( auth.threshold > weights ) {
            auth.threshold = weights;
        }
        authdb.set(auth, account);
    }
}

void row::sethreshold(name account, uint32_t threshold)
{
    require_auth(account);
    check( threshold != 0, "threshold can't be zero" );

    authorities authdb(_self, account.value);
    auto auth = authdb.get_or_default();
    const auto weights = std::accumulate( auth.keys.begin(), auth.keys.end(), 0UL,
    [](const auto result, const auto& a){
        return result + a.weight;
    });
    check( threshold <= weights, "invalid threshold" );

    auth.threshold = threshold;
    authdb.set(auth, account);
}

[[eosio::action]] void row::hi(name nm)
{
    require_auth(nm);
    print_f("Name : %\n", nm);
}