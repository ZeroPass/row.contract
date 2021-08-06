#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include <eosio/check.hpp>
#include <eosio/crypto.hpp>

#include "types.hpp"

#ifdef ROW_RSA_ENABLED
#include "base64.hpp"

namespace details {
    extern "C" {
        #include "powm.h"
        struct __attribute__((aligned (16))) capi_checksum256 { uint8_t hash[32]; };

        __attribute__((eosio_wasm_import))
        void sha256( const char* data, uint32_t length, capi_checksum256* hash );
    }

    constexpr auto sha256_digest_info_prefix = std::array<byte_t, 19> {
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };
    constexpr size_t pkcs1_v1_5_t_sha256_size = sha256_digest_info_prefix.size() + sizeof(eosio::checksum256);
    static_assert( pkcs1_v1_5_t_sha256_size == 51 );
}
#endif //ROW_RSA_ENABLED

struct rsa_public_key {
    bytes modulus;
    bytes exponent;
};

inline bool operator == (const rsa_public_key & lkey, const rsa_public_key& rkey) {
    return lkey.exponent == lkey.exponent && lkey.modulus == rkey.modulus;
}

inline bool operator != (const rsa_public_key & lkey, const rsa_public_key& rkey) {
    return !( lkey == rkey );
}

struct rsa_public_key_view {
    const bytes_view modulus;
    const bytes_view exponent;

    constexpr rsa_public_key_view( const bytes_view& mod,
        const bytes_view& exp ) :
        modulus( mod ),
        exponent( exp )
    {}

    constexpr rsa_public_key_view( const rsa_public_key& rsa_pub_key ) :
        modulus( rsa_pub_key.modulus ),
        exponent( rsa_pub_key.exponent )
    {}
};

inline bool operator == (const rsa_public_key_view & lkey, const rsa_public_key_view& rkey) {
    return lkey.exponent == rkey.exponent && lkey.modulus == rkey.modulus;
}

inline bool operator != (const rsa_public_key_view & lkey, const rsa_public_key_view& rkey) {
    return !( lkey == rkey );
}

using ecc_public_key = bytes;
using dsa_public_key = std::variant<ecc_public_key, rsa_public_key>;

struct wa_public_key {
    /**
     * The DSA public key
     */
    dsa_public_key pubkey;

    bool is_ecc() const
    {
        return std::holds_alternative<ecc_public_key>( pubkey );
    }

    bool is_rsa() const
    {
        return std::holds_alternative<rsa_public_key>( pubkey );
    }

    eosio::webauthn_public_key::user_presence_t user_presence;

    std::string rpid;

    friend bool operator == ( const wa_public_key& a, const wa_public_key& b ) {
        return std::tie( a.pubkey, a.user_presence, a.rpid ) == std::tie( b.pubkey, b.user_presence, b.rpid );
    }

    friend bool operator != ( const wa_public_key& a, const wa_public_key& b ) {
        return std::tie( a.pubkey, a.user_presence, a.rpid ) != std::tie( b.pubkey, b.user_presence, b.rpid );
    }
};

struct wa_signature {
    /**
     * The ECC signature data
     */
    bytes signature;

    /**
     * The Encoded Authenticator Data returned from WebAuthN ceremony
     * @see https://w3c.github.io/webauthn/#sctn-authenticator-data
     */
    std::vector<uint8_t> auth_data;

    /**
     * the JSON encoded Collected Client Data from a WebAuthN ceremony
     * @see https://w3c.github.io/webauthn/#dictdef-collectedclientdata
     */
    std::string client_json;
};

#ifdef ROW_RSA_ENABLED
static int powm(const char* base, uint32_t base_len,
                const char* exponent,  uint32_t exponent_len,
                const char* modulus,   uint32_t modulus_len,
                char* out,  uint32_t out_len)
{
    eosio::check( base_len && modulus_len && exponent_len && modulus_len,
        "__powm error, at least 1 param has an invalid length"
    );

    eosio::check( base_len == modulus_len,
        "__powm error, base_len and modulus_len are not the same size"
    );

    if ( out_len == 0 ) return modulus_len;

    details::key_prop* prop;
    eosio::check(
        rsa_gen_key_prop( (const uint8_t*)modulus, modulus_len, (const uint8_t*)exponent, exponent_len, &prop ) == 0,
        "powm error, rsa_gen_key_prop failed"
    );
    auto res = rsa_mod_exp_sw( (const uint8_t*)base, base_len, prop, (uint8_t *)out );
    rsa_free_key_prop( prop );

    //TODO: pad output, see below
    return res == 0 ? modulus_len : 0;
}

/**
* Returns result of modular exponentiation.
* @note intrinsic __powm
* @param base     - base
* @param exponent - exponent
* @param modulus  - modulus
*
* @return result, the size of vector is the same as modulus
*/
 [[nodiscard]] inline bytes powm( const bytes_view& base, const bytes_view& exponent, const bytes_view& modulus ) {
    bytes result( modulus.size() );
    [[maybe_unused]]auto res_size = powm(
        (const char*)base.data(), base.size(),
        (const char*)exponent.data(), exponent.size(),
        (const char*)modulus.data(), modulus.size(),
        (char*)result.data(), result.size()
    );
    //TODO: res_size could be negative meaning error, verify there is no error
    return result;
}

[[nodiscard]] inline bytes rsavp1(const rsa_public_key_view& rsa_pub_key, const bytes_view& signature) {
    // Note: Missing check for signature representative, an integer between 0 and n - 1
    return powm( signature, rsa_pub_key.exponent, rsa_pub_key.modulus );
}

template<size_t t_len, typename Lambda>
bool rsassa_pkcs1_v1_5_verify(const rsa_public_key_view& rsa_pub_key, const bytes_view& signature, Lambda&& gen_t)
{
    if ( signature.size() != rsa_pub_key.modulus.size() ) {
        eosio::print( "[ERROR] rsassa_pkcs1_v1_5_verify: invalid signature" );
        return false;
    }

    const auto em = rsavp1( rsa_pub_key, signature );
    if ( em.size() < t_len + 11 ) {
        eosio::print( "[ERROR] rsassa_pkcs1_v1_5_verify: intended encoded message length too short" );
        return false;
    }

    // Construct EM' = 0x00 || 0x01 || PS || 0x00 || T
    // https://tools.ietf.org/html/rfc3447#section-9.2
    byte_t em_[em.size()];
    em_[0] = 0x00;
    em_[1] = 0x01;

    const auto ps_len = em.size() - t_len - 3;
    memset( &em_[2], 0xff, ps_len );

    em_[2 + ps_len] = 0x00;
    gen_t( span<byte_t>{ &em_[ 3 + ps_len ], t_len });

    return memcmp( em_, em.data(), em.size() ) == 0;
}

// T generator - https://tools.ietf.org/html/rfc3447#section-9.2
// @param put_hash - function should calculate hash and put the calculated digest to the buffer pointed to by it's argument
template<std::size_t S, typename Lambda>
inline void rsa_1_5_t_generator(span<byte_t>& t, const std::array<byte_t, S> digest_info_prefix, Lambda&& put_hash)
{
    memcpy( t.data(), digest_info_prefix.data(), digest_info_prefix.size() );
    put_hash( &t[digest_info_prefix.size()] );
}

/**
* Verifies a RSA PKCS1 v1.5 signed message
* @note function uses intrinsic __powm to decrypt signature.
*       The decrypted signature is verified in contract following the RFC8017 spec.
*       https://tools.ietf.org/html/rfc8017#section-8.2.2
*
* @param rsa_pub_key - RSA public
* @param message     - message buffer to verify
* @param signature   - signature
*
* @return false if verification has failed, true if succeeds
*/
bool verify_rsa_sha256(const rsa_public_key_view& rsa_pub_key, const bytes_view& message, const bytes_view& signature) {
    return rsassa_pkcs1_v1_5_verify<details::pkcs1_v1_5_t_sha256_size>( rsa_pub_key, signature, [&](span<byte_t>&& t) {
        rsa_1_5_t_generator( t, details::sha256_digest_info_prefix, [&]( byte_t* out_hash ){
            details::sha256( (const char*)message.data(), message.size(),
                reinterpret_cast<details::capi_checksum256*>( out_hash )
            );
        });
    });
}
#endif //ROW_RSA_ENABLED


// Verifies digital signature generated
inline bool verify_wa_signature(const wa_public_key& wa_pubkey, const eosio::checksum256& digest, const wa_signature& signature)
{
    if (wa_pubkey.is_ecc()) {
        eosio::check( signature.signature.size() == sizeof( eosio::ecc_signature ), "invalid signature size" );
        eosio::ecc_signature ecc_sig;
        std::copy_n( signature.signature.begin(), ecc_sig.size(), ecc_sig.begin() );
        eosio::webauthn_signature wa_sig {
            std::move( ecc_sig ),
            signature.auth_data,
            signature.client_json
        };

        const ecc_public_key& raw_ecc_pubkey = std::get<ecc_public_key>( wa_pubkey.pubkey );
        eosio::check( raw_ecc_pubkey.size() == sizeof( eosio::ecc_public_key ), "invalid public key size" );

        eosio::ecc_public_key ecc_pubkey;
        std::copy_n( raw_ecc_pubkey.begin(), ecc_pubkey.size(), ecc_pubkey.begin() );
        eosio::webauthn_public_key wa_ecc_pubkey {
            std::move( ecc_pubkey ),
            wa_pubkey.user_presence,
            wa_pubkey.rpid
        };

        auto pubkey = eosio::recover_key( digest, wa_sig );
        return pubkey == eosio::public_key( std::move( wa_ecc_pubkey ));
    }
#ifdef ROW_RSA_ENABLED
    else {
        constexpr static size_t min_auth_data_size = 37;
        static_assert( min_auth_data_size >= sizeof( eosio::checksum256 ), "auth_data min size not enough to store a sha256");
        eosio::check( signature.auth_data.size() >= min_auth_data_size, "auth_data not as large as required" );
        eosio::check( signature.client_json.find("\"type\":\"webauthn.get\"") != std::string::npos, "webauthn signature type not an assertion" );

        // Verify challenge
        using namespace std::string_view_literals;

        constexpr auto challenge_prefix = "\"challenge\":\""sv;
        auto challenge_start = signature.client_json.find( challenge_prefix ) + challenge_prefix.size();
        auto challenge_end   = signature.client_json.find( "\"", challenge_start );
        eosio::check( challenge_start != std::string::npos && challenge_start != challenge_end,
            "missing or corrupted webauthn signature.client_json.challenge"
        );
        auto b64_challenge = std::string_view{ signature.client_json }
            .substr( challenge_start, challenge_end - challenge_start );

        auto challenge = base64url_decode(b64_challenge);
        eosio::check( challenge.has_value(), "invalid base64 signature.client_json.challenge" );
        auto hash = digest.extract_as_byte_array();
        eosio::check(
            challenge.value().size() == hash.size()
            && std::equal( hash.begin(), hash.end(), challenge.value().begin() ),
            "wrong webauthn challenge"
        );

        //TODO:   auto rpid  = signature.client_json.origin.hostname;
        //        eosio::check( memcmp(c.auth_data.data(), fc::sha256::hash(rpid).data(), sizeof(eosio::checksum256)) == 0, "webauthn rpid hash doesn't match origin");

        using user_presence_t = eosio::webauthn_public_key::user_presence_t;
        auto user_verification = user_presence_t::USER_PRESENCE_NONE;
        constexpr static auto add_user_presence_flag = [](user_presence_t& b, user_presence_t f){
            using UT = std::underlying_type_t<user_presence_t>;
            b = static_cast<user_presence_t>( static_cast<UT>(b) | static_cast<UT>(f) );
        };

        if ( signature.auth_data[32] & 0x01 )
            add_user_presence_flag( user_verification, user_presence_t::USER_PRESENCE_PRESENT );
        if ( signature.auth_data[32] & 0x04 )
            add_user_presence_flag( user_verification, user_presence_t::USER_PRESENCE_VERIFIED );
        // TODO: require user presence.

        auto client_data_hash = eosio::sha256(
            signature.client_json.data(),
            signature.client_json.size()
        ).extract_as_byte_array();

        bytes signed_data;
        signed_data.resize( signature.auth_data.size() + client_data_hash.size() );
        auto sdit = std::copy( signature.auth_data.begin(), signature.auth_data.end(), signed_data.begin() );
        sdit = std::copy( client_data_hash.begin(), client_data_hash.end(), sdit );
        return verify_rsa_sha256( std::get<rsa_public_key>(wa_pubkey.pubkey), signed_data, signature.signature );
    }
#endif //ROW_RSA_ENABLED
    return false;
}

// Asserts that disital signature is valid
inline void assert_wa_signature(const wa_public_key& wa_pubkey, const eosio::checksum256& digest, const wa_signature& signature, const char* error) {
    eosio::check( verify_wa_signature( wa_pubkey, digest, signature ), error );
}