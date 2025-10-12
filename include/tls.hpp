#ifndef TLS_HPP
#define TLS_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <algorithm>
#include <array>
#include <expected>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <ranges>
#include <regex>
#include <span>
#include <string>
#include <sstream>
#include <variant>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <crypto.hpp>
#include <tcp.hpp>
#include <utils.hpp>

namespace ntk {

    // ===============
    //  TLS Extension 
    // ===============   

    enum class tls_extension_type : uint16_t {
        application_layer_protocol_negotiation = 0x0010,
        delegated_credential                   = 0x0022,
        ec_point_formats                       = 0x000b,
        extended_main_secret                   = 0x0017,
        pre_shared_key                         = 0x0029,
        psk_key_exchange_modes                 = 0x002d,
        renegotiation_info                     = 0xff01,
        server_name                            = 0x0000,
        status_request                         = 0x0005,
        signature_algorithms                   = 0x000d,
        supported_groups                       = 0x000a,
        supported_versions                     = 0x002b,
        key_share                              = 0x0033,
        record_size_limit                      = 0x001c
    };

    struct tls_extension {
        std::optional<tls_extension_type> type;
        uint16_t raw_type;
        std::vector<uint8_t> value;
    };

    static const std::unordered_map<tls_extension_type,std::string> tls_extension_type_names = {
        { tls_extension_type::application_layer_protocol_negotiation,   "alpn" },
        { tls_extension_type::delegated_credential,     "delegated_credential" },
        { tls_extension_type::ec_point_formats,             "ec_point_formats" },
        { tls_extension_type::extended_main_secret,     "extended_main_secret" },
        { tls_extension_type::pre_shared_key,                 "pre_shared_key" },
        { tls_extension_type::psk_key_exchange_modes, "psk_key_exchange_modes" },
        { tls_extension_type::renegotiation_info,         "renegotiation_info" },
        { tls_extension_type::server_name,                       "server_name" },
        { tls_extension_type::signature_algorithms,     "signature_algorithms" },
        { tls_extension_type::status_request,                 "status_request" },
        { tls_extension_type::supported_groups,             "supported_groups" },
        { tls_extension_type::supported_versions,         "supported_versions" },
        { tls_extension_type::key_share,                           "key_share" },
        { tls_extension_type::record_size_limit,            "record_size_limit"}
    };

    constexpr std::array<tls_extension_type,14> default_tls_extensions = {
        tls_extension_type::application_layer_protocol_negotiation,
        tls_extension_type::delegated_credential,
        tls_extension_type::ec_point_formats,
        tls_extension_type::extended_main_secret,
        tls_extension_type::pre_shared_key,
        tls_extension_type::psk_key_exchange_modes,
        tls_extension_type::renegotiation_info,
        tls_extension_type::server_name,
        tls_extension_type::status_request,
        tls_extension_type::signature_algorithms,
        tls_extension_type::supported_groups,
        tls_extension_type::supported_versions,
        tls_extension_type::key_share,
        tls_extension_type::record_size_limit
    };

    namespace look_up {

    constexpr std::array<tls_extension_type,14/* entries in enum tls_extension_type */> tls_extensions = {
        tls_extension_type::application_layer_protocol_negotiation,
        tls_extension_type::delegated_credential,
        tls_extension_type::ec_point_formats,
        tls_extension_type::extended_main_secret,
        tls_extension_type::pre_shared_key,
        tls_extension_type::psk_key_exchange_modes,
        tls_extension_type::renegotiation_info,
        tls_extension_type::server_name,
        tls_extension_type::status_request,
        tls_extension_type::signature_algorithms,
        tls_extension_type::supported_groups,
        tls_extension_type::supported_versions,
        tls_extension_type::key_share,
        tls_extension_type::record_size_limit
    };

    } // namespace look_up

    inline auto get_tls_extension_type = make_lookup( look_up::tls_extensions );

    // ======================
    //  Delegated Credential 
    // ======================

    enum signature_algorithm {
        ecdsa_sha1             = 0x0203,
        ecdsa_secp256r1_sha256 = 0x0403,
        ecdsa_secp384r1_sha384 = 0x0503,
        ecdsa_secp521r1_sha512 = 0x0603,
        rsa_pss_rsae_sha256    = 0x0804,
        rsa_pss_rsae_sha384    = 0x0805,
        rsa_pss_rsae_sha512    = 0x0806,
        rsa_pkcs1_sha256       = 0x0401,
        rsa_pkcs1_sha384       = 0x0501,
        rsa_pkcs1_sha512       = 0x0601,
        rsa_pkcs1_sha1         = 0x0201
    };

    namespace look_up {

    constexpr std::array<signature_algorithm,11/* entires in enum named_group */> signature_algorithms = {
        signature_algorithm::ecdsa_sha1,
        signature_algorithm::ecdsa_secp256r1_sha256,
        signature_algorithm::ecdsa_secp384r1_sha384,
        signature_algorithm::ecdsa_secp521r1_sha512,
        signature_algorithm::rsa_pss_rsae_sha256,
        signature_algorithm::rsa_pss_rsae_sha384,
        signature_algorithm::rsa_pss_rsae_sha512,
        signature_algorithm::rsa_pkcs1_sha256,
        signature_algorithm::rsa_pkcs1_sha384,
        signature_algorithm::rsa_pkcs1_sha512,
        signature_algorithm::rsa_pkcs1_sha1 
    };

    } // namespace look_up

    inline auto get_tls_signature_algorithm = make_lookup( look_up::signature_algorithms );

    inline std::unordered_map<signature_algorithm,std::string> signature_algorithm_names = {
        { signature_algorithm::ecdsa_sha1,                         "ecdsa_sha1" },
        { signature_algorithm::ecdsa_secp256r1_sha256, "ecdsa_secp256r1_sha256" },
        { signature_algorithm::ecdsa_secp384r1_sha384, "ecdsa_secp384r1_sha384" },
        { signature_algorithm::ecdsa_secp521r1_sha512, "ecdsa_secp521r1_sha512" },
        { signature_algorithm::rsa_pss_rsae_sha256,       "rsa_pss_rsae_sha256" },
        { signature_algorithm::rsa_pss_rsae_sha384,       "rsa_pss_rsae_sha384" },
        { signature_algorithm::rsa_pss_rsae_sha512,       "rsa_pss_rsae_sha512" },
        { signature_algorithm::rsa_pkcs1_sha256,             "rsa_pkcs1_sha256" },
        { signature_algorithm::rsa_pkcs1_sha384,             "rsa_pkcs1_sha384" },
        { signature_algorithm::rsa_pkcs1_sha512,             "rsa_pkcs1_sha512" },
        { signature_algorithm::rsa_pkcs1_sha1,                 "rsa_pkcs1_sha1" }
    };

    constexpr std::array<signature_algorithm,4> default_delegated_credential_signature_algorithms = {
        signature_algorithm::ecdsa_sha1,
        signature_algorithm::ecdsa_secp256r1_sha256,
        signature_algorithm::ecdsa_secp384r1_sha384,
        signature_algorithm::ecdsa_secp521r1_sha512
    };

    constexpr std::array<signature_algorithm,11> default_signature_algorithms = {
        signature_algorithm::ecdsa_sha1,
        signature_algorithm::ecdsa_secp256r1_sha256,
        signature_algorithm::ecdsa_secp384r1_sha384,
        signature_algorithm::ecdsa_secp521r1_sha512,
        signature_algorithm::rsa_pss_rsae_sha256,
        signature_algorithm::rsa_pss_rsae_sha384,
        signature_algorithm::rsa_pss_rsae_sha512,
        signature_algorithm::rsa_pkcs1_sha256,
        signature_algorithm::rsa_pkcs1_sha384,
        signature_algorithm::rsa_pkcs1_sha512,
        signature_algorithm::rsa_pkcs1_sha1  
    };

    std::expected<std::vector<signature_algorithm>,std::string> parse_signature_algorithms( std::span<const uint8_t> signature_algorithms_bytes );

    std::expected<std::vector<signature_algorithm>,std::string> parse_client_hello_delegated_credential( std::span<const uint8_t> dedicated_credential_bytes );

    struct delegated_credential {
        uint32_t valid_time;              
        uint16_t expected_verify_algorithm;    
        std::vector<uint8_t> credential;      
        std::vector<uint8_t> signature; 
    };

    // =================
    //  Key Share Entry 
    // =================

    struct key_share_entry {
        uint16_t group;
        std::vector<uint8_t> key_data;

        bool operator==( const key_share_entry& other ) const {
            return group == other.group;
        }
    };

    enum named_group : uint16_t {
        ffdhe2048 = 0x0100,
        ffdhe3072 = 0x0101,
        secp256r1 = 0x0017,
        secp384r1 = 0x0018,
        secp521r1 = 0x0019,
        x25519    = 0x001d,
    };

    namespace look_up {

    constexpr std::array<named_group,6/* entires in enum named_group */> named_groups = {
        named_group::ffdhe2048,
        named_group::ffdhe3072,
        named_group::secp256r1,
        named_group::secp384r1,
        named_group::secp521r1,
        named_group::x25519
    };

    } // namespace look_up

    inline auto get_tls_named_group = make_lookup( look_up::named_groups );

    inline std::unordered_map<named_group,std::string> named_group_names = {
        { named_group::ffdhe2048, "ffdhe2048" },
        { named_group::ffdhe3072, "ffdhe3072" },
        { named_group::secp256r1, "secp256r1" },
        { named_group::secp384r1, "secp384r1" },
        { named_group::secp521r1, "secp521r1" },
        { named_group::x25519,       "x25519" }
    };

    constexpr std::array<named_group,2> default_key_share_groups {
        named_group::secp256r1,
        named_group::x25519
    };

    constexpr std::array<named_group,6> default_supported_groups {
        named_group::ffdhe2048,
        named_group::ffdhe3072,
        named_group::secp256r1,
        named_group::secp384r1,
        named_group::secp521r1,
        named_group::x25519
    };

    constexpr std::array<std::string,2> default_alpn = {
        "h2",
        "http/1.1"
    };

    std::expected<std::vector<std::string>,std::string> parse_client_hello_alpn( std::span<const uint8_t> alpn_bytes );

    std::expected<std::vector<key_share_entry>,std::string> parse_key_share_entries( std::span<const uint8_t> key_share_entries_bytes );

    std::expected<std::vector<named_group>,std::string> parse_supported_groups( std::span<const uint8_t> supported_groups_bytes );

    // =============
    //  TLS Version 
    // =============

    enum class tls_version : uint16_t {
        tls_1_0 = 0x0301,
        tls_1_2 = 0x0303,
        tls_1_3 = 0x0304
    };

    static const std::unordered_map<tls_version,std::string> tls_version_names = {
        { tls_version::tls_1_0, "Version 1.0" },
        { tls_version::tls_1_2, "Version 1.2" },
        { tls_version::tls_1_3, "Version 1.3" }
    };

    namespace look_up {

        constexpr std::array<tls_version,3/* entries in enum tls_version */> tls_versions = {
            tls_version::tls_1_0,
            tls_version::tls_1_2,
            tls_version::tls_1_3
        };

    } // namespace look_up

    constexpr std::array<tls_version,2> default_supported_versions = { 
        tls_version::tls_1_2,
        tls_version::tls_1_3
    };

    inline auto get_tls_version = make_lookup( look_up::tls_versions );

    std::expected<std::vector<tls_version>,std::string> parse_supported_versions( std::span<const uint8_t> supported_versions_bytes );

    // ===============
    //  Cipher Suites 
    // ===============

    enum class cipher_suite : uint16_t {
        TLS_RSA_WITH_AES_128_CBC_SHA                  = 0x002f,
        TLS_RSA_WITH_AES_256_CBC_SHA                  = 0x0035,
        TLS_RSA_WITH_AES_128_GCM_SHA256               = 0x009c,
        TLS_RSA_WITH_AES_256_GCM_SHA384               = 0x009d,
        TLS_AES_128_GCM_SHA256                        = 0x1301,
        TLS_AES_256_GCM_SHA384                        = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256                  = 0x1303,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = 0xc02b,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = 0xc009,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = 0xc00a,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = 0xc013,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = 0xc014,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = 0xc02c,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = 0xc02f,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = 0xc030,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xcca8,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9
    };

    static const std::unordered_map<cipher_suite,std::string> tls_cipher_suite_names = {
        { cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA,                                   "TLS_RSA_WITH_AES_128_CBC_SHA" },
        { cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA,                                   "TLS_RSA_WITH_AES_256_CBC_SHA" },
        { cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256,                             "TLS_RSA_WITH_AES_128_GCM_SHA256" },
        { cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384,                             "TLS_RSA_WITH_AES_256_GCM_SHA384" },
        { cipher_suite::TLS_AES_128_GCM_SHA256,                                               "TLS_AES_128_GCM_SHA256" },
        { cipher_suite::TLS_AES_256_GCM_SHA384,                                               "TLS_AES_256_GCM_SHA384" },
        { cipher_suite::TLS_CHACHA20_POLY1305_SHA256,                                   "TLS_CHACHA20_POLY1305_SHA256" },
        { cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,             "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
        { cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,                   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
        { cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,                   "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
        { cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,                       "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
        { cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,                       "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
        { cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,             "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
        { cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
        { cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,                 "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
        { cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,     "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
        { cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" }
    };

    namespace look_up {

    constexpr std::array<cipher_suite,17> cipher_suites = {
        cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA,                  
        cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA,                  
        cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256,               
        cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384,               
        cipher_suite::TLS_AES_128_GCM_SHA256,                        
        cipher_suite::TLS_AES_256_GCM_SHA384,                        
        cipher_suite::TLS_CHACHA20_POLY1305_SHA256,                  
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,          
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,          
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 
    };

    } // namespace look_up

    constexpr std::array<cipher_suite,17> default_cipher_suites = {
        cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA,                  
        cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA,                  
        cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256,               
        cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384,               
        cipher_suite::TLS_AES_128_GCM_SHA256,                        
        cipher_suite::TLS_AES_256_GCM_SHA384,                        
        cipher_suite::TLS_CHACHA20_POLY1305_SHA256,                  
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,          
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,          
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 
    };

    inline auto get_cipher_suite = make_lookup( look_up::cipher_suites );

    template <typename T>
    auto make_variant_map( const std::unordered_map<T, std::string>& m ) {
        return std::variant<
            std::unordered_map<signature_algorithm,std::string>,
            std::unordered_map<named_group,std::string>,
            std::unordered_map<tls_version,std::string>
        >( m );
    }

    const std::unordered_map<tls_extension_type,
        std::variant<
            std::unordered_map<signature_algorithm, std::string>,
            std::unordered_map<named_group, std::string>,
            std::unordered_map<tls_version, std::string>
        >
    > tls_extension_map = {
        { tls_extension_type::supported_groups,             make_variant_map( named_group_names ) },
        { tls_extension_type::supported_versions,           make_variant_map( tls_version_names ) },
        { tls_extension_type::signature_algorithms, make_variant_map( signature_algorithm_names ) },
        { tls_extension_type::key_share,                      make_variant_map(named_group_names) }
    };

    // ==================
    //  TLS Content Type 
    // ==================

    enum class tls_content_type : uint8_t {
        change_cipher_spec = 0x14,
        alert,            // 0x15
        handshake,        // 0x16
        application_data  // 0x17
    };

    namespace look_up {

        constexpr std::array<tls_content_type,4/* entries in tls_content_type enum */> tls_content_types {
            tls_content_type::change_cipher_spec,
            tls_content_type::alert,
            tls_content_type::handshake,
            tls_content_type::application_data
        };

    } // namespace look_up

    inline auto get_tls_content_type = make_lookup( look_up::tls_content_types );

    static const std::unordered_map<tls_content_type,std::string> tls_content_type_names = {
        { tls_content_type::change_cipher_spec, "ChangeCipherSpec" },
        { tls_content_type::alert, "Alert" },
        { tls_content_type::handshake, "Handshake" },
        { tls_content_type::application_data, "Application Data" }
    };

    // =============
    //  TLS Context 
    // =============

    struct tls_context {
        std::optional<std::vector<uint8_t>> peer_public_key;
        std::optional<std::vector<uint8_t>> host_public_key; 
        std::optional<std::vector<uint8_t>> host_private_ley;
        std::optional<named_group> negotiated_key_share;
        std::optional<signature_algorithm> negotiatioed_signature_algorithm;
        tls_version negotiated_version;
        cipher_suite negotiated_cipher_suite;
    };

    // =============
    //  TLS Records 
    // =============

    namespace record_header_offset {

        constexpr std::size_t content_type = 0;
        constexpr std::size_t version = 1;
        constexpr std::size_t payload_len = 3;
    
    } // record_header_offset

    struct tls_record {
        tls_content_type content_type;
        tls_version version;
        std::vector<uint8_t> payload;

        bool operator==( const tls_record& other ) const {
            return content_type == other.content_type &&
                version == other.version &&
                payload == other.payload;
        }
    };

    struct tls_record_extraction_result {
        std::vector<tls_record> records;
        bool has_remainder;
    };

    struct incomplete_tls_record {
        tls_record record;
        std::size_t expected_payload_length;
    };

    struct tls_record_header {
        tls_content_type content_type;
        tls_version version;
        uint16_t payload_length;

        bool operator==( const tls_record_header& other ) const {
            return content_type == other.content_type &&
                version == other.version &&
                payload_length == other.payload_length;
        }
    };

    tls_record_extraction_result extract_tls_records( const std::vector<std::vector<uint8_t>>& payloads );

    std::expected<tls_record,std::string> get_tls_record_from_ethernet( std::span<const uint8_t> packet );

    std::expected<tls_record,std::string> get_tls_record_from_payload( std::span<const uint8_t> payload );

    std::variant<tls_record,incomplete_tls_record> append_to_incomplete_record( incomplete_tls_record record, std::span<const uint8_t> packet );

    std::variant<tls_record,incomplete_tls_record> append_to_incomplete_record_from_payload( incomplete_tls_record incomplete_record, std::span<const unsigned char> payload );

    std::expected<std::variant<tls_record,incomplete_tls_record>,std::string> get_complete_or_incomplete_record( std::span<const uint8_t> packet );

    std::expected<std::variant<tls_record,incomplete_tls_record>,std::string> get_complete_or_incomplete_record_from_payload( std::span<const uint8_t> payload );

    std::expected<tls_record,std::string> get_empty_tls_record_from_ethernet( std::span<const uint8_t> packet );

    std::expected<tls_record,std::string> get_empty_tls_record_from_payload( std::span<const uint8_t> payload );

    std::expected<tls_record_header,std::string> get_tls_record_header( const std::array<uint8_t,constants::record_header_len> record_header_bytes );

    std::expected<tls_record_header,std::string> get_tls_record_header_from_ethernet( std::span<const uint8_t> packet );

    std::expected<tls_record_header,std::string> get_tls_record_header_from_payload( std::span<const uint8_t> payload );

    bool is_complete_record( std::span<const unsigned char> record_bytes );

    std::expected<bool,std::string> is_tls( const unsigned char* packet );

    std::expected<bool,std::string> is_tls( std::span<const uint8_t> packet );

    std::expected<bool,std::string> is_tls_payload( const std::span<const uint8_t> payload );

    std::expected<
        std::tuple<std::vector<tls_record>,std::size_t>, 
        std::string
    > split_tls_records( std::span<const uint8_t> tls_payload );

    std::expected<
        std::tuple<std::vector<tls_record>,std::size_t>,
        std::string
    > get_tls_records_from_ethernet( std::span<const uint8_t> packet );

    std::expected<tls_record,std::string> get_parsed_tls_record( std::span<const uint8_t> raw_tls_record );

    std::expected<tls_record,std::string> get_parsed_tls_record_from_ethernet( std::span<const unsigned char> packet );    

    // ====================
    //  TLS Handshake Type 
    // ====================

    enum class tls_handshake_type : uint8_t {
        client_hello  = 0x01,
        server_hello // 0x02
    };

    namespace look_up {

        constexpr std::array<tls_handshake_type,2/* entries in tls_handshake_type enum */> tls_handshake_types = {
            tls_handshake_type::client_hello,
            tls_handshake_type::server_hello
        };

    } // namespace look_up

    inline auto get_tls_handshake_type = make_lookup( look_up::tls_handshake_types );

    // ==============
    //  Client Hello 
    // ==============

    struct client_hello {
        tls_version client_version;
        std::array<uint8_t,32> random;
        std::vector<uint8_t> session_id;
        std::vector<uint8_t> cipher_suites;
        std::vector<uint8_t> compression_methods;
        std::vector<uint8_t> extensions;

        bool operator==( const client_hello& other ) const {
            return client_version == other.client_version &&
                   random == other.random &&
                   session_id == other.session_id &&
                   cipher_suites == other.cipher_suites &&
                   compression_methods == other.compression_methods &&
                   extensions == other.extensions;
        }
    };

    struct client_hello_extensions {
        std::optional<bool> renegotiation_info;
        std::optional<std::vector<named_group>> supported_groups;
        std::optional<std::vector<tls_version>> supported_versions;
        std::optional<std::vector<signature_algorithm>> signature_algorithms;
        std::optional<std::vector<std::string>> alpn;
        std::optional<std::vector<key_share_entry>> key_share_entries;

        bool operator==( const client_hello_extensions& other ) const {
            return renegotiation_info == other.renegotiation_info &&
                   equal_unordered_optional_vec( supported_groups, other.supported_groups ) &&
                   equal_unordered_optional_vec( supported_versions, other.supported_versions ) &&
                   equal_unordered_optional_vec( signature_algorithms, other.signature_algorithms ) &&
                   equal_unordered_optional_vec( alpn, other.alpn ) &&
                   equal_unordered_optional_vec( key_share_entries, other.key_share_entries );
        }
    };

    struct client_hello_info {
        tls_version client_version;
        std::array<uint8_t,32> random;
        std::vector<uint8_t> session_id;
        std::vector<cipher_suite> cipher_suites;
        std::optional<client_hello_extensions> extensions;
    };

    std::expected<client_hello,std::string> parse_client_hello( const std::span<const uint8_t> client_hello_bytes );

    std::expected<std::vector<uint8_t>,std::string> extract_client_hello_cipher_suites( const std::span<const uint8_t> client_hello_bytes,
                                                                                        const std::size_t session_id_len ); 

    std::expected<std::vector<uint8_t>,std::string> extract_client_hello_compression_methods( const std::span<const uint8_t> client_hello_bytes,
                                                                                              const std::size_t compression_methods_len_pos );

    std::expected<client_hello,std::string> get_client_hello( const std::span<const uint8_t> tcp_payload );

    std::expected<client_hello,std::string> get_client_hello( const tls_record& record );

    std::expected<client_hello,std::string> get_client_hello_from_ethernet_frame( const unsigned char* ethernet_frame );

    std::expected<client_hello,std::string> get_client_hello_from_ethernet_frame( std::span<const uint8_t> ethernet_frame );

    std::expected<bool,std::string> is_client_hello( const unsigned char* packet );

    std::expected<bool,std::string> is_client_hello( std::span<const uint8_t> packet );

    bool is_client_hello( const tls_record& record );

    std::expected<client_hello_info,std::string> get_client_hello_info( std::span<const uint8_t> client_hello_bytes );

    std::expected<client_hello_info,std::string> get_client_hello_info_from_ethernet( std::span<const uint8_t> packet );

    std::expected<client_hello_extensions,std::string> parse_client_hello_extensions( std::span<const tls_extension> extensions );

    inline auto client_hello_filter = [] ( const auto& packet ) {
        auto result = is_client_hello( packet );
        return result && result.value();
    };

    // ==============
    //  Server Hello 
    // ==============

    struct server_hello {
        tls_version server_version;
        std::array<uint8_t,32> random;
        std::vector<uint8_t> session_id;
        uint16_t cipher_suite;
        uint8_t compression_method;
        std::vector<uint8_t> extensions;
    };

    std::expected<server_hello,std::string> parse_server_hello( const std::span<const uint8_t> server_hello_bytes );

    std::expected<server_hello,std::string> get_server_hello_from_ethernet( const unsigned char* ethernet_frame );

    std::expected<server_hello,std::string> get_server_hello_from_ethernet( std::span<const uint8_t> ethernet_frame );

    std::expected<server_hello,std::string> get_server_hello( const tls_record& record );

    std::expected<uint16_t,std::string> get_server_hello_cipher_suite( const std::span<const uint8_t>& server_hello_bytes, const std::size_t cipher_suite_pos );

    std::expected<std::vector<uint8_t>,std::string> extract_tls_session_id( const std::span<const uint8_t> handshake_message_bytes );

    std::expected<void,std::string> get_server_hello_extensions( const std::span<const uint8_t>& server_hello_bytes, server_hello s_hello,
                                                                 const std::size_t extensions_len_pos );

    std::expected<std::optional<tls_version>,std::string> get_tls_version_from_handshake_message( const std::span<const uint8_t> handshake_message_bytes );

    std::expected<std::array<uint8_t,constants::random_len>,std::string> extract_handshake_message_random( const std::span<const uint8_t> handshake_message_bytes );

    std::expected<std::vector<uint8_t>,std::string> extract_handshake_message_extensions( const std::span<const uint8_t> handshake_message_bytes,
                                                                                          const std::size_t extensions_len_pos );

    std::expected<bool,std::string> is_server_hello( const unsigned char* packet );

    std::expected<bool,std::string> is_server_hello( const std::vector<uint8_t>& packet );

    bool is_server_hello( const tls_record& record );

    std::expected<std::vector<tls_extension>,std::string> parse_tls_extensions( std::span<const uint8_t> extensions_bytes );

    // =======
    //  Alert 
    // =======

    std::expected<bool,std::string> is_tls_alert( const unsigned char* packet );
    
    std::expected<bool,std::string> is_tls_alert( std::span<const uint8_t> packet );

    bool is_tls_alert( const tls_record& record );

    // ====================
    //  Change Cipher Spec 
    // ====================

    bool is_change_cipher_spec( const tls_record& record );

    // ==================
    //  Application Data 
    // ==================

    bool is_tls_application_data( const tls_record& record );

    // =====
    //  SNI 
    // =====

    std::expected<std::string,std::string> get_sni( const client_hello& hello );

    std::expected<std::string,std::string> parse_sni_list( std::span<const unsigned char>& sni_list );

    std::vector<std::string> get_snis( const session& packets, const std::string& host );

    std::expected<bool,std::string> has_sni( const client_hello& hello, const std::string& host );

    std::expected<bool,std::string> sni_contains( const client_hello& hello, const std::string& host );

    using sni_to_ip = std::map<std::string,uint32_t>;

    sni_to_ip get_sni_to_ip( const session& packets );

    // =============
    //  TLS Secrets 
    // =============

    using session_secrets = std::map<std::string,std::vector<uint8_t>>;
    using secrets = std::map<std::string,session_secrets>;

    secrets get_tls_secrets( const std::string& filename );

    secrets get_tls_secrets( const std::string& filename, std::array<uint8_t,32> client_random );

    std::pair<secrets,std::size_t> get_tls_secrets_dynamically( std::ifstream& file_handle, std::array<uint8_t,32> client_random );

    std::vector<uint8_t> get_traffic_secret( const secrets& session_keys,
                                             const std::array<uint8_t,32>& client_random,
                                             const std::string& label );

    bool is_complete_secrets( const session_secrets& secrets );

    bool secret_labels_are_equal( std::array<std::string,5> lhs, std::array<std::string,5> rhs );

    const std::array<std::string,5> tls_secret_labels = {
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",  
        "EXPORTER_SECRET",
        "SERVER_TRAFFIC_SECRET_0",  
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",  
        "CLIENT_TRAFFIC_SECRET_0"
    };

    // ================
    //  TLS Decryption 
    // ================

    struct tls_key_material {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;
    };

    struct tls_key_block {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> mac_key;
    };

    std::vector<uint8_t> pkcs7_pad( const std::vector<uint8_t>& data, const std::size_t block_size );

    tls_key_material derive_tls_key_iv( const std::vector<uint8_t>& secret, const EVP_MD* hash_func,
                                        std::size_t key_len, std::size_t iv_len );

    std::vector<tls_record> decrypt_tls_data(
        const std::array<uint8_t,32>& client_random,
        const std::array<uint8_t,32>& server_random,
        const tls_version version,
        const uint16_t cipher_suite_id,
        const std::vector<tls_record>& encrypted_records,
        const secrets& session_keys,
        const std::string& secret_label = "SERVER_HANDSHAKE_TRAFFIC_SECRET" );

    tls_record decrypt_record( const std::array<uint8_t,32>& client_random,
                               const std::array<uint8_t,32>& server_random,
                               const tls_version version,
                               const uint16_t cipher_suite_id,
                               const tls_record& record,
                               const secrets& session_keys,
                               const std::string& secret_label,
                               uint64_t seq_num );

    tls_record encrypt_record( const std::array<uint8_t,32>& client_random,
                               const std::array<uint8_t,32>& server_random,
                               const tls_version version,
                               const uint16_t cipher_suite_id,
                               const tls_record& record,
                               const secrets& session_keys,
                               const std::string& secret_label,
                               uint64_t seq_num );

    std::vector<uint8_t> build_tls13_nonce( const std::vector<uint8_t>& base_iv, uint64_t seq_num );

    std::vector<uint8_t> build_tls13_aad( tls_content_type content_type, tls_version version, uint16_t length );

    // =============
    //  Certficiate 
    // =============

    std::vector<uint8_t> extract_certificate( const std::vector<uint8_t>& handshake_payload );

    // =================
    //  TLS Certificate 
    // =================

    struct tls_certificate {};

    // ===============
    //  TLS Handshake signature_algorithms
    // ===============

    struct tls_handshake {
        std::optional<client_hello> c_hello;
        std::optional<server_hello> s_hello;
        std::optional<tls_certificate> certificate;

        bool is_complete() const {
            return c_hello && s_hello;
        }
    };

    // =====================
    //  TLS Decryption Task 
    // =====================

    struct tls_decryption_task {
        tls_record record;
        uint64_t seq_num;
    };

    // ========================
    //  TLS Decryption Context 
    // ========================

    class tls_decryption_context : public tcp_live_stream {
        public:
            std::queue<tls_decryption_task> m_task_queue;
            std::mutex m_queue_mutex;
            std::mutex m_decrypted_mutex;
            std::map<uint64_t,tls_record> m_decrypted_records;
            std::mutex m_future_mutex;
            std::vector<std::pair<std::future<tls_record>,uint64_t>> m_pending_futures;

            tls_decryption_context( const four_tuple& four )
                : tcp_live_stream( four ),
                  m_client_traffic_seq_number( 0 ),
                  m_server_traffic_seq_number( 0 ) {}
            tls_decryption_context( const four_tuple& four, const std::string ssl_keys_log )
                : tcp_live_stream( four ),
                  m_client_traffic_seq_number( 0 ),
                  m_server_traffic_seq_number( 0 ),
                  m_ssl_keys_log( ssl_keys_log ) {}
            ~tls_decryption_context() = default;

            std::expected<bool,std::string> feed( std::span<const uint8_t> packet );
            std::expected<bool,std::string> feed_packet( std::span<const uint8_t> packet );
            bool populate_client_hello( std::span<const uint8_t> packet );
            bool populate_server_hello( std::span<const uint8_t> packet );
            std::expected<bool,std::string> handle_server_data_packet( std::span<const uint8_t> server_data_packet );
            void handle_incomplete_record( std::span<const uint8_t> server_data_packet, std::span<const uint8_t>& payload_span );
            std::expected<bool,std::string> handle_complete_record( std::span<const uint8_t>& payload_span ); 
            
            tls_record handle_decryption_task( const tls_decryption_task& decryption_task );
            void decrypt_record_asynchronously( tls_decryption_task decryption_task );
            void wait_for_all();

            tls_handshake m_handshake;
            uint64_t m_client_traffic_seq_number;
            uint64_t m_server_traffic_seq_number;
            std::optional<secrets> m_secrets;  
            std::ifstream m_ssl_keys_log;
            std::optional<incomplete_tls_record> m_incomplete_record;
            friend class tls_decryption_context_friend_helper;
    };

    class tls_decryption_context_friend_helper {
        public:
            static tls_handshake get_handshake( const tls_decryption_context& t );
            static uint64_t get_client_traffic_seq_number( const tls_decryption_context& t );
            static uint64_t get_server_traffic_seq_number( const tls_decryption_context& t );
            static bool is_client_hello_populated( const tls_decryption_context& t );
            static bool is_server_hello_populated( const tls_decryption_context& t );
            static bool has_secrets( const tls_decryption_context& t );
            static std::size_t get_task_queue_size( const tls_decryption_context& t );
            static std::queue<tls_decryption_task> get_task_queue( const tls_decryption_context& t ); 
            static std::map<uint64_t,tls_record> get_decrypted_records( const tls_decryption_context& t );
    };

    // =========
    //  Classes 
    // =========

    class tls_over_tcp : public tcp_transfer {
        public:
            tls_over_tcp( const four_tuple& four );
        private:
            client_hello c_hello;
            server_hello s_hello;
    };

    class tls_live_stream : public tcp_live_stream {
        public:
            tls_live_stream( const four_tuple& four )
                : tcp_live_stream( four ), 
                  m_client_hello_populated( false ), 
                  m_server_hello_populated( false ) {} 
            tls_live_stream( const four_tuple& four, const std::string ssl_keys_log )
                : tcp_live_stream( four ), 
                  m_lines_consumed( 0 ), 
                  m_ssl_keys_log( ssl_keys_log ), 
                  m_client_hello_populated( false ), 
                  m_server_hello_populated( false ),
                  m_client_traffic_seq_number( 0 ),
                  m_server_traffic_seq_number( 0 ),
                  m_decrypted_records( std::nullopt ) {}
            tls_live_stream( const tcp_live_stream& tcp_stream );
            const std::string& get_sni() const;
            std::expected<bool,std::string> feed( std::span<const uint8_t> packet );
            bool has_secrets() const;
            bool has_client_traffic_secret() const;
        private:
            bool populate_client_hello( std::span<const uint8_t> packet ); 
            bool populate_server_hello( std::span<const uint8_t> packet );
            client_hello m_client_hello;
            server_hello m_server_hello;
            bool m_client_hello_populated;
            bool m_server_hello_populated;
            std::string m_sni;
            std::ifstream m_ssl_keys_log;
            secrets m_tls_secrets;
            std::atomic<std::size_t> m_lines_consumed;
            int m_client_traffic_seq_number;
            int m_server_traffic_seq_number;
            std::vector<uint8_t> m_partial_record_buffer;
            std::optional<incomplete_tls_record> m_incomplete_record;
            std::expected<bool,std::string> handle_client_data_packet( std::span<const uint8_t> client_data_packet );
            std::expected<bool,std::string> handle_server_data_packet( std::span<const uint8_t> server_data_packet );
            void handle_incomplete_record( std::span<const uint8_t> server_data_packet, 
                                           std::optional<std::vector<tls_record>>& encrypted_records,
                                           std::span<const uint8_t>& payload_span );
            std::expected<bool,std::string> handle_complete_record( std::optional<std::vector<tls_record>>& encrypted_records,   
                                                                    std::span<const uint8_t>& payload_span ); 
            std::expected<bool,std::string> decrypt_server_records( std::span<const tls_record> encrypted_records );
        protected:
            std::optional<std::vector<tls_record>> m_decrypted_records;
        private:
            friend std::ostream& operator<<( std::ostream& os, const tls_live_stream& live_stream );
            friend class tls_live_stream_friend_helper;
    };

    class tls_live_stream_friend_helper {
        public:
            static std::optional<std::reference_wrapper<const client_hello>> get_client_hello( const tls_live_stream& t );
            static std::optional<std::reference_wrapper<const server_hello>> get_server_hello( const tls_live_stream& t );
            static const bool client_hello_populated( const tls_live_stream& t );
            static const bool server_hello_populated( const tls_live_stream& t );
            static const std::size_t lines_consumed( const tls_live_stream& t );
            static const secrets tls_secrets( const tls_live_stream& t );
            static const int client_traffic_seq_number( const tls_live_stream& t );
            static const int server_traffic_seq_number( const tls_live_stream& t );
            static std::optional<std::vector<tls_record>> decrypted_records( const tls_live_stream& t );
            static std::vector<uint8_t> partial_record_buffer( const tls_live_stream& t );
            static std::optional<incomplete_tls_record> get_incomplete_record( const tls_live_stream& t );
    };

    class log_file_trimmer {
        public:
            log_file_trimmer( std::string log_file ) : m_log_file( log_file ) {}
            log_file_trimmer( const log_file_trimmer& ) = delete;
            log_file_trimmer& operator=( const log_file_trimmer& ) = delete;
            void start();
            void stop();
    struct tls_context {
        std::optional<std::vector<uint8_t>> peer_public_key;
        std::optional<std::vector<uint8_t>> host_public_key; 
        std::optional<std::vector<uint8_t>> host_private_ley;
        std::optional<named_group> negotiated_key_share;
        std::optional<signature_algorithm> negotiatioed_signature_algorithm;
        tls_version negotiated_version;
        cipher_suite negotiated_cipher_suite;
    };
        private:
            void run();
            std::string m_log_file;
            std::thread m_thread;
            std::atomic<bool> m_stop;
    };

    class tls_live_stream_session : public tcp_live_stream_session {
        private:
            log_file_trimmer m_log_file_trimmer;
    };

    // =========
    //  Filters 
    // =========

    struct tls_filter {
        bool operator()( const ntk::tcp_live_stream& stream );
    };

    struct sni_filter {
        bool operator()( const ntk::tcp_live_stream& stream );
        sni_filter( const std::string& sni );

        std::string m_sni;
    };

    // =========
    //  Helpers 
    // =========

    std::string client_random_to_hex( const std::array<uint8_t,32>& random );

    std::string session_id_to_hex( const std::vector<uint8_t>& session_id );

    std::string string_to_hex( const std::vector<uint8_t>& data );

    // =====================
    //  Generate TLS Random 
    // =====================

    std::array<uint8_t,32> generate_tls_random( const uint32_t timestamp );

    std::array<uint8_t,32> generate_tls_random();

    std::array<uint8_t,32> generate_tls_random( const tls_version version );

    // ===============
    //  Get Timestamp 
    // ===============

    uint32_t get_timestamp();

    std::string load_client_config();

    std::string generate_default_client_config();

    std::string generate_default_server_config();

    std::expected<std::vector<std::string>,std::string> extract_array( const std::string& config, const std::string& array_name );

    std::expected<bool,std::string> extract_boolean( const std::string& config, const std::string& var_name );

    struct client_hello_result {
        std::vector<uint8_t> client_hello;
        std::optional<x25519_key_pair> x25519;
        std::optional<secp256r1_key_pair> secp256r1;
    };

    std::expected<client_hello_result,std::string> generate_client_hello( const std::string& config );

} // namespace ntk

#endif