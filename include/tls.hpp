#ifndef TLS_HPP
#define TLS_HPP

#include <array>
#include <map>
#include <vector>
#include <ranges>
#include <span>
#include <string>
#include <expected>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

#include <cstdint>
#include <cstddef>
#include <cstring>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <tcp.hpp>

namespace ntk {

    using sni_to_ip = std::map<std::string,uint32_t>;

    const std::array<std::string,5> tls_secret_labels = {
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",  
        "EXPORTER_SECRET",
        "SERVER_TRAFFIC_SECRET_0",  
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",  
        "CLIENT_TRAFFIC_SECRET_0"
    };

    enum class tls_content_type : uint8_t {
        CHANGE_CIPHER_SEC = 0x14,
        ALERT,           // 0x15
        HANDSHAKE,       // 0x16
        APPLICATION_DATA // 0x17
    };

    enum class cipher_suite : uint16_t {
        TLS_AES_128_GCM_SHA256 =  0x1301,
        TLS_AES_256_GCM_SHA384 // 0x1302
    };

    static const std::unordered_map<tls_content_type,std::string> tls_content_type_names = {
        { tls_content_type::CHANGE_CIPHER_SEC, "ChangeCipherSpec" },
        { tls_content_type::ALERT, "Alert" },
        { tls_content_type::HANDSHAKE, "Handshake" },
        { tls_content_type::APPLICATION_DATA, "Application Data" }
    };

    static const std::unordered_map<cipher_suite,std::string> tls_cipher_suite_names = {
        { cipher_suite::TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256" },
        { cipher_suite::TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384" }
    };

    struct tls_record {
        tls_content_type content_type;
        uint16_t version;
        std::vector<uint8_t> payload;
    };

    struct tls_record_extraction_result {
        std::vector<tls_record> records;
        bool has_remainder;
    };

    struct client_hello {
        uint16_t client_version;
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

    struct server_hello {
        uint16_t server_version;
        std::array<uint8_t,32> random;
        std::vector<uint8_t> session_id;
        uint16_t cipher_suite;
        uint8_t compression_method;
        std::vector<uint8_t> extensions;
    };

    struct tls_key_material {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;
    };

    client_hello parse_client_hello( const std::span<const uint8_t> client_hello_bytes );

    server_hello parse_server_hello( const std::span<const uint8_t> server_hello_bytes );

    std::expected<
        std::tuple<std::vector<tls_record>,size_t>, 
        std::string
    > split_tls_records( std::span<const uint8_t> tls_payload );

    using secrets = std::map<std::string,std::map<std::string,std::vector<uint8_t>>>;

    secrets get_tls_secrets( const std::string& filename );

    secrets get_tls_secrets( const std::string& filename, std::array<uint8_t,32> client_random );

    std::string client_random_to_hex( const std::array<uint8_t,32>& random );

    std::string session_id_to_hex( const std::vector<uint8_t>& session_id );

    std::string string_to_hex( const std::vector<uint8_t>& data );

    tls_key_material derive_tls_key_iv( const std::vector<uint8_t>& secret, const EVP_MD* hash_func,
                                        size_t key_len, size_t iv_len );

    std::vector<tls_record> decrypt_tls_data(
        const std::array<uint8_t,32>& client_random,
        const std::array<uint8_t,32>& server_random,
        const uint16_t tls_version,
        const uint16_t cipher_suite_id,
        const std::vector<tls_record>& encrypted_records,
        const secrets& session_keys,
        const std::string& secret_label = "SERVER_HANDSHAKE_TRAFFIC_SECRET" );

    tls_record decrypt_record( const std::array<uint8_t,32>& client_random,
                               const std::array<uint8_t,32>& server_random,
                               const uint16_t tls_version,
                               const uint16_t cipher_suite_id,
                               const tls_record& record,
                               const secrets& session_keys,
                               const std::string& secret_label,
                               uint64_t seq_num );

    std::vector<uint8_t> build_tls13_nonce( const std::vector<uint8_t>& base_iv, uint64_t seq_num );

    std::vector<uint8_t> get_traffic_secret( const secrets& session_keys,
                                             const std::array<uint8_t,32>& client_random,
                                             const std::string& label );

    std::vector<uint8_t> build_tls13_aad( tls_content_type content_type, uint16_t version, uint16_t length );

    std::vector<uint8_t> extract_certificate( const std::vector<uint8_t>& handshake_payload );

    bool is_tls( const unsigned char* packet );

    bool is_tls_v( const std::vector<uint8_t>& packet );

    bool is_client_hello( const unsigned char* packet );

    bool is_client_hello_v( const std::vector<uint8_t>& packet );

    bool is_client_hello( const tls_record& record );

    bool is_server_hello( const unsigned char* packet );

    bool is_server_hello_v( const std::vector<uint8_t>& packet );

    bool is_server_hello( const tls_record& record );

    bool is_tls_alert( const unsigned char* packet );
    
    bool is_tls_alert_v( const std::vector<uint8_t>& packet );

    bool is_tls_application_data( const tls_record& record );

    bool is_tls_payload( const std::vector<uint8_t>& payload );

    bool secret_labels_are_equal( std::array<std::string,5> lhs, std::array<std::string,5> rhs );

    bool is_complete_secrets( const std::map<std::string,std::vector<uint8_t>>& secrets );

    client_hello get_client_hello( const std::span<const uint8_t> tcp_payload );

    std::expected<std::string,std::string> get_sni( const client_hello& hello );

    std::vector<std::string> get_snis( const session& packets, const std::string& host );

    std::expected<bool,std::string> has_sni( const client_hello& hello, const std::string& host );

    std::expected<bool,std::string> sni_contains( const client_hello& hello, const std::string& host );

    sni_to_ip get_sni_to_ip( const session& packets );

    client_hello get_client_hello_from_ethernet_frame( const unsigned char* ethernet_frame );

    client_hello get_client_hello_from_ethernet_frame( const std::vector<uint8_t>& ethernet_frame );

    client_hello get_client_hello( const tls_record& record );

    server_hello get_server_hello_from_ethernet_frame( const unsigned char* ethernet_frame );

    server_hello get_server_hello_from_ethernet_frame( const std::vector<uint8_t>& ethernet_frame );

    server_hello get_server_hello( const tls_record& record );

    class tls_over_tcp : public tcp_transfer {
        public:
            tls_over_tcp( const four_tuple& four );
        private:
            client_hello c_hello;
            server_hello s_hello;
    };

    class tls_live_stream : public tcp_live_stream {
        public:
            tls_live_stream( const tcp_live_stream& tcp_stream );
            const std::string& get_sni() const;
        private:
            client_hello m_client_hello;
            server_hello m_server_hello;
            std::string m_sni;

            friend std::ostream& operator<<( std::ostream& os, const tls_live_stream& live_stream );
    };

    struct tls_filter {
        bool operator()( const ntk::tcp_live_stream& stream );
    };

    struct sni_filter {
        bool operator()( const ntk::tcp_live_stream& stream );
        sni_filter( const std::string& sni );

        std::string m_sni;
    };

    tls_record_extraction_result extract_tls_records( const std::vector<std::vector<uint8_t>>& payloads );

    std::expected<tls_record,std::string> get_tls_record_from_ethernet( std::span<const uint8_t> packet );

} // namespace ntk

#endif