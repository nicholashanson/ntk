#ifndef TLS_HPP
#define TLS_HPP

#include <array>
#include <algorithm>
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
#include <variant>

#include <cstdint>
#include <cstddef>
#include <cstring>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <tcp.hpp>
#include <utils.hpp>

namespace ntk {

    // ===============
    //  TLS Extension 
    // ===============   

    enum class tls_extension : uint16_t {
        server_name        = 0x0000,
        supported_versions = 0x002b,
        key_share          = 0x0033
    };

    // =============
    //  TLS Version 
    // =============

    enum class tls_version : uint16_t {
        tls_1_0 = 0x0301,
        tls_1_2 = 0x0303,
        tls_1_3 = 0x0304
    };

    namespace look_up {

        constexpr std::array<tls_version,3/* entries in enum tls_version */> tls_versions = {
            tls_version::tls_1_0,
            tls_version::tls_1_2,
            tls_version::tls_1_3
        };

    } // namespace look_up

    inline auto get_tls_version = make_lookup( look_up::tls_versions );

    // ===============
    //  Cipher Suites 
    // ===============

    enum class cipher_suite : uint16_t {
        TLS_AES_128_GCM_SHA256 =  0x1301,
        TLS_AES_256_GCM_SHA384 // 0x1302
    };

    static const std::unordered_map<cipher_suite,std::string> tls_cipher_suite_names = {
        { cipher_suite::TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256" },
        { cipher_suite::TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384" }
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
        std::tuple<std::vector<tls_record>,size_t>, 
        std::string
    > split_tls_records( std::span<const uint8_t> tls_payload );

    std::expected<
        std::tuple<std::vector<tls_record>,size_t>,
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

    tls_key_material derive_tls_key_iv( const std::vector<uint8_t>& secret, const EVP_MD* hash_func,
                                        size_t key_len, size_t iv_len );

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

} // namespace ntk

#endif