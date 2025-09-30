#include <tls.hpp>

namespace ntk {

    // =====================
    //  Generate TLS Random 
    // =====================

    std::array<uint8_t,32> generate_tls_random( const uint32_t timestamp ) {
        constexpr std::size_t num_random_bytes = 28;
        std::array<uint8_t,32> random_bytes;
        auto timestamp_bytes = get_big_endian_byte_encoding<uint32_t,4>( timestamp );
        std::copy( timestamp_bytes.begin(), timestamp_bytes.end(), random_bytes.begin() );
        RAND_bytes( random_bytes.data() + timestamp_bytes.size(), num_random_bytes );
        return random_bytes;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::array<uint8_t,32> generate_tls_random() {
        std::array<uint8_t,32> random_bytes;
        RAND_bytes( random_bytes.data(), random_bytes.size() );
        return random_bytes;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::array<uint8_t,32> generate_tls_random( const tls_version version ) {
        if ( version == tls_version::tls_1_2 ) {
            auto timestamp = get_timestamp();
            return generate_tls_random( timestamp );
        }
        return generate_tls_random();
    }

    // ===============
    //  Get Timestamp
    // ===============

    uint32_t get_timestamp() {
        return static_cast<uint32_t>( std::chrono::system_clock::to_time_t( std::chrono::system_clock::now() ) );
    }

    // ===============
    //  String to Hex 
    // ===============

    std::string string_to_hex( const std::vector<uint8_t>& data ) {
        std::ostringstream oss;
        for ( auto byte : data )
            oss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << int( byte );
        return oss.str();
    }

    // ======================
    //  Client Random to Hex 
    // ======================

    std::string client_random_to_hex( const std::array<uint8_t,32>& random ) {
        std::ostringstream oss;
        for ( auto byte : random )
            oss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << int( byte );
        return oss.str();
    }

    // ===================
    //  Session ID to Hex 
    // ===================

    std::string session_id_to_hex( const std::vector<uint8_t>& session_id ) {
        std::ostringstream oss;
        for ( auto byte : session_id )
            oss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << int( byte );
        return oss.str();
    }

    // ====================
    //  Parse Client Hello 
    // ====================

    std::expected<client_hello,std::string> parse_client_hello( const std::span<const uint8_t> client_hello_bytes ) {
        client_hello c_hello;
        auto version_result = get_tls_version_from_handshake_message( client_hello_bytes );
        if ( !version_result ) {
            return std::unexpected( version_result.error() );
        }
        if ( !version_result.value() ) {
            return std::unexpected( "Unrecognized TLS Version in ClientHello" );
        }
        c_hello.client_version = version_result.value().value();
        auto random_result = extract_handshake_message_random( client_hello_bytes );
        if ( !random_result ) {
            return std::unexpected( random_result.error() );
        }
        c_hello.random = std::move( random_result.value() );

        auto session_id_result = extract_tls_session_id( client_hello_bytes );
        if ( !session_id_result ) {
            return std::unexpected( session_id_result.error() );
        }
        c_hello.session_id = std::move( session_id_result.value() );

        const std::size_t session_id_len = c_hello.session_id.size();
        auto cipher_suites_result = extract_client_hello_cipher_suites( client_hello_bytes, session_id_len );
        if ( !cipher_suites_result ) {
            return std::unexpected( cipher_suites_result.error() );
        }
        c_hello.cipher_suites = std::move( cipher_suites_result.value() );
        
        const std::size_t cipher_suites_pos = constants::minimum_handshake_message_len + session_id_len  + 2 /* cipher suites len bytes */; 
        const std::size_t cipher_suites_len = c_hello.cipher_suites.size(); 
        const std::size_t compression_methods_len_pos = cipher_suites_pos + cipher_suites_len;
        auto compression_methods_result = extract_client_hello_compression_methods( client_hello_bytes, compression_methods_len_pos );
        if ( !compression_methods_result ) {
            return std::unexpected( compression_methods_result.error() );
        }
        c_hello.compression_methods = std::move( compression_methods_result.value() );

        const std::size_t compression_methods_len = c_hello.compression_methods.size();
        const std::size_t extensions_len_pos = compression_methods_len_pos + 1 + compression_methods_len;
        auto extensions_result = extract_handshake_message_extensions( client_hello_bytes, extensions_len_pos );
        if ( !extensions_result ) {
            return std::unexpected( extensions_result.error() );
        }
        c_hello.extensions = std::move( extensions_result.value() );
        return c_hello;
    }

    // ====================================
    //  Extract Client Hello Cipher Suites 
    // ====================================

    std::expected<std::vector<uint8_t>,std::string> extract_client_hello_cipher_suites( const std::span<const uint8_t> client_hello_bytes,
                                                                                        const std::size_t session_id_len ) {
        const std::size_t cipher_suites_len_pos = constants::session_id_len_pos + 1 /* session id len byte */ + session_id_len;
        const std::size_t cipher_suites_pos = cipher_suites_len_pos + 2 /* cipher suites len bytes */;
        if ( client_hello_bytes.size() < cipher_suites_len_pos + 1 + 2 /* cipher suites len bytes */ ) {
            return std::unexpected( "ClientHello too short for Cipher Suites Length Field" );
        }
        std::size_t cipher_suites_len = read_uint16_be( client_hello_bytes, cipher_suites_len_pos );
        if ( client_hello_bytes.size() < cipher_suites_pos + 1 + cipher_suites_len ) {
            return std::unexpected( "ClientHello too short for Cipher Suites list" );
        }
        std::vector<uint8_t> cipher_suites( cipher_suites_len );
        std::memcpy( cipher_suites.data(), &client_hello_bytes[ cipher_suites_pos ], cipher_suites_len );
        return cipher_suites;
    }

    // ==========================================
    //  Extract Client Hello Compression Methods 
    // ==========================================

    std::expected<std::vector<uint8_t>,std::string> extract_client_hello_compression_methods( const std::span<const uint8_t> client_hello_bytes,
                                                                                              const std::size_t compression_methods_len_pos ) {
        if ( client_hello_bytes.size() < compression_methods_len_pos + 1 ) {
            return std::unexpected( "ClientHello too short for Compression Methods Length Field" );
        }
        const std::size_t compression_methods_len = client_hello_bytes[ compression_methods_len_pos ];
        std::vector<uint8_t> compression_methods( compression_methods_len );
        std::memcpy( compression_methods.data(), &client_hello_bytes[ compression_methods_len_pos + 1 ], compression_methods_len );
        return compression_methods;
    }

    // ==================
    //  Get Client Hello 
    // ==================

    std::expected<client_hello,std::string> get_client_hello( const std::span<const uint8_t> tcp_payload ) {
        if ( tcp_payload.size() < constants::record_header_len + constants::handshake_header_len ) {
            return std::unexpected( "TCP Payload is too short to contain a ClientHello" );
        }
        auto client_hello_bytes = tcp_payload.subspan( constants::record_header_len + constants::handshake_header_len );
        return parse_client_hello( client_hello_bytes );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<client_hello,std::string> get_client_hello_from_ethernet_frame( const unsigned char* ethernet_frame ) {
        auto payload_result = get_tcp_payload( ethernet_frame );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return std::unexpected( "TCP Payload is empty" );
        }
        auto& payload = *payload_result.value();
        return get_client_hello( payload );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<client_hello,std::string> get_client_hello_from_ethernet_frame( std::span<const uint8_t> ethernet_frame ) {
        return get_client_hello_from_ethernet_frame( ethernet_frame.data() );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<client_hello,std::string> get_client_hello( const tls_record& record ) {
        auto client_hello_bytes = std::span<const uint8_t>( record.payload ).subspan( constants::handshake_header_len );
        return parse_client_hello( client_hello_bytes );
    }

    // =================
    //  Is Client Hello 
    // =================

    std::expected<bool,std::string> is_client_hello( const unsigned char* packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return false;
        }
        auto& payload = *payload_result.value();
        if ( payload.size() < constants::record_header_len + 1 /* 5 recorder header bytes + 1 handshake type byte */ ) { 
            return false;
        }
        auto content_type_opt = get_tls_content_type( payload[ record_header_offset::content_type ] );
        if ( !content_type_opt ) {
            return std::unexpected( "Unrecognized TLS Content Type" );
        }
        auto handshake_tpye_opt = get_tls_handshake_type( payload[ constants::record_header_len ] );
        return content_type_opt == tls_content_type::handshake &&
               handshake_tpye_opt == tls_handshake_type::client_hello;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<bool,std::string> is_client_hello( std::span<const uint8_t> packet ) {
        return is_client_hello( packet.data() );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    bool is_client_hello( const tls_record& record ) {
        return record.content_type == tls_content_type::handshake &&
               static_cast<tls_handshake_type>( record.payload.front() ) == tls_handshake_type::client_hello;
    }

    // ====================
    //  Parse Server Hello 
    // ====================

    std::expected<server_hello,std::string> parse_server_hello( const std::span<const uint8_t> server_hello_bytes ) {
        server_hello s_hello;
        auto version_result = get_tls_version_from_handshake_message( server_hello_bytes );
        if ( !version_result ) {
            return std::unexpected( version_result.error() );
        }
        if ( !version_result.value() ) {
            return std::unexpected( "Unrecognized TLS Version in ServerHello" );
        }
        s_hello.server_version = version_result.value().value();
        auto random_result = extract_handshake_message_random( server_hello_bytes );
        if ( !random_result ) {
            return std::unexpected( random_result.error() );
        }
        s_hello.random = std::move( random_result.value() );

        auto session_id_result = extract_tls_session_id( server_hello_bytes );
        if ( !session_id_result ) {
            return std::unexpected( session_id_result.error() );
        }
        s_hello.session_id = std::move( session_id_result.value() );

        const std::size_t session_id_len = s_hello.session_id.size();
        const std::size_t cipher_suite_pos = constants::minimum_handshake_message_len + session_id_len;
        auto cipher_suite_result = get_server_hello_cipher_suite( server_hello_bytes, cipher_suite_pos );
        if ( cipher_suite_result ) {
            s_hello.cipher_suite = cipher_suite_result.value();
        } else {
            return std::unexpected( cipher_suite_result.error() );
        }

        const std::size_t compression_method_pos = cipher_suite_pos + constants::cipher_suite_len;
        if ( server_hello_bytes.size() < compression_method_pos + 1 /* compression method byte */ ) {
            return std::unexpected( "ServerHello too short for compression method" );
        }
        s_hello.compression_method = server_hello_bytes[ compression_method_pos ];

        const std::size_t extensions_len_pos = compression_method_pos + 1;
        auto extensions_result = extract_handshake_message_extensions( server_hello_bytes, extensions_len_pos );
        if ( !extensions_result ) {
            return std::unexpected( extensions_result.error() );
        }
        s_hello.extensions = std::move( extensions_result.value() );
        return s_hello;
    }

    // ===============================
    //  Get Server Hello Cipher Suite 
    // ===============================

    std::expected<uint16_t,std::string> get_server_hello_cipher_suite( const std::span<const uint8_t>& server_hello_bytes, const std::size_t cipher_suite_pos ) {
        if ( server_hello_bytes.size() < cipher_suite_pos + 1 + constants::cipher_suite_len ) {
            return std::unexpected( "ServerHello too short for cipher suite" );
        }
        return read_uint16_be( server_hello_bytes, cipher_suite_pos );
    }

    // ====================
    //  Extract Session ID 
    // ====================

    std::expected<std::vector<uint8_t>,std::string> extract_tls_session_id( std::span<const uint8_t> handshake_message_bytes ) {
        if ( handshake_message_bytes.size() < constants::session_id_len_pos + 1 ) {
            return std::unexpected( "Handshake Message too short for session id length" );
        }
        const std::size_t session_id_len = handshake_message_bytes[ constants::session_id_len_pos ];
        if ( handshake_message_bytes.size() < constants::session_id_len_pos + 1 + session_id_len ) {
            return std::unexpected( "Handshake Message too short for session id" );
        }
        std::vector<uint8_t> session_id( session_id_len );
        if ( session_id_len == 0 ) {
            return session_id;
        }
        std::memcpy( session_id.data(), &handshake_message_bytes[ constants::session_id_len_pos + 1 ], session_id_len );
        return session_id;
    }

    // ==================================
    //  Extract Handshake Message Random 
    // ==================================

    std::expected<std::array<uint8_t,constants::random_len>,std::string> extract_handshake_message_random( const std::span<const uint8_t> handshake_message_bytes ) {
        if ( handshake_message_bytes.size() < constants::version_len + constants::random_len ) {
            return std::unexpected( "Handshake Message too short for Random" );
        }
        std::array<uint8_t,constants::random_len> random;
        std::memcpy( random.data(), &handshake_message_bytes[ constants::version_len ], constants::random_len );
        return random;
    }

    // ========================================
    //  Get TLS Version From Handshake Message
    // ========================================

    std::expected<std::optional<tls_version>,std::string> get_tls_version_from_handshake_message( const std::span<const uint8_t> handshake_message_bytes ) {
        if ( handshake_message_bytes.size() < constants::version_len  ) {
            return std::unexpected( "Handshake Message too short for TLS Version" );
        }
        return get_tls_version( read_uint16_be( handshake_message_bytes, 0 ) );
    }

    // ======================================
    //  Extract Handshake Message Extensions 
    // ======================================

    std::expected<std::vector<uint8_t>,std::string> extract_handshake_message_extensions( const std::span<const uint8_t> handshake_message_bytes,
                                                                                          const std::size_t extensions_len_pos ) {
        const std::size_t extensions_len = read_uint16_be( handshake_message_bytes, extensions_len_pos );
        if ( handshake_message_bytes.size() < extensions_len_pos + 1 + extensions_len ) {
            return std::unexpected( "HandShake Message too short for Extensions" );
        }
        std::vector<uint8_t> extensions( extensions_len );
        std::memcpy( extensions.data(), &handshake_message_bytes[ extensions_len_pos + 2 /* extension len field len */ ], extensions_len );
        return extensions;
    }

    // ==================
    //  Get Server Hello 
    // ==================

    std::expected<server_hello,std::string> get_server_hello_from_payload( const std::span<const uint8_t> tcp_payload ) {
        auto server_hello_bytes = tcp_payload.subspan( constants::record_header_len + constants::handshake_header_len );
        return parse_server_hello( server_hello_bytes );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<server_hello,std::string> get_server_hello_from_ethernet( const unsigned char* ethernet_frame ) {
        auto payload_result = get_tcp_payload( ethernet_frame );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return std::unexpected( "TCP Payload is empty" );
        }
        auto& payload = *payload_result.value();
        auto split_result = split_tls_records( payload );
        if ( !split_result ) {
            return std::unexpected( split_result.error() );
        }
        auto [ records, offset_reached ] = *split_result;
        if ( records.empty() ) {
            return std::unexpected( "The ethernet frame contains no complete TLS records" );
        }  
        auto& server_hello_record = records.front();
        return get_server_hello( server_hello_record );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<server_hello,std::string> get_server_hello_from_ethernet( const std::span<const uint8_t> ethernet_frame ) {
        return get_server_hello_from_ethernet( ethernet_frame.data() );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<server_hello,std::string> get_server_hello( const tls_record& record ) {
        if ( !is_server_hello( record ) ) {
            return std::unexpected( "The record is not a valid ServerHello" );
        }
        auto server_hello_bytes = std::span<const uint8_t>( record.payload ).subspan( constants::handshake_header_len );
        return parse_server_hello( server_hello_bytes ); 
    }

    // ===================
    //  Split TLS Records 
    // ===================

    std::expected<
        std::tuple<std::vector<tls_record>,std::size_t>,
        std::string
    > split_tls_records( std::span<const uint8_t> tls_payload ) {
        std::size_t offset_reached{};
        if ( tls_payload.empty() ) return std::unexpected( "TLS Payload is empty" );
        std::vector<tls_record> records;

        while ( !tls_payload.empty() ) {
            if ( tls_payload.size() < constants::record_header_len ) {
                return std::unexpected( "TLS Payload too short for Record Header" ); 
            }
            const uint16_t record_payload_len = read_uint16_be( tls_payload, record_header_offset::payload_len );
            const std::size_t full_record_len = constants::record_header_len + record_payload_len;

            if ( tls_payload.size() < full_record_len ) {
                break;
            }
            auto record_span = tls_payload.first( full_record_len );
            auto result = get_parsed_tls_record( record_span );
            if ( !result ) {
                return std::unexpected( "Failed to parse TLS Record: " + result.error() );
            }
            records.push_back( std::move( result.value() ) );
            offset_reached += full_record_len;
            tls_payload = tls_payload.subspan( full_record_len );
        }
        return std::make_tuple( records, offset_reached );
    }

    // ===============================
    //  Get TLS Records From Ethernet 
    // ===============================

    std::expected<
        std::tuple<std::vector<tls_record>,std::size_t>,
        std::string
    > get_tls_records_from_ethernet( std::span<const uint8_t> packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return std::unexpected( "TCP Payload is empty" );
        }
        auto& payload = *payload_result.value();
        return split_tls_records( payload );
    }

    // =======================
    //  Get Parsed TLS Record 
    // =======================

    std::expected<tls_record,std::string> get_parsed_tls_record( std::span<const uint8_t> raw_tls_record ) {
        if ( raw_tls_record.size() < constants::record_header_len ) {
            return std::unexpected( "TLS Record too short to contain Record Header" );
        }
        auto content_type_opt = get_tls_content_type( raw_tls_record[ record_header_offset::content_type ] );
        if ( !content_type_opt ) {
            return std::unexpected( "Unrecognized TLS Content Type");
        }
        auto version_opt = get_tls_version( read_uint16_be( raw_tls_record, record_header_offset::version ) );
        if ( !version_opt ) {
            return std::unexpected( "Unrecognized TLS Version" );
        }
        const uint16_t record_payload_len = read_uint16_be( raw_tls_record, record_header_offset::payload_len );
        if ( raw_tls_record.size() < constants::record_header_len + record_payload_len ) {
            return std::unexpected( "TLS Record Payload length exceeds buffer size" );
        }
        std::vector<uint8_t> payload( raw_tls_record.begin() + constants::record_header_len, 
                                      raw_tls_record.begin() + constants::record_header_len + record_payload_len );
        return tls_record {
            content_type_opt.value(),
            version_opt.value(),
            payload
        };
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<tls_record,std::string> get_parsed_tls_record_from_ethernet( std::span<const uint8_t> packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return std::unexpected( "TCP Payload is empty" );
        }
        auto& payload = *payload_result.value();
        return get_parsed_tls_record( payload );
    }

    // =================
    //  Is Server Hello 
    // =================

    std::expected<bool,std::string> is_server_hello( const unsigned char* packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return std::unexpected( "TCP Payload is empty" );
        }
        auto& payload = *payload_result.value();
        if ( payload.size() < constants::record_header_len + 1 /* 5 bytes for recorder header + 1 handshake type byte */ ) { 
            return false;
        }
        auto content_type_opt = get_tls_content_type( payload[ record_header_offset::content_type ] );
        if ( !content_type_opt ) {
            return std::unexpected( "Unrecognized TLS Content Type" );
        }
        
        auto handshake_tpye_opt = get_tls_handshake_type( payload[ constants::record_header_len ] );
        return content_type_opt == tls_content_type::handshake &&
               handshake_tpye_opt == tls_handshake_type::server_hello;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<bool,std::string> is_server_hello( std::span<const uint8_t>& packet ) {
        return is_server_hello( packet.data() );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    bool is_server_hello( const tls_record& record ) {
        if ( record.payload.empty() ) { 
            return false;
        }
        return record.content_type == tls_content_type::handshake &&
               static_cast<tls_handshake_type>( record.payload.front() ) == tls_handshake_type::server_hello;
    }

    // ==============
    //  Is TLS Alert 
    // ==============

    std::expected<bool,std::string> is_tls_alert( const unsigned char* packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return false;
        }
        auto& payload = *payload_result.value();
        auto content_type_opt = get_tls_content_type( payload[ record_header_offset::content_type ] );
        if ( !content_type_opt ) {
            return std::unexpected( "Unrecognized TLS Content Type" );
        }
        return content_type_opt == tls_content_type::alert;   
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<bool,std::string> is_tls_alert( std::span<const uint8_t> packet ) {
        return is_tls_alert( packet.data() );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    bool is_tls_alert( const tls_record& record ) {
        return record.content_type == tls_content_type::alert;
    }

    // =======================
    //  Is Change Cipher Spec 
    // =======================

    bool is_change_cipher_spec( const tls_record& record ) {
        return record.content_type == tls_content_type::change_cipher_spec;    
    }

    // =========================
    //  Is TLS Application Data 
    // =========================

    bool is_tls_application_data( const tls_record& record ) {
        return record.content_type == tls_content_type::application_data;
    }

    // ====================
    //  Get Traffic Secret 
    // ====================

    std::vector<uint8_t> get_traffic_secret( const secrets& session_keys,
                                             const std::array<uint8_t,32>& client_random,
                                             const std::string& label ) {
        auto client_hex = client_random_to_hex( client_random );
        return session_keys.at( client_hex ).at( label );
    }

    // =================
    //  Get TLS Secrets 
    // =================

    secrets get_tls_secrets( const std::string& filename ) {
        secrets tls_secrets;
        std::ifstream file( filename );
        std::string line;

        while ( std::getline( file, line ) ) {
            if ( line.empty() || std::all_of( line.begin(), line.end(), isspace ) ) continue;
            if ( line[ 0 ] == '#' ) continue;
            std::istringstream iss( line );
            std::string label;
            std::string client_random_hex;
            std::string secret_hex;
            iss >> label >> client_random_hex >> secret_hex;

            secret_hex.erase( std::remove_if(secret_hex.begin(), secret_hex.end(),
                [] ( unsigned char c ) {
                    return !std::isxdigit( c );
                }), secret_hex.end() );

            std::vector<uint8_t> secret;
            for ( std::size_t i = 0; i < secret_hex.size(); i += 2 ) {
                secret.push_back( std::stoi( secret_hex.substr( i, 2 ), nullptr, 16 ) );
            }

            tls_secrets[ client_random_hex ][ label ] = secret;
        }

        return tls_secrets;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    secrets get_tls_secrets( const std::string& filename, std::array<uint8_t,32> client_random ) {
        auto client_random_h = client_random_to_hex( client_random );
        secrets tls_secrets;
        std::ifstream file( filename );
        std::string line;

        while ( std::getline( file, line ) ) {
            if ( line.empty() || std::all_of( line.begin(), line.end(), isspace ) ) continue;
            if ( line[ 0 ] == '#' ) continue;
            std::istringstream iss( line );
            std::string label;
            std::string client_random_hex;
            std::string secret_hex;
            iss >> label >> client_random_hex >> secret_hex;

            secret_hex.erase( std::remove_if(secret_hex.begin(), secret_hex.end(),
                [] ( unsigned char c ) {
                    return !std::isxdigit( c );
                }), secret_hex.end() );

            std::vector<uint8_t> secret;
            for ( std::size_t i = 0; i < secret_hex.size(); i += 2 ) {
                secret.push_back( std::stoi( secret_hex.substr( i, 2 ), nullptr, 16 ) );
            }

            if ( client_random_hex == client_random_h ) {
                tls_secrets[ client_random_hex ][ label ] = secret;
                if ( is_complete_secrets( tls_secrets[ client_random_hex ] ) )
                    break;
            }
        }

        return tls_secrets;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::pair<secrets,std::size_t> get_tls_secrets_dynamically( std::ifstream& file_handle, std::array<uint8_t,32> client_random ) {
        auto client_random_h = client_random_to_hex( client_random );
        std::size_t line_number = 0;
        secrets tls_secrets;
        std::string line;

        while ( std::getline( file_handle, line ) ) {
            ++line_number;
            if ( line.empty() || std::all_of( line.begin(), line.end(), isspace ) ) continue;
            if ( line[ 0 ] == '#' ) continue;
            std::istringstream iss( line );
            std::string label;
            std::string client_random_hex;
            std::string secret_hex;
            iss >> label >> client_random_hex >> secret_hex;

            secret_hex.erase( std::remove_if(secret_hex.begin(), secret_hex.end(),
                [] ( unsigned char c ) {
                    return !std::isxdigit( c );
                }), secret_hex.end() );

            std::vector<uint8_t> secret;
            for ( std::size_t i = 0; i < secret_hex.size(); i += 2 ) {
                secret.push_back( std::stoi( secret_hex.substr( i, 2 ), nullptr, 16 ) );
            }

            if ( client_random_hex == client_random_h ) {
                tls_secrets[ client_random_hex ][ label ] = secret;
                if ( is_complete_secrets( tls_secrets[ client_random_hex ] ) )
                    break;
            }
        }
        return { tls_secrets, line_number };
    }

    // =====================
    //  Is Complete Secrets 
    // =====================

    bool is_complete_secrets( const session_secrets& secrets ) {
        constexpr std::size_t expected_number_of_secrets = 5;
        if ( secrets.size() != expected_number_of_secrets ) return false;
        std::array<std::string,expected_number_of_secrets> labels;
        std::size_t count = 0;
        for ( auto [ label, secret ] : secrets ) {
            labels[ count ] = label;
            count += 1;
        }
        return secret_labels_are_equal( labels, tls_secret_labels );
    }

    // ===================
    //  HKDF Expand Label 
    // ===================

    std::vector<uint8_t> hkdf_expand_label( const std::vector<uint8_t>& secret, const std::string& label,              
                                            const std::vector<uint8_t>& context, std::size_t out_len, const EVP_MD* hash_func ) {
        std::string full_label = "tls13 " + label;
        std::vector<uint8_t> hkdf_label;

        hkdf_label.push_back( static_cast<uint8_t>( ( out_len >> 8 ) & 0xff ) );
        hkdf_label.push_back( static_cast<uint8_t>( out_len & 0xff ) );
        hkdf_label.push_back( static_cast<uint8_t>( full_label.size() ) );
        hkdf_label.insert( hkdf_label.end(), full_label.begin(), full_label.end() );
        hkdf_label.push_back( static_cast<uint8_t>( context.size() ) );
        hkdf_label.insert( hkdf_label.end(), context.begin(), context.end() );

        std::vector<uint8_t> out( out_len );
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id( EVP_PKEY_HKDF, nullptr );
        if ( !ctx ) throw std::runtime_error( "EVP_PKEY_CTX_new_id failed" );

        if ( EVP_PKEY_derive_init( ctx ) <= 0 ||
             EVP_PKEY_CTX_set_hkdf_mode( ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY ) <= 0 ||
             EVP_PKEY_CTX_set_hkdf_md( ctx, hash_func ) <= 0 ||
             EVP_PKEY_CTX_set1_hkdf_key( ctx, secret.data(), secret.size() ) <= 0 ||
             EVP_PKEY_CTX_add1_hkdf_info( ctx, hkdf_label.data(), hkdf_label.size() ) <= 0 ||
             EVP_PKEY_derive( ctx, out.data(), &out_len ) <= 0 ) {
            EVP_PKEY_CTX_free( ctx );
            throw std::runtime_error( "HKDF-Expand-Label failed" );
        }

        EVP_PKEY_CTX_free( ctx );
        return out;
    }

    // ===================
    //  Derive TLS Key IV 
    // ===================

    tls_key_material derive_tls_key_iv( const std::vector<uint8_t>& secret, const EVP_MD* hash_func,
                                        size_t key_len, size_t iv_len ) {
        tls_key_material km;
        std::vector<uint8_t> context; 
        km.key = hkdf_expand_label( secret, "key", context, key_len, hash_func );
        km.iv = hkdf_expand_label( secret, "iv",  context, iv_len,  hash_func );
        return km;
    }

    // =====================
    //  Build TLS 1.3 Nonce 
    // =====================

    std::vector<uint8_t> build_tls13_nonce( const std::vector<uint8_t>& base_iv, uint64_t seq_num ) {
        std::vector<uint8_t> nonce = base_iv;
        for ( int i = 0; i < 8; ++i ) {
            nonce[ nonce.size() - 8 + i ] ^= static_cast<uint8_t>( ( seq_num >> ( 56 - 8 * i ) ) & 0xff );
        }
        return nonce;
    }

    // =================
    //  Decrypt AES-GCM 
    // =================

    std::vector<uint8_t> decrypt_aes_gcm( const std::vector<uint8_t>& key,
                                          const std::vector<uint8_t>& nonce,
                                          const std::vector<uint8_t>& aad,
                                          const std::vector<uint8_t>& cipher_text_with_tag,
                                          const EVP_CIPHER* cipher ) {
        constexpr std::size_t tag_length = 16;
        std::size_t cipher_len = cipher_text_with_tag.size() - tag_length;
        const uint8_t* tag = &cipher_text_with_tag[ cipher_len ];
        const uint8_t* cipher_text = &cipher_text_with_tag[ 0 ];
        std::vector<uint8_t> plain_text( cipher_len );

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex( ctx, cipher, nullptr, nullptr, nullptr );
        EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr );
        EVP_DecryptInit_ex( ctx, nullptr, nullptr, key.data(), nonce.data() );

        int len = 0;
        EVP_DecryptUpdate( ctx, nullptr, &len, aad.data(), aad.size() );
        EVP_DecryptUpdate( ctx, plain_text.data(), &len, cipher_text, cipher_len );
        EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_TAG, 16, ( void* )tag );

        if ( EVP_DecryptFinal_ex( ctx, plain_text.data() + len, &len) <= 0 ) {
            EVP_CIPHER_CTX_free( ctx );
            throw std::runtime_error( "GCM decryption failed ( tag mismatch )" );
        }

        EVP_CIPHER_CTX_free( ctx );
        return plain_text;
    }

    // =================
    //  Encrypt AES-GCM 
    // =================

    std::vector<uint8_t> encrypt_aes_gcm( const std::vector<uint8_t>& key,
                                          const std::vector<uint8_t>& nonce,
                                          const std::vector<uint8_t>& aad,
                                          const std::vector<uint8_t>& plain_text,
                                          const EVP_CIPHER* cipher ) {
        constexpr std::size_t tag_length = 16;
        std::vector<uint8_t> cipher_text_with_tag( plain_text.size() + tag_length );
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex( ctx, cipher, nullptr, nullptr, nullptr );
        EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr );
        EVP_EncryptInit_ex( ctx, nullptr, nullptr, key.data(), nonce.data() );

        int len = 0;
        EVP_EncryptUpdate( ctx, nullptr, &len, aad.data(), aad.size() );
        
        int out_len = 0;
        EVP_EncryptUpdate( ctx, cipher_text_with_tag.data(), &out_len, plain_text.data(), plain_text.size() );
        
        int final_len = 0;
        EVP_EncryptFinal_ex( ctx, nullptr, &final_len );
        EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_GET_TAG, tag_length, cipher_text_with_tag.data() + plain_text.size() );
        EVP_CIPHER_CTX_free( ctx );
        return cipher_text_with_tag;
    }

    // ===================
    //  Build TLS 1.3 AAD 
    // ===================

    std::vector<uint8_t> build_tls13_aad( tls_content_type content_type, tls_version version, uint16_t length ) {
        return {
            static_cast<uint8_t>( content_type ),        
            extract_most_significant_byte( version ),      
            extract_least_significant_byte( version ),  
            extract_most_significant_byte( length ),         
            extract_least_significant_byte( length )    
        };
    }

    // ==================
    //  Decrypt TLS Data 
    // ==================

    std::vector<tls_record> decrypt_tls_data( const std::array<uint8_t,32>& client_random,
                                              const std::array<uint8_t,32>& server_random,
                                              const tls_version version,
                                              const uint16_t cipher_suite_id,
                                              const std::vector<tls_record>& encrypted_records,
                                              const secrets& session_keys,
                                              const std::string& secret_label ) {
        const cipher_suite suite = static_cast<cipher_suite>( cipher_suite_id );
        const EVP_MD* hash_fn = nullptr;
        const EVP_CIPHER* cipher = nullptr;
        std::size_t key_len = 0;
        switch ( suite ) {
            case cipher_suite::TLS_AES_128_GCM_SHA256:
                hash_fn = EVP_sha256();
                cipher = EVP_aes_128_gcm();
                key_len = 16;
                break;
            case cipher_suite::TLS_AES_256_GCM_SHA384:
                hash_fn = EVP_sha384();
                cipher = EVP_aes_256_gcm();
                key_len = 32;
                break;
            default:
                throw std::runtime_error( "Unsupported cipher suite" );
        }

        auto secret = get_traffic_secret( session_keys, client_random, secret_label );
        auto key_material = derive_tls_key_iv( secret, hash_fn, key_len, 12 );
        std::vector<tls_record> result;
        uint64_t seq_num = 0;
        for ( const auto& record : encrypted_records ) {
            if ( record.content_type != tls_content_type::application_data ) {
                result.push_back( record );
                continue;
            }
            auto nonce = build_tls13_nonce( key_material.iv, seq_num );
            auto aad = build_tls13_aad( record.content_type, record.version, record.payload.size() );
            auto decrypted_payload = decrypt_aes_gcm( key_material.key, nonce, aad, record.payload, cipher );
            result.push_back( { record.content_type, record.version, decrypted_payload } );
            seq_num++;
        }
        return result;
    }

    // ================
    //  Decrypt Record 
    // ================

    tls_record decrypt_record( const std::array<uint8_t,32>& client_random,
                               const std::array<uint8_t,32>& server_random,
                               const tls_version version,
                               const uint16_t cipher_suite_id,
                               const tls_record& record,
                               const secrets& session_keys,
                               const std::string& secret_label,
                               uint64_t seq_num ) {
        const cipher_suite suite = static_cast<cipher_suite>( cipher_suite_id );
        const EVP_MD* hash_fn = nullptr;
        const EVP_CIPHER* cipher = nullptr;
        std::size_t key_len = 0;
        switch ( suite ) {
            case cipher_suite::TLS_AES_128_GCM_SHA256:
                hash_fn = EVP_sha256();
                cipher = EVP_aes_128_gcm();
                key_len = 16;
                break;
            case cipher_suite::TLS_AES_256_GCM_SHA384:
                hash_fn = EVP_sha384();
                cipher = EVP_aes_256_gcm();
                key_len = 32;
                break;
            case cipher_suite::TLS_CHACHA20_POLY1305_SHA256:
            case cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            case cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
                hash_fn = EVP_sha256();
                cipher = EVP_chacha20_poly1305();
                key_len = 32;
                break;
            default:
                throw std::runtime_error( "Unsupported cipher suite" );
        }
        auto secret = get_traffic_secret( session_keys, client_random, secret_label );
        auto key_material = derive_tls_key_iv( secret, hash_fn, key_len, 12 );
        auto nonce = build_tls13_nonce( key_material.iv, seq_num );
        auto aad = build_tls13_aad( record.content_type, record.version, record.payload.size() );
        auto decrypted_payload = decrypt_aes_gcm( key_material.key, nonce, aad, record.payload, cipher );
        tls_record result { record.content_type, record.version, decrypted_payload };
        return result;
    }

    // ================
    //  Encrypt Record 
    // ================

    tls_record encrypt_record( const std::array<uint8_t,32>& client_random,
                               const std::array<uint8_t,32>& server_random,
                               const tls_version version,
                               const uint16_t cipher_suite_id,
                               const tls_record& record,
                               const secrets& session_keys,
                               const std::string& secret_label,
                               uint64_t seq_num ) {
        constexpr std::size_t tag_length = 16;
        const cipher_suite suite = static_cast<cipher_suite>( cipher_suite_id );
        const EVP_MD* hash_fn = nullptr;
        const EVP_CIPHER* cipher = nullptr;
        std::size_t key_len = 0;
        switch ( suite ) {
            case cipher_suite::TLS_AES_128_GCM_SHA256:
                hash_fn = EVP_sha256();
                cipher = EVP_aes_128_gcm();
                key_len = 16;
                break;
            case cipher_suite::TLS_AES_256_GCM_SHA384:
                hash_fn = EVP_sha384();
                cipher = EVP_aes_256_gcm();
                key_len = 32;
                break;
            case cipher_suite::TLS_CHACHA20_POLY1305_SHA256:
            case cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            case cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
                hash_fn = EVP_sha256();
                cipher = EVP_chacha20_poly1305();
                key_len = 32;
                break;
            default:
                throw std::runtime_error( "Unsupported cipher suite" );
        }
        auto secret = get_traffic_secret( session_keys, client_random, secret_label );
        auto key_material = derive_tls_key_iv( secret, hash_fn, key_len, 12 );
        std::vector<uint8_t> plain_text = record.payload;
        auto nonce = build_tls13_nonce( key_material.iv, seq_num );
        std::size_t expected_cipher_len = plain_text.size() + tag_length;
        auto aad = build_tls13_aad( record.content_type, record.version, static_cast<uint16_t>( expected_cipher_len ) );
        auto cipher_text_with_tag = encrypt_aes_gcm( key_material.key, nonce, aad, plain_text, cipher );
        return tls_record {
            record.content_type,
            record.version,
            cipher_text_with_tag
        };
    }

    // =====================
    //  Extract Certificate 
    // =====================

    std::vector<uint8_t> extract_certificate( const std::vector<uint8_t>& handshake_payload ) {
        std::size_t pos = 4; 
        uint8_t context_len = handshake_payload[ pos++ ];
        pos += context_len;
        uint32_t cert_list_len = ( handshake_payload[ pos ] << 16 ) |
                                 ( handshake_payload[ pos + 1 ] << 8 ) |
                                   handshake_payload[ pos + 2 ];
        pos += 3;
        uint32_t cert_len = ( handshake_payload[ pos ] << 16 ) |
                            ( handshake_payload[ pos + 1 ] << 8 ) |
                              handshake_payload[ pos + 2 ];
        pos += 3;
        std::vector<uint8_t> cert( handshake_payload.begin() + pos,
                                   handshake_payload.begin() + pos + cert_len );
        return cert;
    }

    // ====================
    //  Is Complete Record 
    // ====================

    bool is_complete_record( const std::span<const uint8_t> record_bytes ) {
        if ( record_bytes.size() < constants::record_header_len ) { 
            return false;
        }
        const uint16_t record_payload_len = read_uint16_be( record_bytes, record_header_offset::payload_len );
        const std::size_t total_len = constants::record_header_len + record_payload_len;
        return record_bytes.size() == total_len;
    }

    // ========
    //  Is TLS 
    // ========

    std::expected<bool,std::string> is_tls( const unsigned char* packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return false;
        }
        auto& payload = *payload_result.value();
        return is_tls_payload( payload );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<bool,std::string> is_tls( std::span<const uint8_t> packet ) {
        return is_tls( packet.data() );
    }

    // ================
    //  Is TLS Payload 
    // ================

    std::expected<bool,std::string> is_tls_payload( std::span<const uint8_t> payload ) {
        if ( payload.size() < constants::record_header_len ) { 
            return false;
        }
        auto content_type_opt = get_tls_content_type( payload[ record_header_offset::content_type ] );
        auto version_opt = get_tls_version( read_uint16_be( payload, record_header_offset::version ) );
        return content_type_opt && version_opt;
    }

    // =========================
    //  Secret Labels Are Equal 
    // =========================

    bool secret_labels_are_equal( std::array<std::string,5> lhs, std::array<std::string,5> rhs ) {
        std::sort( lhs.begin(), lhs.end() );
        std::sort( rhs.begin(), rhs.end() );
        return lhs == rhs;
    }

    // =========
    //  Get SNI 
    // =========

    std::expected<std::string,std::string> get_sni( const client_hello& hello ) {
        constexpr std::size_t extension_type_field_offset = 0;
        constexpr std::size_t extension_len_field_offset = 2;
        constexpr std::size_t extension_header_len = 4;
        constexpr std::size_t sni_list_len_field_len = 2;
        auto extension_bytes = std::span<const uint8_t>( hello.extensions );

        while ( !extension_bytes.empty() ) {
            if ( extension_bytes.size() < extension_header_len ) {
                return std::unexpected( "Extension too short for Header" );
            }
            const uint16_t extension_type = read_uint16_be( extension_bytes, extension_type_field_offset );
            const uint16_t extension_len = read_uint16_be( extension_bytes, extension_len_field_offset );
            if ( extension_bytes.size() < extension_header_len + extension_len ) {
                return std::unexpected( "Extension body truncated" );
            }
            if ( extension_type == 0x0000 ) {
                if ( extension_len < sni_list_len_field_len ) {
                    return std::unexpected( "SNI Extension too short to contain List Length" );
                }
                const uint16_t sni_list_len = read_uint16_be( extension_bytes, extension_header_len );
                if ( sni_list_len_field_len + sni_list_len > extension_len ) {
                    return std::unexpected( "SNI List length exceeds bounds" );
                }
                auto sni_list = extension_bytes.subspan( extension_header_len + sni_list_len_field_len );
                return parse_sni_list( sni_list );
            }

            extension_bytes = extension_bytes.subspan( extension_header_len + extension_len );
        }
        return std::unexpected( "No Sever Name found" );
    }

     // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<std::string,std::string> get_sni( const std::vector<uint8_t>& hello ) {
        auto client_hello_result = get_client_hello_from_ethernet_frame( hello );
        if ( !client_hello_result ) {
            return std::unexpected( client_hello_result.error() );
        }
        auto sni_result = get_sni( client_hello_result.value() );
        if ( !sni_result ) {
            return std::unexpected( sni_result.error() );
        } 
        return sni_result.value();
    }

    // ================
    //  Parse SNI List 
    // ================

    std::expected<std::string,std::string> parse_sni_list( std::span<const unsigned char>& sni_list ) {
        constexpr std::size_t sni_entry_header_len = 3;
        constexpr std::size_t name_len_offset = 1;
        while ( !sni_list.empty() ) {
            if ( sni_list.size() < sni_entry_header_len ) {
                return std::unexpected( "SNI Entry too short" );
            }
            const uint8_t name_type = sni_list.front();
            const uint16_t name_len = read_uint16_be( sni_list, name_len_offset );
            if ( sni_list.size() < sni_entry_header_len + name_len ) {
                return std::unexpected( "Server Name truncated" );
            }

            std::string server_name( sni_list.begin() + sni_entry_header_len,
                                     sni_list.begin() + sni_entry_header_len + name_len );
            return server_name;
            sni_list = sni_list.subspan( sni_entry_header_len + name_len );
        }
        return std::unexpected( "No Server Name found" );
    }

    // =========
    //  Has SNI 
    // =========

    std::expected<bool,std::string> has_sni( const client_hello& hello, const std::string& host ) {
        auto result = get_sni( hello );
        if ( !result.has_value() ) {
            return std::unexpected( result.error() );  
        }
        return result.value() == host;
    }

    // ==============
    //  SNI Contains 
    // ==============

    std::expected<bool,std::string> sni_contains( const client_hello& hello, const std::string& host ) {
        auto result = get_sni( hello );
        if ( !result ) {
            return std::unexpected( result.error() );  
        }
        return result.value().contains( host );
    }

    // ==========
    //  Get SNIs 
    // ==========

    std::vector<std::string> get_snis( const session& packets, const std::string& host ) {
        std::vector<std::string> snis;
        for ( auto& client_hello_packet : packets | std::views::filter( client_hello_filter ) ) {
            auto client_hello_result = get_client_hello_from_ethernet_frame( client_hello_packet );
            if ( !client_hello_result ) {
                continue;
            }
            auto sni_result = get_sni( client_hello_result.value() );
            if ( !sni_result ) {
                continue;
            }
            if ( sni_result.value().contains( host ) ) {
                snis.push_back( sni_result.value() );
            }
        }
        return snis;
    }

    // ===============
    //  Get SNI To IP 
    // ===============

    sni_to_ip get_sni_to_ip( const session& packets ) {
        sni_to_ip results;
        for ( auto& client_hello_packet : packets | std::views::filter( client_hello_filter ) ) {
            auto sni_result = get_sni( client_hello_packet );
            if ( !sni_result ) {
                continue;
            }
            auto header_result = get_parsed_ipv4_header_from_ethernet( client_hello_packet );
            if ( !header_result ) {
                continue;
            }
            if ( !results.contains( sni_result.value() ) ) {
                results[ sni_result.value() ] = header_result.value().destination_ip_addr;
            }
        }
        return results;
    }

    // ==============
    //  TLS Over TCP 
    // ==============

    tls_over_tcp::tls_over_tcp( const four_tuple& four )
        : tcp_transfer( four ) {}

    // =================
    //  TLS Live Stream 
    // =================

    tls_live_stream::tls_live_stream( const tcp_live_stream& tcp_stream ) 
        : tcp_live_stream( tcp_stream ) {
        bool found_client_hello = false;

        for ( auto& packet : m_traffic ) {
            if ( is_client_hello( packet ) ) {
                auto client_hello_result = get_client_hello_from_ethernet_frame( packet );
                if ( !client_hello_result ) {
                    std::cerr << client_hello_result.error() << std::endl;
                    return;
                }
                m_client_hello = client_hello_result.value();
                found_client_hello = true;
                break;
            }
        }
        if ( found_client_hello ) {
            auto sni_result = ntk::get_sni( m_client_hello );
            if ( !sni_result ) {
                m_sni = sni_result.error();
            } else {
                m_sni = sni_result.value();
            }
        } else {
            m_sni = "No ClientHello found.";
        }
    }

    // ============================
    //  TLS Live Stream :: Get SNI 
    // ============================
    
    const std::string& tls_live_stream::get_sni() const {
        return m_sni;
    }

    // =========================
    //  TLS Live Stream :: Feed 
    // =========================

    std::expected<bool,std::string> tls_live_stream::feed( std::span<const uint8_t> packet ) {
        m_decrypted_records = std::nullopt;
        if ( !m_handshake_feed.m_complete ) { 
            return tcp_live_stream::feed( packet );
        }
        if ( !m_client_hello_populated ) {
            auto is_client_hello_result = ntk::is_client_hello( packet );
            if ( !is_client_hello_result ) {
                return std::unexpected( is_client_hello_result.error() );
            }
            if ( is_client_hello_result.value() ) { 
                return populate_client_hello( packet ); 
            }
        }
        if ( !m_server_hello_populated ) { 
            populate_server_hello( packet );
            if ( m_server_hello_populated ) { 
                auto [ tls_secrets, line_reached ] = get_tls_secrets_dynamically( m_ssl_keys_log, m_client_hello.random );
                m_tls_secrets = tls_secrets;
                m_lines_consumed = line_reached;
                return true; 
            }
        }
        auto is_data_packet_result = is_data_packet( packet );
        if ( !is_data_packet_result ) {
            return std::unexpected( is_data_packet_result.error() );
        }
        auto is_client_packet_result = is_client_packet( packet );
        if ( !is_client_packet_result ) {
            return std::unexpected( is_client_packet_result.error() );
        }
        if ( is_data_packet_result.value() && is_client_packet_result.value() ) {
            return handle_client_data_packet( packet );
        }
        auto is_server_packet_result = is_server_packet( packet );
        if ( !is_server_packet_result ) {
            return std::unexpected( is_server_packet_result.error() );
        }
        if ( is_data_packet_result.value() && is_server_packet_result.value() ) {
            return handle_server_data_packet( packet );
        }
        return false;
    }

    // ==============================================
    //  TLS Live Stream :: Handle Client Data Packet 
    // ==============================================

    std::expected<bool,std::string> tls_live_stream::handle_client_data_packet( std::span<const uint8_t> client_data_packet ) {
        auto result = get_tls_record_from_ethernet( client_data_packet );
        if ( !result ) {
            return false;
        }
        auto& encrypted_record = result.value();
        if ( is_change_cipher_spec( encrypted_record ) ) {
            return false;
        }
        if ( has_client_traffic_secret() ) {
            auto decrypted_record = decrypt_record( m_client_hello.random, 
                                                    m_server_hello.random, 
                                                    m_server_hello.server_version, 
                                                    m_server_hello.cipher_suite, 
                                                    encrypted_record,
                                                    m_tls_secrets, 
                                                    "CLIENT_TRAFFIC_SECRET_0", 
                                                    m_client_traffic_seq_number );
            m_decrypted_records.emplace();
            m_decrypted_records->push_back( std::move( decrypted_record ) );
            ++m_client_traffic_seq_number;
        }
        return true;
    }

    // ==============================================
    //  TLS Live Stream :: Handle Server Data Packet 
    // ==============================================

    std::expected<bool,std::string> tls_live_stream::handle_server_data_packet( std::span<const uint8_t> server_data_packet ) {
        auto is_tls_result = is_tls( server_data_packet );
        if ( !is_tls_result ) { 
            return std::unexpected( is_tls_result.error() );
        }
        if ( !is_tls_result.value() && !m_incomplete_record ) {
            return false;
        }
        std::optional<std::vector<tls_record>> encrypted_records; 
        auto payload_result = get_tcp_payload( server_data_packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        auto& payload = *payload_result.value();
        std::span<const uint8_t> payload_span( payload.data(), payload.size() ); 
        while ( !payload_span.empty() ) {
            if ( m_incomplete_record ) {
                handle_incomplete_record( server_data_packet, encrypted_records, payload_span );
            } else {
                auto result = handle_complete_record( encrypted_records, payload_span );
                if ( !result ) {
                    return std::unexpected( result.error() );
                }
            }
        }
        if ( encrypted_records ) {
            return decrypt_server_records( encrypted_records.value() );
        }
        return false;
    }

    // =============================================
    //  TLS Live Stream :: Handle Incomplete Record 
    // =============================================

    void tls_live_stream::handle_incomplete_record( std::span<const uint8_t> server_data_packet,
                                                    std::optional<std::vector<tls_record>>& encrypted_records,
                                                    std::span<const uint8_t>& payload_span ) {
        std::size_t payload_size_before = m_incomplete_record.value().record.payload.size();
        auto record_variant = append_to_incomplete_record( m_incomplete_record.value(), server_data_packet );
        if ( std::holds_alternative<tls_record>( record_variant ) ) {
            if ( !encrypted_records ) encrypted_records.emplace();
            std::size_t payload_size_after = std::get<tls_record>( record_variant ).payload.size();
            encrypted_records->push_back( std::move( std::get<tls_record>( record_variant ) ) );
            std::size_t bytes_consumed = payload_size_after - payload_size_before;
            payload_span = payload_span.subspan( bytes_consumed );
            m_incomplete_record.reset();
        } else {
            m_incomplete_record.value().record.payload.insert( m_incomplete_record.value().record.payload.end(), 
                                                               payload_span.begin(), payload_span.end() );
            payload_span = payload_span.subspan( 0, 0 );
        }
    }

    // ===========================================
    //  TLS Live Stream :: Handle Complete Record 
    // ===========================================

    std::expected<bool,std::string> tls_live_stream::handle_complete_record( std::optional<std::vector<tls_record>>& encrypted_records,   
                                                                             std::span<const uint8_t>& payload_span ) {
        auto split_result = split_tls_records( payload_span );
        if ( !split_result ) {
            return false;
        } else {
            auto [ records, offset_reached ] = split_result.value();
            if ( records.empty() ) {
                auto empty_record_result = get_empty_tls_record_from_payload( payload_span );
                if ( !empty_record_result ) {
                    return std::unexpected( empty_record_result.error() );
                }
                auto record_header = get_tls_record_header_from_payload( payload_span ).value();
                empty_record_result.value().payload.assign( payload_span.begin() + constants::record_header_len, payload_span.end() );
                m_incomplete_record = incomplete_tls_record {
                    empty_record_result.value(),
                    record_header.payload_length
                };
                payload_span = payload_span.subspan( 0, 0 ); 
            } else {
                if ( !encrypted_records ) encrypted_records.emplace();
                encrypted_records->insert( encrypted_records->end(), records.begin(), records.end() );
                payload_span = payload_span.subspan( offset_reached );
            }
        }
        return true;
    } 

    // ===========================================
    //  TLS Live Stream :: Decrypt Server Records 
    // ===========================================

    std::expected<bool,std::string> tls_live_stream::decrypt_server_records( std::span<const tls_record> encrypted_records ) {
        for ( auto& encrypted_record : encrypted_records ) {
            auto decrypted_record = decrypt_record( m_client_hello.random, 
                                                    m_server_hello.random, 
                                                    m_server_hello.server_version, 
                                                    m_server_hello.cipher_suite, 
                                                    encrypted_record,
                                                    m_tls_secrets, 
                                                    "SERVER_TRAFFIC_SECRET_0", 
                                                    m_server_traffic_seq_number );
            if ( !m_decrypted_records ) m_decrypted_records.emplace();
            m_decrypted_records->push_back( std::move( decrypted_record ) );
            ++m_server_traffic_seq_number;
        }
        return true;
    }

    // ================================
    //  TLS Live Stream :: Has Secrets 
    // ================================

    bool tls_live_stream::has_secrets() const {
        return !m_tls_secrets.empty();
    }

    // ==========================================
    //  TLS Live Stream :: Populate Client Hello 
    // ==========================================

    bool tls_live_stream::populate_client_hello( std::span<const uint8_t> packet ) {
        auto result = get_client_hello_from_ethernet_frame( packet );
        if ( result ) {
            m_client_hello = *result;
            m_client_hello_populated = true;
            return true;
        } else {
            return false;
        }
    }

    // ==========================================
    //  TLS Live Stream :: Populate Server Hello 
    // ==========================================

    bool tls_live_stream::populate_server_hello( const std::span<const uint8_t> packet ) {
        auto result = get_server_hello_from_ethernet( packet );
        if ( result ) {
            m_server_hello = *result;
            m_server_hello_populated = true;
            return true;
        } else {
            return false;
        }
    }

    // ==============================================
    //  TLS Live Stream :: Has Client Traffic Secret 
    // ==============================================

    bool tls_live_stream::has_client_traffic_secret() const {
        if ( has_secrets() ) {
            auto it = m_tls_secrets.find( client_random_to_hex( m_client_hello.random ) );
            if ( it != m_tls_secrets.end() && it->second.contains( "CLIENT_TRAFFIC_SECRET_0" ) ) {
                return true;
            }
        }
        return false;
    } 

    // ===================================================
    //  TLS Live Stream Friend Helper :: Get Client Hello 
    // ===================================================

    std::optional<std::reference_wrapper<const client_hello>> tls_live_stream_friend_helper::get_client_hello( const tls_live_stream& t ) {
        if ( t.m_client_hello_populated ) {
            return std::cref( t.m_client_hello );
        } else {
            return std::nullopt;
        }
    }

    // ===================================================
    //  TLS Live Stream Friend Helper :: Get Server Hello 
    // ===================================================

    std::optional<std::reference_wrapper<const server_hello>> tls_live_stream_friend_helper::get_server_hello( const tls_live_stream& t ) {
        if ( t.m_server_hello_populated ) {
            return std::cref( t.m_server_hello );
        } else {
            return std::nullopt;
        }
    }

    // =======================================================
    //  TLS Live Stream Friend Helper :: Get Client Populated 
    // =======================================================

    const bool tls_live_stream_friend_helper::client_hello_populated( const tls_live_stream& t ) {
        return t.m_client_hello_populated;
    }

    // =======================================================
    //  TLS Live Stream Friend Helper :: Get Server Populated 
    // =======================================================

    const bool tls_live_stream_friend_helper::server_hello_populated( const tls_live_stream& t ) {
        return t.m_server_hello_populated;
    }

    // =================================================
    //  TLS Live Stream Friend Helper :: Lines Consumed 
    // =================================================

    const std::size_t tls_live_stream_friend_helper::lines_consumed( const tls_live_stream& t ) {
        return t.m_lines_consumed;
    } 

    // ==============================================
    //  TLS Live Stream Friend Helper :: TLS Secrets 
    // ==============================================

    const secrets tls_live_stream_friend_helper::tls_secrets( const tls_live_stream& t ) {
        return t.m_tls_secrets;
    }

    // ============================================================
    //  TLS Live Stream Friend Helper :: Client Traffic Seq Number 
    // ============================================================

    const int tls_live_stream_friend_helper::client_traffic_seq_number( const tls_live_stream& t ) {
        return t.m_client_traffic_seq_number;
    }

    // ============================================================
    //  TLS Live Stream Friend Helper :: Server Traffic Seq Number 
    // ============================================================

    const int tls_live_stream_friend_helper::server_traffic_seq_number( const tls_live_stream& t ) {
        return t.m_server_traffic_seq_number;
    }

    // ====================================================
    //  TLS Live Stream Friend Helper :: Decrypted Records 
    // ====================================================

    std::optional<std::vector<tls_record>> tls_live_stream_friend_helper::decrypted_records( const tls_live_stream& t ) {
        return t.m_decrypted_records;
    }

    // ========================================================
    //  TLS Live Stream Friend Helper :: Partial Record Buffer 
    // ========================================================

    std::vector<uint8_t> tls_live_stream_friend_helper::partial_record_buffer( const tls_live_stream& t ) {
        return t.m_partial_record_buffer;
    }

    // ========================================================
    //  TLS Live Stream Friend Helper :: Get Incomplete Record 
    // ========================================================

    std::optional<incomplete_tls_record> tls_live_stream_friend_helper::get_incomplete_record( const tls_live_stream& t ) {
        return t.m_incomplete_record;
    }

    // ==================
    //  Log File Trimmer 
    // ==================

    void log_file_trimmer::start() {
        m_thread = std::thread( &log_file_trimmer::run, this );
    }

    void log_file_trimmer::stop() {
        m_stop = true;
        if ( m_thread.joinable() ) m_thread.join();
    }

    void log_file_trimmer::run() {
        while ( !m_stop ) {
            //trim_file;
        }
    }

    // ============
    //  TLS Filter 
    // ============

    bool tls_filter::operator()( const ntk::tcp_live_stream& stream ) {
        return stream.traffic_contains( [] ( const auto& packet ) {
            auto result = is_client_hello( packet ); 
            return result && result.value();     
        });
    }

    // ============
    //  SNI Filter 
    // ============

    sni_filter::sni_filter( const std::string& sni )
        : m_sni( sni ) {}

    // ==================
    //  SNI Filter :: () 
    // ==================

    bool sni_filter::operator()( const ntk::tcp_live_stream& stream ) {
        auto has_matching_sni = [&]( const std::vector<uint8_t> packet ) {
            if ( is_client_hello( packet ) ) {
                auto client_hello_result = get_client_hello_from_ethernet_frame( packet );
                if ( !client_hello_result ) {
                    return false;
                }
                auto sni_result = sni_contains( client_hello_result.value(), m_sni );
                if ( sni_result ) {
                    return sni_result.value(); 
                } else {
                    return false;
                } 
            }
            return false;
        };
        return stream.traffic_contains( has_matching_sni );
    }

    // =====================
    //  Extract TLS Records 
    // =====================

    tls_record_extraction_result extract_tls_records( const std::vector<std::vector<uint8_t>>& payloads ) {
        tls_record_extraction_result result;
        std::vector<uint8_t> remainder;
        for ( auto& payload : payloads ) {
            std::vector<uint8_t> cumulative_payload;
            cumulative_payload.insert( cumulative_payload.end(), remainder.begin(), remainder.end() );
            cumulative_payload.insert( cumulative_payload.end(), payload.begin(), payload.end() );
            auto [ complete_records, offset_reached ] = *split_tls_records( cumulative_payload );
            result.records.insert( result.records.end(), complete_records.begin(), complete_records.end() );
            remainder.assign( cumulative_payload.begin() + offset_reached, cumulative_payload.end() );
        }
        result.has_remainder = !remainder.empty();
        return result;
    }

    // ================
    //  Get TLS Record 
    // ================

    std::expected<tls_record,std::string> get_tls_record_from_ethernet( std::span<const uint8_t> packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return std::unexpected( "TCP Payload is empty" );
        }
        auto payload = *payload_result.value();
        return get_tls_record_from_payload( payload );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<tls_record,std::string> get_tls_record_from_payload( std::span<const uint8_t> payload ) {
        auto result = split_tls_records( payload );
        if ( result.has_value() ) {
            auto [ records, offset_reached ] = result.value();
            if ( records.size() == 0 ) return std::unexpected( "Packet does not contain any records" );
            if ( records.size() != 1 || offset_reached != payload.size() ) std::unexpected( "Packet does not contain a single complete record" );
            return records[ 0 ];
        } else {
            return std::unexpected( result.error() );
        }
    }

    // =============================
    //  Append to Incomplete Record 
    // =============================

    std::variant<tls_record,incomplete_tls_record> append_to_incomplete_record( incomplete_tls_record incomplete_record, std::span<const unsigned char> packet ) {
        if ( incomplete_record.record.payload.size() == incomplete_record.expected_payload_length ) { 
            return incomplete_record.record;
        }
        if ( packet.empty() ) { 
            return incomplete_record;
        }
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return incomplete_record;
        }
        if ( !payload_result.value() ) {
            return incomplete_record;
        }
        auto& payload = *payload_result.value();
        return append_to_incomplete_record_from_payload( incomplete_record, payload );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::variant<tls_record,incomplete_tls_record> append_to_incomplete_record_from_payload( incomplete_tls_record incomplete_record, std::span<const unsigned char> payload ) {
        if ( incomplete_record.record.payload.size() == incomplete_record.expected_payload_length ) { 
            return incomplete_record.record;
        }
        if ( payload.empty() ) { 
            return incomplete_record;
        }
        const std::size_t bytes_required = incomplete_record.expected_payload_length - incomplete_record.record.payload.size();
        if ( bytes_required <= payload.size() ) {
            auto complete_record = tls_record { incomplete_record.record.content_type, incomplete_record.record.version, incomplete_record.record.payload };
            complete_record.payload.insert( complete_record.payload.end(), payload.begin(), payload.begin() + bytes_required );
            return complete_record;
        } 
        incomplete_record.record.payload.insert( incomplete_record.record.payload.end(), payload.begin(), payload.end() );
        return incomplete_record;
    }    

    // ===================================
    //  Get Complete or Incomplete Record 
    // ===================================

    std::expected<std::variant<tls_record,incomplete_tls_record>,std::string> get_complete_or_incomplete_record( std::span<const uint8_t> packet ) {
        auto parse_result = get_parsed_tls_record_from_ethernet( packet );
        if ( !parse_result ) {
            auto empty_record_result = get_empty_tls_record_from_ethernet( packet );
            if ( !empty_record_result ) {
                return std::unexpected( empty_record_result.error() );
            }
            auto& empty_record = empty_record_result.value();
            auto record_header = get_tls_record_header_from_ethernet( packet ).value();
            auto payload = *get_tcp_payload( packet ).value();
            empty_record.payload.assign( payload.begin() + constants::record_header_len, payload.end() );
            return incomplete_tls_record{ empty_record, record_header.payload_length };
        } 
        return parse_result.value();
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<std::variant<tls_record,incomplete_tls_record>,std::string> get_complete_or_incomplete_record_from_payload( std::span<const uint8_t> payload ) {
        auto parse_result = get_parsed_tls_record( payload );
        if ( !parse_result ) {
            auto empty_record_result = get_empty_tls_record_from_payload( payload );
            if ( !empty_record_result ) {
                return std::unexpected( empty_record_result.error() );
            }
            auto& empty_record = empty_record_result.value();
            auto record_header = get_tls_record_header_from_payload( payload ).value();
            empty_record.payload.assign( payload.begin() + constants::record_header_len, payload.end() );
            return incomplete_tls_record{ empty_record, record_header.payload_length };
        }
        return parse_result.value();
    }

    // ======================
    //  Get Empty TLS Record 
    // ======================

    std::expected<tls_record,std::string> get_empty_tls_record_from_ethernet( std::span<const uint8_t> packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return std::unexpected( "TCP Payload is empty" );
        }
        auto& payload = *payload_result.value();
        return get_empty_tls_record_from_payload( payload );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<tls_record,std::string> get_empty_tls_record_from_payload( std::span<const uint8_t> payload ) {
        auto record_header_result = get_tls_record_header_from_payload( payload );
        if ( !record_header_result ) {
            return std::unexpected( record_header_result.error() );
        }
        return tls_record { record_header_result.value().content_type, record_header_result.value().version };
    }

    // =======================
    //  Get TLS Record Header 
    // =======================

    std::expected<tls_record_header,std::string> get_tls_record_header( const std::array<uint8_t,constants::record_header_len> record_header_bytes ) {
        auto content_type_opt = get_tls_content_type( record_header_bytes[ record_header_offset::content_type ] );
        if ( !content_type_opt ) {
            return std::unexpected( "Unrecognized TLS Content Type" );
        }
        auto version_opt = get_tls_version( read_uint16_be( record_header_bytes, record_header_offset::version ) );
        if ( !version_opt ) {
            return std::unexpected( "Unrecognized TLS Version" );
        }
        auto payload_length = read_uint16_be( record_header_bytes, record_header_offset::payload_len );
        return tls_record_header{ content_type_opt.value(), version_opt.value(), payload_length };
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<tls_record_header,std::string> get_tls_record_header_from_ethernet( std::span<const uint8_t> packet ) {
        auto payload_result = get_tcp_payload( packet );
        if ( !payload_result ) {
            return std::unexpected( payload_result.error() );
        }
        if ( !payload_result.value() ) {
            return std::unexpected( "TCP Payload is empty" );
        }
        auto& payload = *payload_result.value();
        return get_tls_record_header_from_payload( payload );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<tls_record_header,std::string> get_tls_record_header_from_payload( std::span<const uint8_t> payload ) {
        if ( payload.size() < constants::record_header_len ) {
            return std::unexpected( "Payload too short for Record Header" );
        }
        std::array<uint8_t,constants::record_header_len> record_header_bytes;
        std::copy_n( payload.begin(), record_header_bytes.size(), record_header_bytes.begin() );
        return get_tls_record_header( record_header_bytes );
    }

} // namespace ntk