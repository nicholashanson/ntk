#include <tls.hpp>

namespace ntk {

    // ==============================
    //           Helpers
    // ==============================

    std::string string_to_hex( const std::vector<uint8_t>& data ) {
        return session_id_to_hex( data );
    }

    std::string client_random_to_hex( const std::array<uint8_t,32>& random ) {
        std::ostringstream oss;
        for ( auto byte : random )
            oss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << int( byte );
        return oss.str();
    }

    std::string session_id_to_hex( const std::vector<uint8_t>& session_id ) {
        std::ostringstream oss;
        for ( auto byte : session_id )
            oss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << int( byte );
        return oss.str();
    }

    // ==============================
    //       Parse Client Hello
    // ==============================

    std::expected<client_hello,std::string> parse_client_hello( const std::span<const uint8_t> client_hello_bytes ) {
        constexpr std::size_t client_version_len = 2;
        constexpr std::size_t random_len = 32;
        constexpr std::size_t session_id_len_pos = client_version_len + random_len;
        constexpr std::size_t min_required = client_version_len + random_len + 1;  // +1 for session_id_len
        if ( client_hello_bytes.size() < min_required ) {
            return std::unexpected( "ClientHello too short for version and random" );
        }

        client_hello c_hello;
        c_hello.client_version = static_cast<tls_version>( read_uint16_be( client_hello_bytes, 0 ) );
        std::memcpy( c_hello.random.data(), &client_hello_bytes[ client_version_len ], random_len );

        const std::size_t session_id_len = client_hello_bytes[ client_version_len + random_len ];
        c_hello.session_id.resize( session_id_len );
        std::memcpy( c_hello.session_id.data(), &client_hello_bytes[ client_version_len + random_len + 1 ], session_id_len );

        const std::size_t cipher_suites_len_pos = session_id_len_pos + 1 + session_id_len;
        const std::size_t cipher_suites_pos = cipher_suites_len_pos + 2;
        std::size_t cipher_suites_len = read_uint16_be( client_hello_bytes, cipher_suites_len_pos );
        c_hello.cipher_suites.resize( cipher_suites_len );
        std::memcpy( c_hello.cipher_suites.data(), &client_hello_bytes[ cipher_suites_pos ], cipher_suites_len );
        
        const std::size_t compression_methods_len_pos = cipher_suites_pos + cipher_suites_len;
        const std::size_t compression_methods_len = client_hello_bytes[ compression_methods_len_pos ];
        c_hello.compression_methods.resize( compression_methods_len );
        std::memcpy( c_hello.compression_methods.data(), &client_hello_bytes[ compression_methods_len_pos + 1 ], compression_methods_len );

        const std::size_t extensions_len_pos = compression_methods_len_pos + 1 + compression_methods_len;
        const std::size_t extensions_len = read_uint16_be( client_hello_bytes, extensions_len_pos );
        c_hello.extensions.resize( extensions_len );
        std::memcpy( c_hello.extensions.data(), &client_hello_bytes[ extensions_len_pos + 2 ], extensions_len );

        return c_hello;
    }

    // ==============================
    //        Get Client Hello
    // ==============================

    std::expected<client_hello,std::string> get_client_hello( const std::span<const uint8_t> tcp_payload ) {   
        auto client_hello_bytes = tcp_payload.subspan( 9 );
        return parse_client_hello( client_hello_bytes );
    }

    std::expected<client_hello,std::string> get_client_hello( const std::vector<uint8_t>& tcp_payload ) {     
        auto tls_record_span = std::span<const uint8_t>( tcp_payload );
        auto client_hello_bytes = tls_record_span.subspan( 9 );
        return parse_client_hello( client_hello_bytes );
    }

    std::expected<client_hello,std::string> get_client_hello_from_ethernet_frame( const unsigned char* ethernet_frame ) {
        auto tcp_payload = get_tcp_payload( ethernet_frame );
        return get_client_hello( tcp_payload );
    }

    std::expected<client_hello,std::string> get_client_hello_from_ethernet_frame( const std::vector<uint8_t>& ethernet_frame ) {
        return get_client_hello_from_ethernet_frame( ethernet_frame.data() );
    }

    std::expected<client_hello,std::string> get_client_hello( const tls_record& record ) {
        auto client_hello_bytes = std::span<const uint8_t>( record.payload ).subspan( 4 );
        return parse_client_hello( client_hello_bytes );
    }

    // ==============================
    //    Client Hello Predicates
    // ==============================

    bool is_client_hello( const unsigned char* packet ) {
        if ( !is_tls( packet ) ) return false;
        auto tls_record = get_tcp_payload( packet );
        uint8_t content_type = tls_record[ 0 ];
        if ( content_type != 22 ) return false;
        uint8_t handshake_t = tls_record[ 5 ];
        return static_cast<handshake_type>( handshake_t ) == handshake_type::CLIENT_HELLO; 
    }

    bool is_client_hello_v( const std::vector<uint8_t>& packet ) {
        return is_client_hello( packet.data() );
    }

    bool is_client_hello( const tls_record& record ) {
        if ( record.content_type != tls_content_type::HANDSHAKE ) return false;
        if ( record.payload.empty() ) return false;
        uint8_t handshake_t = record.payload[ 0 ];
        return static_cast<handshake_type>( handshake_t ) == handshake_type::CLIENT_HELLO;
    }

    // ==============================
    //       Parse Server Hello
    // ==============================

    std::expected<server_hello,std::string> parse_server_hello( const std::span<const uint8_t> server_hello_bytes ) {
        constexpr std::size_t version_len = 2;
        constexpr std::size_t random_len = 32;
        constexpr std::size_t session_id_len_pos = version_len + random_len; 
        constexpr std::size_t min_required = session_id_len_pos + 1; 
        if ( server_hello_bytes.size() < min_required ) {
            return std::unexpected( "ServerHello too short for version and random" );
        }

        server_hello s_hello;
        s_hello.server_version = static_cast<tls_version>( read_uint16_be( server_hello_bytes, 0 ) );
        std::memcpy( s_hello.random.data(), &server_hello_bytes[ version_len ], random_len );

        auto session_id_result = get_server_hello_session_id( server_hello_bytes, s_hello );
        if ( !session_id_result ) {
            return std::unexpected( session_id_result.error() );
        }

        const std::size_t session_id_len = s_hello.session_id.size();
        const std::size_t cipher_suite_pos = session_id_len_pos + 1 + session_id_len;
        auto cipher_suite_result = get_server_hello_cipher_suite( server_hello_bytes, cipher_suite_pos );
        if ( cipher_suite_result ) {
            s_hello.cipher_suite = cipher_suite_result.value();
        } else {
            return std::unexpected( cipher_suite_result.error() );
        }

        const std::size_t compression_method_pos = cipher_suite_pos + 2;
        if ( server_hello_bytes.size() < compression_method_pos + 1 + 2 ) {
            return std::unexpected( "ServerHello too short for compression method" );
        }
        s_hello.compression_method = server_hello_bytes[ compression_method_pos ];

        const std::size_t extensions_len_pos = compression_method_pos + 1;
        auto extensions_result = get_server_hello_extensions( server_hello_bytes, s_hello, extensions_len_pos );
        if ( !extensions_result ) {
            return std::unexpected( session_id_result.error() );
        }
        return s_hello;
    }

    // ==============================
    // Get Server Hello Cipher Suite
    // ==============================

    std::expected<uint16_t,std::string> get_server_hello_cipher_suite( const std::span<const uint8_t>& server_hello_bytes, const std::size_t cipher_suite_pos ) {
        if ( server_hello_bytes.size() < cipher_suite_pos + 1 + 2 ) {
            return std::unexpected( "ServerHello too short cipher suite" );
        }
        return read_uint16_be( server_hello_bytes, cipher_suite_pos );
    }

    // ==============================
    //  Get Server Hello Session ID
    // ==============================

    std::expected<void,std::string> get_server_hello_session_id( const std::span<const uint8_t>& server_hello_bytes, server_hello& s_hello ) {
        constexpr std::size_t version_len = 2;
        constexpr std::size_t random_len = 32;
        constexpr std::size_t session_id_len_pos = version_len + random_len;
        const std::size_t session_id_len = server_hello_bytes[ session_id_len_pos ];
        if ( server_hello_bytes.size() < session_id_len_pos + 1 + session_id_len ) {
            return std::unexpected( "ServerHello too short for session id" );
        }
        s_hello.session_id.resize( session_id_len );
        std::memcpy( s_hello.session_id.data(), &server_hello_bytes[ session_id_len_pos + 1 ], session_id_len );
        return {};
    }

    // ==============================
    //   Get Server Hello Extensions
    // ==============================

    std::expected<void,std::string> get_server_hello_extensions( const std::span<const uint8_t>& server_hello_bytes, server_hello s_hello,
                                                                 const std::size_t extensions_len_pos ) {
        const std::size_t extensions_len = read_uint16_be( server_hello_bytes, extensions_len_pos );
        if ( server_hello_bytes.size() < extensions_len_pos + 1 + extensions_len ) {
            return std::unexpected( "ServerHello too short extensions" );
        }
        s_hello.extensions.resize( extensions_len );
        std::memcpy( s_hello.extensions.data(), &server_hello_bytes[ extensions_len_pos + 2 ], extensions_len );
        return {};
    }

    // ==============================
    //        Get Server Hello
    // ==============================

    std::expected<server_hello,std::string> get_server_hello( const std::span<const uint8_t> tcp_payload ) {
        auto server_hello_bytes = tcp_payload.subspan( 9 );
        return parse_server_hello( server_hello_bytes );
    }

    std::expected<server_hello,std::string> get_server_hello_from_ethernet_frame( const unsigned char* ethernet_frame ) {
        auto tcp_payload = get_tcp_payload( ethernet_frame );
        auto split_result = split_tls_records( tcp_payload );
        if ( !split_result ) {
            return std::unexpected( split_result.error() );
        }
        auto [ records, offset_reached ] = *split_result;
        if ( records.empty() ) {
            return std::unexpected( "The ethernet frame contains no complete TLS records" );
        }  
        auto& server_hello_record = records.front();
        if ( !is_server_hello( server_hello_record ) ) {
            return std::unexpected( "The first record found in the ethernet frame is not a valid ServerHello" );
        }
        auto server_hello_bytes = std::span<const uint8_t>( server_hello_record.payload ).subspan( 4 );
        return parse_server_hello( server_hello_bytes );
    }

    std::expected<server_hello,std::string> get_server_hello_from_ethernet_frame( const std::vector<uint8_t>& ethernet_frame ) {
        return get_server_hello_from_ethernet_frame( ethernet_frame.data() );
    }

    std::expected<server_hello,std::string> get_server_hello( const tls_record& record ) {
        auto server_hello_bytes = std::span<const uint8_t>( record.payload ).subspan( 4 );
        return parse_server_hello( server_hello_bytes ); 
    }

    // ==============================
    //       Split TLS Records 
    // ==============================

    std::expected<
        std::tuple<std::vector<tls_record>,size_t>,
        std::string
    > split_tls_records( std::span<const uint8_t> tls_payload ) {
        std::size_t offset_reached = 0;
        if ( tls_payload.size() == 0 ) return std::unexpected( "TLS payload is empty" );
        std::vector<tls_record> records;

        while ( !tls_payload.empty() ) {
            if ( tls_payload.size() < 5 ) {
                return std::unexpected( "TLS payload too short for record header" ); 
            }
            uint16_t record_len = read_uint16_be( tls_payload, 3 );
            std::size_t full_record_len = 5 + record_len;

            if ( tls_payload.size() < full_record_len ) {
                break;
            }
            auto record_span = tls_payload.first( full_record_len );
            auto result = get_parsed_tls_record( record_span );
            if ( !result ) {
                return std::unexpected( "Failed to parse TLS record: " + result.error() );
            }
            records.push_back( std::move( result.value() ) );
            offset_reached += full_record_len;
            tls_payload = tls_payload.subspan( full_record_len );
        }
        return std::make_tuple( records, offset_reached );
    }

    std::expected<
        std::tuple<std::vector<tls_record>,size_t>,
        std::string
    > get_tls_records_from_ethernet( std::span<const uint8_t> packet ) {
        auto tls_payload = get_tcp_payload( packet );
        return split_tls_records( tls_payload );
    }

    // ==============================
    //      Get Parsed TLS Record 
    // ==============================

    std::expected<tls_record,std::string> get_parsed_tls_record( std::span<const uint8_t> raw_tls_record ) {
        if ( raw_tls_record.size() < 5 ) {
            return std::unexpected("TLS record too short to contain header");
        }
        tls_record record;
        record.content_type = static_cast<tls_content_type>( raw_tls_record[ 0 ] );
        record.version = static_cast<tls_version>( read_uint16_be( raw_tls_record, 1 ) );
        uint16_t record_len = read_uint16_be( raw_tls_record, 3 );
        if ( raw_tls_record.size() < 5 + record_len ) {
            return std::unexpected( "TLS record payload length exceeds buffer size" );
        }
        record.payload.assign( raw_tls_record.begin() + 5, raw_tls_record.begin() + 5 + record_len );
        return record;
    }

    std::expected<tls_record,std::string> get_parsed_tls_record_from_ethernet( std::span<const unsigned char> packet ) {
        auto payload = get_tcp_payload( packet );
        return get_parsed_tls_record( payload );
    }

    // ==============================
    //    Server Hello Predicates
    // ==============================

    bool is_server_hello( const unsigned char* packet ) {
        if ( !is_tls( packet ) ) return false;
        auto tls_record = get_tcp_payload( packet );
        if ( tls_record.size() < 6 ) return false;
        uint8_t content_type = tls_record[ 0 ];
        if ( content_type != 22 ) return false;
        uint8_t handshake_t = tls_record[ 5 ];
        return static_cast<handshake_type>( handshake_t ) == handshake_type::SERVER_HELLO; 
    }

    bool is_server_hello_v( const std::vector<uint8_t>& packet ) {
        return is_server_hello( packet.data() );
    }

    bool is_server_hello(const tls_record& record) {
        if ( record.content_type != tls_content_type::HANDSHAKE ) return false;
        if ( record.payload.empty() ) return false;
        uint8_t handshake_t = record.payload[ 0 ];
        return static_cast<handshake_type>( handshake_t ) == handshake_type::SERVER_HELLO;
    }

    // ==============================
    //        Alert Predicates
    // ==============================

    bool is_tls_alert( const unsigned char* packet ) {
        if ( !is_tls( packet ) ) return false;
        auto tls_record = get_tcp_payload( packet );
        if ( tls_record.size() < 7 ) return false; 
        uint8_t content_type = tls_record[ 0 ];
        if ( content_type != 20 ) return false; 
        uint16_t length = ( tls_record[ 3 ] << 8 ) | tls_record[ 4 ];
        if ( length < 2 ) return false; 
        uint8_t alert_level = tls_record[ 5 ];       
        uint8_t alert_description = tls_record[ 6 ];
        if ( alert_level != 1 && alert_level != 2 ) return false;
        return true;
    }

    bool is_tls_alert_v( const std::vector<uint8_t>& packet ) {
        return is_tls_alert( packet.data() );
    }

    bool is_tls_alert( const tls_record& record ) {
        return record.content_type == tls_content_type::ALERT;
    }

    // ==============================
    //  Change Cipher Spec Predicates
    // ==============================

    bool is_change_cipher_spec( const tls_record& record ) {
        return record.content_type == tls_content_type::CHANGE_CIPHER_SPEC;    
    }

    // ==============================
    //  Application Data Predicates
    // ==============================

    bool is_tls_application_data( const tls_record& record ) {
        return record.content_type == tls_content_type::APPLICATION_DATA;
    }

    // ==============================
    //       Get Traffic Secret
    // ==============================

    std::vector<uint8_t> get_traffic_secret( const secrets& session_keys,
                                             const std::array<uint8_t,32>& client_random,
                                             const std::string& label ) {
        auto client_hex = client_random_to_hex( client_random );
        return session_keys.at( client_hex ).at( label );
    }

    // ==============================
    //         Get TLS Secrets
    // ==============================

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
            for ( size_t i = 0; i < secret_hex.size(); i += 2 ) {
                secret.push_back( std::stoi( secret_hex.substr( i, 2 ), nullptr, 16 ) );
            }

            tls_secrets[ client_random_hex ][ label ] = secret;
        }

        return tls_secrets;
    }

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
            for ( size_t i = 0; i < secret_hex.size(); i += 2 ) {
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
            for ( size_t i = 0; i < secret_hex.size(); i += 2 ) {
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

    // ==============================
    //       Is Complete Secrets
    // ==============================

    bool is_complete_secrets( const std::map<std::string,std::vector<uint8_t>>& secrets ) {
        if ( secrets.size() != 5 ) return false;
        std::array<std::string,5> labels;
        size_t count = 0;
        for ( auto [ label, secret ] : secrets ) {
            labels[ count ] = label;
            count += 1;
        }
        return secret_labels_are_equal( labels, tls_secret_labels );
    }

    // ==============================
    //       TLS Label Expansion
    // ==============================

    std::vector<uint8_t> hkdf_expand_label( const std::vector<uint8_t>& secret, const std::string& label,              
                                            const std::vector<uint8_t>& context, size_t out_len, const EVP_MD* hash_func ) {
        std::string full_label = "tls13 " + label;
        std::vector<uint8_t> hkdf_label;

        hkdf_label.push_back( static_cast<uint8_t>( ( out_len >> 8 ) & 0xFF ) );
        hkdf_label.push_back( static_cast<uint8_t>( out_len & 0xFF ) );
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

    // ==============================
    //      TLS Key Derivation
    // ==============================

    tls_key_material derive_tls_key_iv( const std::vector<uint8_t>& secret, const EVP_MD* hash_func,
                                        size_t key_len, size_t iv_len ) {
        tls_key_material km;
        std::vector<uint8_t> context; 
        km.key = hkdf_expand_label( secret, "key", context, key_len, hash_func );
        km.iv = hkdf_expand_label( secret, "iv",  context, iv_len,  hash_func );
        return km;
    }

    // ==============================
    //     TLS Nonce Construction
    // ==============================

    std::vector<uint8_t> build_tls13_nonce( const std::vector<uint8_t>& base_iv, uint64_t seq_num ) {
        std::vector<uint8_t> nonce = base_iv;
        for ( int i = 0; i < 8; ++i ) {
            nonce[ nonce.size() - 8 + i ] ^= static_cast<uint8_t>( ( seq_num >> ( 56 - 8 * i ) ) & 0xff );
        }
        return nonce;
    }

    // ==============================
    //   TLS Decryption - AES-GCM
    // ==============================

    std::vector<uint8_t> decrypt_aes_gcm( const std::vector<uint8_t>& key,
                                          const std::vector<uint8_t>& nonce,
                                          const std::vector<uint8_t>& aad,
                                          const std::vector<uint8_t>& cipher_text_with_tag,
                                          const EVP_CIPHER* cipher ) {
        std::size_t cipher_len = cipher_text_with_tag.size() - 16;
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

    // ==============================
    //   TLS Encryption - AES-GCM
    // ==============================

    std::vector<uint8_t> encrypt_aes_gcm( const std::vector<uint8_t>& key,
                                          const std::vector<uint8_t>& nonce,
                                          const std::vector<uint8_t>& aad,
                                          const std::vector<uint8_t>& plain_text,
                                          const EVP_CIPHER* cipher ) {
        std::vector<uint8_t> cipher_text_with_tag( plain_text.size() + 16 );
        
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
        EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_GET_TAG, 16, cipher_text_with_tag.data() + plain_text.size() );

        EVP_CIPHER_CTX_free( ctx );
        return cipher_text_with_tag;
    }

    // ==============================
    //   TLS Decryption - Build AAD
    // ==============================

    std::vector<uint8_t> build_tls13_aad( tls_content_type content_type, tls_version version, uint16_t length ) {
        return {
            static_cast<uint8_t>( content_type ),        
            extract_most_significant_byte( version ),      
            extract_least_significant_byte( version ),  
            extract_most_significant_byte( length ),         
            extract_least_significant_byte( length )    
        };
    }

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
            if ( record.content_type != tls_content_type::APPLICATION_DATA ) {
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

    // ==============================
    //        Decrypt Record
    // ==============================

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

    // ==============================
    //        Decrypt Record
    // ==============================

    tls_record encrypt_record( const std::array<uint8_t,32>& client_random,
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
            default:
                throw std::runtime_error( "Unsupported cipher suite" );
        }
        auto secret = get_traffic_secret( session_keys, client_random, secret_label );
        auto key_material = derive_tls_key_iv( secret, hash_fn, key_len, 12 );
        std::vector<uint8_t> plain_text = record.payload;
        auto nonce = build_tls13_nonce( key_material.iv, seq_num );
        std::size_t expected_cipher_len = plain_text.size() + 16;
        auto aad = build_tls13_aad( record.content_type, record.version, static_cast<uint16_t>( expected_cipher_len ) );
        auto cipher_text_with_tag = encrypt_aes_gcm( key_material.key, nonce, aad, plain_text, cipher );
        return tls_record {
            record.content_type,
            record.version,
            cipher_text_with_tag
        };
    }

    // ==============================
    //         Certificate
    // ==============================

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

    // ==============================
    //      TLS Record Predicates
    // ==============================

    bool is_complete_record( std::span<const unsigned char> record_bytes ) {
        if ( record_bytes.size() < 5 ) {
            return false;
        }
        uint16_t record_len = ( static_cast<uint16_t>( record_bytes[ 3 ] ) << 8 ) | record_bytes[ 4 ];
        std::size_t total_len = 5 + record_len;
        return record_bytes.size() == total_len;
    }

    bool is_tls( const unsigned char* packet ) {
        if ( !is_tcp( packet ) ) return false;
        auto tcp_payload = get_tcp_payload( packet );
        if ( tcp_payload.size() == 0 ) return false;
        uint8_t content_type = tcp_payload[ 0 ];
        uint8_t major_version = tcp_payload[ 1 ];
        if ( content_type < 20 || content_type > 23 ) return false; 
        if ( major_version != 3 ) return false;
        return true;
    }
    
    bool is_tls_v( const std::vector<uint8_t>& packet ) {
        return is_tls( packet.data() );
    }

    bool is_tls_payload( const std::vector<uint8_t>& payload ) {
        uint8_t content_type = payload[ 0 ];
        uint8_t major_version = payload[ 1 ];
        if ( content_type < 20 || content_type > 23 ) return false; 
        if ( major_version != 3 ) return false;
        return true;
    }

    bool secret_labels_are_equal( std::array<std::string,5> lhs, std::array<std::string,5> rhs ) {
        std::sort( lhs.begin(), lhs.end() );
        std::sort( rhs.begin(), rhs.end() );
        return lhs == rhs;
    }

    // ==============================
    //   Get SNI From Client Hello
    // ==============================

    std::expected<std::string,std::string> get_sni( const client_hello& hello ) {
        const std::size_t extension_length_pos = 2;
        const std::size_t sni_list_length_pos = 4;
        auto extension_bytes = std::span<const unsigned char>( hello.extensions );

        while ( !extension_bytes.empty() ) {
            if ( extension_bytes.size() < 4 ) {
                return std::unexpected( "Extension too short for header" );
            }

            uint16_t extension_type = read_uint16_be( extension_bytes, 0 );
            uint16_t extension_length = read_uint16_be( extension_bytes, 2 );
            if ( extension_bytes.size() < 4 + extension_length ) {
                return std::unexpected( "Extension body truncated" );
            }

            if ( extension_type == 0x0000 ) {
                if ( extension_length < 2 ) {
                    return std::unexpected( "SNI extension too short to contain list length" );
                }

                uint16_t sni_list_length = read_uint16_be( extension_bytes, 0 );
                if ( sni_list_length > extension_length - 2 ) {
                    return std::unexpected( "SNI list length exceeds bounds" );
                }

                auto sni_list = extension_bytes.subspan( sni_list_length_pos + 2 );
                return parse_sni_list( sni_list );
            }

            extension_bytes = extension_bytes.subspan( 4 + extension_length );
        }

        return std::unexpected( "No sever name found" );
    }

    // ==============================
    //         Parse SNI List
    // ==============================

    std::expected<std::string,std::string> parse_sni_list( std::span<const unsigned char>& sni_list ) {
        while ( !sni_list.empty() ) {
            if ( sni_list.size() < 3 ) {
                return std::unexpected( "SNI entry too short" );
            }

            uint8_t name_type = sni_list[ 0 ];
            uint16_t name_length = read_uint16_be( sni_list, 1 );
            if ( sni_list.size() < 3 + name_length ) {
                return std::unexpected( "Server name truncated" );
            }

            std::string server_name( sni_list.begin() + 3,
                                     sni_list.begin() + 3 + name_length );
            return server_name;
            sni_list = sni_list.subspan( 3 + name_length );
        }

        return std::unexpected( "No server name found" );
    }

    // ==============================
    //     Get SNI From Ethernet
    // ==============================

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

    // ==============================
    //            Has SNI
    // ==============================

    std::expected<bool,std::string> has_sni( const client_hello& hello, const std::string& host ) {
        auto result = get_sni( hello );
        if ( !result.has_value() ) {
            return std::unexpected( result.error() );  
        }
        return result.value() == host;
    }

    // ==============================
    //         SNI Contains
    // ==============================

    std::expected<bool,std::string> sni_contains( const client_hello& hello, const std::string& host ) {
        auto result = get_sni( hello );
        if ( !result.has_value() ) {
            return std::unexpected( result.error() );  
        }
        return result.value().contains( host );
    }

    std::vector<std::string> get_snis( const session& packets, const std::string& host ) {
        std::vector<std::string> snis;
        for ( auto& client_hello_packet : packets | std::views::filter( is_client_hello_v ) ) {
            auto client_hello_result = get_client_hello_from_ethernet_frame( client_hello_packet );
            if ( !client_hello_result ) {
                continue;
            }
            auto sni_result = get_sni( client_hello_result.value() );
            if ( !sni_result ) {
                continue;
            }
            if ( sni_result && sni_result->contains( host ) ) {
                snis.push_back( sni_result.value() );
            }
        }
        
        return snis;
    }

    // ==============================
    //        Get SNI To IP
    // ==============================

    sni_to_ip get_sni_to_ip( const session& packets ) {
        sni_to_ip results;
        for ( auto& client_hello_packet : packets | std::views::filter( is_client_hello_v ) ) {
            auto sni = get_sni( client_hello_packet );
            if ( !sni.has_value() ) {
                std::cerr << sni.error() << std::endl;
            }
            ipv4_header header = get_parsed_ipv4_header( client_hello_packet );
            if ( !results.contains( sni.value() ) ) {
                results[ sni.value() ] = header.destination_ip_addr;
            }
        }

        return results;
    }

    // ==============================
    //      TLS Over TCP Class
    // ==============================

    tls_over_tcp::tls_over_tcp( const four_tuple& four )
        : tcp_transfer( four ) {}

    // ==============================
    //     TLS Live Stream Class
    // ==============================

    tls_live_stream::tls_live_stream( const tcp_live_stream& tcp_stream ) 
        : tcp_live_stream( tcp_stream ) {
        bool found_client_hello = false;

        for ( auto& packet : m_traffic ) {
            if ( is_client_hello_v( packet ) ) {
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

    const std::string& tls_live_stream::get_sni() const {
        return m_sni;
    }

    bool tls_live_stream::feed( const std::vector<uint8_t>& packet ) {
        m_decrypted_records = std::nullopt;
        if ( !m_handshake_feed.m_complete ) return tcp_live_stream::feed( packet );
        if ( is_client_hello_v( packet ) ) return populate_client_hello( packet ); 
        if ( !m_server_hello_populated ) { 
            populate_server_hello( packet );
            if ( m_server_hello_populated ) { 
                auto [ tls_secrets, line_reached ] = get_tls_secrets_dynamically( m_ssl_keys_log, m_client_hello.random );
                if ( is_complete_secrets( tls_secrets[ client_random_to_hex( m_client_hello.random ) ] ) ) {
                    m_tls_secrets = tls_secrets;
                    m_lines_consumed = line_reached;
                }
                return true; 
            }
        }
        if ( is_data_packet( packet ) && is_client_packet( packet ) ) {
            auto result = get_tls_record_from_ethernet( packet );
            if ( !result ) {
                return false;
            }
            auto& encrypted_record = result.value();
            if ( is_change_cipher_spec( encrypted_record ) ) return false;
            auto decrypted_record = decrypt_record( m_client_hello.random, m_server_hello.random, m_server_hello.server_version, m_server_hello.cipher_suite, encrypted_record,
                                                    m_tls_secrets, "CLIENT_TRAFFIC_SECRET_0", m_client_traffic_seq_number );
            m_decrypted_records.emplace();
            m_decrypted_records->push_back( std::move( decrypted_record ) );
            ++m_client_traffic_seq_number;
            return true;
        }
        if ( is_data_packet( packet ) && is_server_packet( packet ) ) {
            if ( !is_tls_v( packet ) && !m_incomplete_record ) {
                return false;
            }
            std::optional<std::vector<tls_record>> encrypted_records; 
            std::variant<tls_record,incomplete_tls_record> record_variant;
            auto payload = get_tcp_payload( packet );
            std::span<uint8_t> payload_span( payload.data(), payload.size() ); 
            while ( !payload_span.empty() ) {
                if ( m_incomplete_record ) {
                    std::size_t payload_size_before = m_incomplete_record.value().record.payload.size();
                    auto record_variant = append_to_incomplete_record( m_incomplete_record.value(), packet );
                    if ( std::holds_alternative<tls_record>( record_variant ) ) {
                        if ( !encrypted_records ) encrypted_records.emplace();
                        std::size_t payload_size_after = std::get<tls_record>( record_variant ).payload.size();
                        encrypted_records->push_back( std::move( std::get<tls_record>( record_variant ) ) );
                        std::size_t bytes_consumed = payload_size_after - payload_size_before;
                        payload_span = payload_span.subspan( bytes_consumed );
                        m_incomplete_record.reset();
                    } else {
                        m_incomplete_record.value().record.payload.insert( m_incomplete_record.value().record.payload.end(), payload_span.begin(), payload_span.end() );
                        payload_span = payload_span.subspan( 0, 0 );
                    }
                } else {
                    auto split_result = split_tls_records( payload_span );
                    if ( !split_result ) {
                        return false;
                    } else {
                        auto [ records, offset_reached ] = split_result.value();
                        if ( records.empty() ) {
                            auto record_header = get_tls_record_header_from_payload( payload_span );
                            auto empty_record = get_empty_tls_record_from_payload( payload_span );
                            empty_record.payload.assign( payload_span.begin() + 5, payload_span.end() );
                            m_incomplete_record = incomplete_tls_record {
                                empty_record,
                                record_header.payload_length
                            };
                            payload_span = payload_span.subspan( 0, 0 ); 
                        } else {
                            if ( !encrypted_records ) encrypted_records.emplace();
                            encrypted_records->insert( encrypted_records->end(), records.begin(), records.end() );
                            payload_span = payload_span.subspan( offset_reached );
                        }
                    } 
                }
            }
            if ( encrypted_records ) {
                for ( auto& encrypted_record : encrypted_records.value() ) {
                    auto decrypted_record = decrypt_record( m_client_hello.random, m_server_hello.random, m_server_hello.server_version, m_server_hello.cipher_suite, encrypted_record,
                                                            m_tls_secrets, "SERVER_TRAFFIC_SECRET_0", m_server_traffic_seq_number );
                    if ( !m_decrypted_records ) m_decrypted_records.emplace();
                    m_decrypted_records->push_back( std::move( decrypted_record ) );
                    ++m_server_traffic_seq_number;
                }
                return true;
            }
        }
        return false;
    }

    bool tls_live_stream::populate_client_hello( const std::vector<uint8_t>& packet ) {
        auto result = get_client_hello_from_ethernet_frame( packet );
        if ( result ) {
            m_client_hello = *result;
            m_client_hello_populated = true;
            return true;
        } else {
            return false;
        }
    }

    bool tls_live_stream::populate_server_hello( const std::vector<uint8_t>& packet ) {
        auto result = get_server_hello_from_ethernet_frame( packet );
        if ( result ) {
            m_server_hello = *result;
            m_server_hello_populated = true;
            return true;
        } else {
            return false;
        }
    }

    std::optional<std::reference_wrapper<const client_hello>> tls_live_stream_friend_helper::get_client_hello( const tls_live_stream& t ) {
        if ( t.m_client_hello_populated ) {
            return std::cref( t.m_client_hello );
        } else {
            return std::nullopt;
        }
    }

    std::optional<std::reference_wrapper<const server_hello>> tls_live_stream_friend_helper::get_server_hello( const tls_live_stream& t ) {
        if ( t.m_server_hello_populated ) {
            return std::cref( t.m_server_hello );
        } else {
            return std::nullopt;
        }
    }

    const bool tls_live_stream_friend_helper::client_hello_populated( const tls_live_stream& t ) {
        return t.m_client_hello_populated;
    }

    const bool tls_live_stream_friend_helper::server_hello_populated( const tls_live_stream& t ) {
        return t.m_server_hello_populated;
    }

    const std::size_t tls_live_stream_friend_helper::lines_consumed( const tls_live_stream& t ) {
        return t.m_lines_consumed;
    } 

    const secrets tls_live_stream_friend_helper::tls_secrets( const tls_live_stream& t ) {
        return t.m_tls_secrets;
    }

    const int tls_live_stream_friend_helper::client_traffic_seq_number( const tls_live_stream& t ) {
        return t.m_client_traffic_seq_number;
    }

    const int tls_live_stream_friend_helper::server_traffic_seq_number( const tls_live_stream& t ) {
        return t.m_server_traffic_seq_number;
    }

    std::optional<std::vector<tls_record>> tls_live_stream_friend_helper::decrypted_records( const tls_live_stream& t ) {
        return t.m_decrypted_records;
    }

    std::vector<uint8_t> tls_live_stream_friend_helper::partial_record_buffer( const tls_live_stream& t ) {
        return t.m_partial_record_buffer;
    }

    std::optional<incomplete_tls_record> tls_live_stream_friend_helper::get_incomplete_record( const tls_live_stream& t ) {
        return t.m_incomplete_record;
    }

    // ==============================
    //        Log File Trimmer
    // ==============================

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

    // ==============================
    //           TLS Filter
    // ==============================

    bool tls_filter::operator()( const ntk::tcp_live_stream& stream ) {
        return stream.traffic_contains( is_client_hello_v );
    }

    // ==============================
    //           SNI Filter
    // ==============================

    sni_filter::sni_filter( const std::string& sni )
        : m_sni( sni ) {}

    bool sni_filter::operator()( const ntk::tcp_live_stream& stream ) {
        auto has_matching_sni = [&]( const std::vector<uint8_t> packet ) {
            if ( is_client_hello_v( packet ) ) {
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

    // ==============================
    //     TLS Record Extraction
    // ==============================

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

    std::expected<tls_record,std::string> get_tls_record_from_ethernet( std::span<const uint8_t> packet ) {
        auto payload = get_tcp_payload( packet );
        return get_tls_record_from_payload( payload );
    }

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

    std::variant<tls_record,incomplete_tls_record> append_to_incomplete_record( incomplete_tls_record incomplete_record, std::span<const unsigned char> packet ) {
        if ( incomplete_record.record.payload.size() == incomplete_record.expected_payload_length ) return incomplete_record.record;
        if ( packet.size() == 0 ) return incomplete_record;

        std::size_t bytes_required = incomplete_record.expected_payload_length - incomplete_record.record.payload.size();
        auto payload = get_tcp_payload( packet );
        if ( bytes_required <= payload.size() ) {
            auto complete_record = tls_record { incomplete_record.record.content_type, incomplete_record.record.version, incomplete_record.record.payload };
            complete_record.payload.insert( complete_record.payload.end(), payload.begin(), payload.begin() + bytes_required );
            return complete_record;
        }
        if ( bytes_required > payload.size() ) {
            incomplete_record.record.payload.insert( incomplete_record.record.payload.end(), payload.begin(), payload.end() );
            return incomplete_record;
        }
    }

    std::variant<tls_record,incomplete_tls_record> get_complete_or_incomplete_record( std::span<const unsigned char> packet ) {
        constexpr std::size_t recorder_header_length = 5;
        auto record = get_parsed_tls_record_from_ethernet( packet );
        if ( !record ) {
            auto empty_record = get_empty_tls_record_from_ethernet( packet );
            auto record_header = get_tls_record_header_from_ethernet( packet );
            auto payload = get_tcp_payload( packet );
            empty_record.payload.assign( payload.begin() + recorder_header_length, payload.end() );
            incomplete_tls_record incomplete_record{ empty_record, record_header.payload_length };
            return incomplete_record;
        } else {
            return record.value();
        }
    }

    tls_record get_empty_tls_record_from_ethernet( std::span<const unsigned char> packet ) {
        tls_record record;
        auto record_header = get_tls_record_header_from_ethernet( packet );
        record.content_type = record_header.content_type;
        record.version = record_header.version;
        return record;
    }

    tls_record get_empty_tls_record_from_payload( std::span<const unsigned char> payload ) {
        tls_record record;
        auto record_header = get_tls_record_header_from_payload( payload );
        record.content_type = record_header.content_type;
        record.version = record_header.version;
        return record;
    }

    tls_record_header get_tls_record_header( const std::array<uint8_t,5> record_header_bytes ) {
        tls_record_header header;
        header.content_type = static_cast<tls_content_type>( record_header_bytes[ 0 ] );
        uint16_t version_raw = read_uint16_be( record_header_bytes, 1 );
        header.version = static_cast<tls_version>( version_raw );
        header.payload_length = read_uint16_be( record_header_bytes, 3 );
        return header;
    }

    tls_record_header get_tls_record_header_from_ethernet( std::span<const unsigned char> packet ) {
        auto payload = get_tcp_payload( packet );
        return get_tls_record_header_from_payload( payload );
    }

    tls_record_header get_tls_record_header_from_payload( std::span<const unsigned char> payload ) {
        std::array<uint8_t,5> record_header_bytes;
        std::copy_n( payload.begin(), record_header_bytes.size(), record_header_bytes.begin() );
        return get_tls_record_header( record_header_bytes );
    }

} // namespace ntk