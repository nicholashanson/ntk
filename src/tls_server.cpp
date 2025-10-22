#include <tls_server.hpp>

namespace ntk {

    // ======================
    //  Create Server Socket
    // ======================

    std::expected<int,std::string> create_server_socket() {
        int sock_fd = socket( AF_INET, SOCK_STREAM, 0 );
        if ( sock_fd == -1 ) {
            return std::unexpected( "Failed to Create Server" );
        }
        return sock_fd;
    }

    // =============
    //  Bind Socket
    // =============

    std::expected<void,std::string> bind_socket( int sock_fd, uint16_t port ) {
        sockaddr_in addr;
        std::memset( &addr, 0, sizeof( addr ) );
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if ( bind( sock_fd, ( sockaddr* )&addr, sizeof( addr ) ) < 0 ) {
            return std::unexpected( "Failed to Bind Socket" );
        }
        return {};
    }

    // ===============
    //  Listen Socket
    // ===============

    std::expected<void,std::string> listen_socket( int sock_fd, int back_log = 5 ) {
        if ( listen( sock_fd, back_log ) < 0 ) {
            return std::unexpected( "Failed to Listen on Socket" );
        }
        return {};
    }

    // ===============
    //  Handle Client
    // ===============

    void handle_client( int client_fd ) {
        std::cout << "\033[2J\033[H";
        generate_default_server_config();
        generate_default_client_config();
        auto client_config_result = load_client_config();
        if ( !client_config_result ) {
            std::cout << client_config_result.error() << std::endl;
        }
        print_client_config( client_config_result.value() );
        std::cin.get();
        std::cout << "\033[2J\033[H";
        print_server_config( load_server_config() );
        std::cin.get();
        std::cout << "\033[2J\033[H";
        client_connection conn{ client_fd, server_state::waiting_for_client_hello, {}, {} };
        std::vector<uint8_t> buffer; 
        while ( true ) { 
            std::vector<uint8_t> temp( 4096 );
            ssize_t n = read( client_fd, temp.data(), temp.size() );
            if ( n <= 0 ) {
                break;
            }
            buffer.insert( buffer.end(), temp.begin(), temp.begin() + n ); 

            if ( conn.state == server_state::waiting_for_client_hello ) {
                auto client_hello_result = parse_client_hello( buffer );
                if ( !client_hello_result ) {
                    std::cout << client_hello_result.error() << std::endl;
                    return;
                }
                auto& client_hello = client_hello_result.value();
                ntk::print_client_hello( client_hello, std::cout, colors::green );
                std::cin.get();
                std::cout << "\033[2J\033[H";
                auto server_hello_result = generate_server_hello( buffer );
                if ( !server_hello_result ) {
                    std::cout << server_hello_result.error() << std::endl;
                    return;
                }
                auto ctx_result = get_server_tls_context( server_hello_result.value(), buffer );
                if ( !ctx_result ) {
                    std::cout << ctx_result.error() << std::endl;
                }
                conn.tls_ctx = ctx_result.value();
                auto parse_result = ntk::parse_server_hello( server_hello_result.value().server_hello );
                if ( !parse_result ) {
                    std::cout << parse_result.error() << std::endl;
                    return;
                }
                auto record_result = construct_server_hello_record( server_hello_result.value().server_hello );
                if ( !record_result ) {
                    std::cout << record_result.error() << std::endl;
                    return;
                }
                auto& server_hello_record = record_result.value();
                print_server_hello( parse_result.value(), std::cout, colors::blue );
                std::cin.get();
                std::cout << "\033[2J\033[H";
                print_tls_context( conn.tls_ctx, std::cout, colors::blue );
                std::cin.get();
                std::cout << "\033[2J\033[H";
                write( client_fd, server_hello_record.data(), server_hello_record.size() );
                conn.state = server_state::sent_server_hello;
                buffer.clear();
            } else if ( conn.state == server_state::sent_server_hello ) {
                auto record_result = get_tls_record_from_payload( buffer );
                if ( !record_result ) {
                    std::cout << record_result.error() << std::endl;
                }
                auto& record = record_result.value();
                print_tls_record( record, std::cout, colors::green );
                std::cin.get();
                std::cout << "\033[2J\033[H";
                buffer.clear();

                auto read_result = ntk::read_from_file( "http_response.txt" );
                if ( !read_result ) {
                    std::cout << read_result.error() << std::endl;
                }
                auto& http_message = read_result.value();
                auto ts_read_result = ntk::read_from_file( "../assets/segment.ts" );
                if ( !ts_read_result ) {
                    std::cout << ts_read_result.error() << std::endl;
                }
                auto& ts = ts_read_result.value();
                http_message.insert( http_message.end(), ts.begin(), ts.end() );
                uint64_t seq_num{};
                
                std::visit( [&]( auto& s ) {
                    auto records_result = ntk::convert_to_tls_application_data_records(
                        ntk::cipher_suite::TLS_AES_128_GCM_SHA256,
                        http_message,
                        s.server_traffic_secret_0,
                        seq_num,
                        16385
                    );

                    if ( !records_result ) {
                        std::cout << "Failed: " << records_result.error() << std::endl;
                        return;
                    }

                    for ( const auto& record : records_result.value() ) {
                        auto parse_result = get_tls_record_from_payload( record );
                        if ( !parse_result ) {
                            std::cout << parse_result.error() << std::endl;
                        }
                        auto& parsed_record = parse_result.value();
                        print_tls_record( parsed_record, std::cout, colors::blue, true );
                    }

                    std::cin.get();
                    std::cout << "\033[2J\033[H";
                    
                    for ( const auto& record : records_result.value() ) {
                        std::size_t total_sent = 0;
                        while (total_sent < record.size()) {
                            ssize_t n = write(client_fd, record.data() + total_sent, record.size() - total_sent);
                            if (n <= 0) {
                                std::cout << "Write failed or connection closed" << std::endl;
                                break;
                            }
                            total_sent += n;
                        }
                    }
                }, conn.tls_ctx.secrets );
            }
        }
        close( client_fd );
    }

    // ================
    //  Accept Clients
    // ================

    void accept_clients( int server_fd ) {
        while ( true ) {
            sockaddr_in client_addr;
            socklen_t client_len = sizeof( client_addr );
            int client_fd = accept( server_fd, ( sockaddr* )&client_addr, &client_len );
            if ( client_fd < 0 ) {
                perror( "accept" );
                continue;
            }
            std::cout << "Client connected: " << inet_ntoa( client_addr.sin_addr ) 
                      << ":" << ntohs( client_addr.sin_port ) << "\n";
            handle_client( client_fd );
        }
    }

    // ============
    //  Run Server
    // ============

    std::expected<void,std::string> run_server() {
        auto server_fd_result = create_server_socket();
        if ( !server_fd_result ) { 
            return std::unexpected( server_fd_result.error() );
        }
        auto server_fd = server_fd_result.value();
        auto bind_result = bind_socket( server_fd, 12345 );
        if ( !bind_result ) {
            return std::unexpected( bind_result.error() );
        }
        auto listen_result = listen_socket( server_fd );
        if ( !listen_result ) {
            std::cout << listen_result.error() << std::endl;
            return std::unexpected( listen_result.error() );
        }
        std::cout << "Server listening on port 12345\n";
        accept_clients( server_fd );
        close( server_fd );
        return {};
    }

    // ===================
    //  Load Server Comfig
    // ===================

    std::string load_server_config() {
        std::ifstream file( "server_config.json" );
        if ( !file ) {
            generate_default_server_config();
            file.open( "server_config.json" );
            if ( !file.is_open() ) {
                throw std::runtime_error( "Failed to open server_config.json after generating default config" );
            }
        }
        std::ostringstream buffer;
        buffer << file.rdbuf(); 
        return buffer.str();
    }

    // ===================
    //  Get Server Comfig
    // ===================

    std::expected<tls_server_config,std::string> get_server_config() {
        tls_server_config server_config;
        auto config = load_server_config();
        auto cipher_preference = extract_boolean( config, "respect_client_cipher_suite_preference" );
        if ( !cipher_preference ) {
            return std::unexpected( cipher_preference.error() );
        }
        server_config.respect_client_cipher_suite_preference = cipher_preference.value();
        auto cipher_suites_result = extract_array( config, "cipher_suites" );
        if ( !cipher_suites_result ) {
            return std::unexpected( cipher_suites_result.error() );
        }
        for ( auto& [ cipher_suite, cipher_suite_name ] : tls_cipher_suite_names ) {
            for ( auto& c : cipher_suites_result.value() ) {
                if ( c == cipher_suite_name ) {
                    server_config.cipher_suites.push_back( cipher_suite );
                } 
            }
        }
        auto key_share_preference = extract_boolean( config, "respect_client_key_share_preference" );
        if ( !key_share_preference ) {
            return std::unexpected( key_share_preference.error() );
        }
        auto key_share_result = extract_array( config, "key_share" );
        if ( !key_share_result ) {
            return std::unexpected( key_share_result.error() );
        }
        for ( auto& [ key_share, key_share_name ] : named_group_names ) {
            for ( auto& k : key_share_result.value() ) {
                if ( k == key_share_name ) {
                    server_config.key_shares.push_back( key_share );
                } 
            }
        }
        auto supported_versions = extract_array( config, "supported_versions" );
        if ( !supported_versions ) {
            return std::unexpected( supported_versions.error() );
        }
        auto& supported_v = supported_versions.value();
        for ( auto& [ v, v_name ] : tls_version_names ) {
            for ( auto& version : supported_v ) {
                if ( version == v_name ) {
                    server_config.supported_versions.push_back( v );
                }
            }
        }
        return server_config;
    }

    // ==========================
    //  Get Server Hello Context
    // ==========================

    std::expected<server_hello_context,std::string> get_server_hello_context( const client_hello_info& c_hello, const tls_server_config& server_config ) {
        server_hello_context context;
        if ( server_config.respect_client_cipher_suite_preference ) {
            for ( auto& cipher_suite : c_hello.cipher_suites ) {
                if ( std::any_of( server_config.cipher_suites.begin(), 
                                  server_config.cipher_suites.end(), 
                                  [&]( auto& c ) { return c == cipher_suite; } ) ) {
                    context.c_suite = cipher_suite;
                    break;
                }
            }
        } else {
            for ( auto& cipher_suite : server_config.cipher_suites ) {
                if ( std::any_of( c_hello.cipher_suites.begin(), 
                                  c_hello.cipher_suites.end(), 
                                  [&]( auto& c ) { return c == cipher_suite; } ) ) {
                    context.c_suite = cipher_suite;
                    break;
                }
            }    
        }
        if ( c_hello.extensions && c_hello.extensions->key_share_entries ) {
            if ( server_config.respect_client_key_share_preference ) {
                for ( auto& ks_e : c_hello.extensions.value().key_share_entries.value() ) {
                    if ( std::any_of( server_config.key_shares.begin(), 
                                      server_config.key_shares.end(), 
                                      [&]( auto& k ) { return k == static_cast<named_group>( ks_e.group ); } ) ) {
                        context.key_share = static_cast<named_group>( ks_e.group );
                        context.peer_public_key = { ks_e.key_data.begin() + 2, ks_e.key_data.end() };
                        break;
                    }
                }
            } else {
                for ( auto& k : server_config.key_shares ) {
                    if ( std::any_of( c_hello.extensions->key_share_entries->begin(), 
                                      c_hello.extensions->key_share_entries->end(), 
                                      [&]( auto& k_e ) { return static_cast<named_group>( k_e.group ) == k; } ) ) {
                        context.key_share = k;
                        auto it = std::find_if( c_hello.extensions->key_share_entries->begin(),
                                                c_hello.extensions->key_share_entries->end(),
                                                [&]( auto& k_e ) { return static_cast<named_group>( k_e.group ) == k; } ); 
                        context.peer_public_key = { it->key_data.begin() + 2, it->key_data.end() };
                        break;
                    }
                }    
            }
        }
        if ( context.key_share ) {
            if ( context.key_share == named_group::x25519 ) {
                auto result = generate_x25519_key_pair();
                if ( !result ) {
                    return std::unexpected( result.error() );
                }
                auto& key_pair = result.value();
                context.private_key = { key_pair.private_key.begin(), key_pair.private_key.end() };
                context.public_key = { key_pair.public_key.begin(), key_pair.public_key.end() };
            } else if ( context.key_share == named_group::secp256r1 ) {
                auto result = generate_secp256r1_key_pair();
                if ( !result ) {
                    return std::unexpected( result.error() );
                }
                auto& key_pair = result.value();
                context.private_key = { key_pair.private_key.begin(), key_pair.private_key.end() };
                context.public_key = { key_pair.public_key.begin(), key_pair.public_key.end() };
            }
        }
        if ( c_hello.extensions && c_hello.extensions->supported_versions ) {
            for ( auto& v : c_hello.extensions->supported_versions.value() ) {
                if ( std::any_of( server_config.supported_versions.begin(),
                                  server_config.supported_versions.end(),
                                  [&]( auto& version) { return version == v; } ) ) {
                    context.version = v;
                    break;
                }
            }
        }
        return context;
    }

    // =============================================
    //  Generate Supported Versions Extension Bytes
    // =============================================

    std::expected<std::vector<uint8_t>,std::string> generate_supported_versions_extension_bytes( const server_hello_context& context ) {
        std::vector<uint8_t> bytes;
        auto extension_bytes = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( tls_extension_type::supported_versions ) );
        bytes.insert( bytes.end(), extension_bytes.begin(), extension_bytes.end() );
        bytes.insert( bytes.end(), { 0x00, 0x02 } );
        auto version_bytes = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( context.version ) );
        bytes.insert( bytes.end(), version_bytes.begin(), version_bytes.end() );
        return bytes;
    }

    // ====================================
    //  Generate Key Share Extension Bytes
    // ====================================

    std::expected<std::vector<uint8_t>,std::string> generate_key_share_extension_bytes( const server_hello_context& context ) {
        std::vector<uint8_t> bytes;
        auto extension_bytes = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( tls_extension_type::key_share ) );
        bytes.insert( bytes.end(), extension_bytes.begin(), extension_bytes.end() );
        if ( !context.public_key ) {
            return std::unexpected( "Public Key in Server Hello Context is undefined" );
        }
        auto total_len = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( context.public_key->size() + 2 + 2 ) );
        bytes.insert( bytes.end(), total_len.begin(), total_len.end() );
        if ( !context.key_share ) {
            return std::unexpected( "Key Share in Server Hello Context is undefined" );
        }
        auto group_bytes = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( context.key_share.value() ) );
        bytes.insert( bytes.end(), group_bytes.begin(), group_bytes.end() );
        auto key_len = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( context.public_key->size() ) );
        bytes.insert( bytes.end(), key_len.begin(), key_len.end() );
        bytes.insert( bytes.end(), context.public_key->begin(), context.public_key->end() );
        return bytes;
    }

    // =======================================
    //  Generate Server Hello Extension Bytes
    // =======================================

    std::expected<std::vector<uint8_t>,std::string> generate_server_hello_extension_bytes( const server_hello_context& context ) {
        std::vector<uint8_t> extensions_bytes;
        auto version_result = generate_supported_versions_extension_bytes( context );
        if ( !version_result ) {
            return std::unexpected( version_result.error() );
        }
        auto& version_extension_bytes = version_result.value();
        extensions_bytes.insert( extensions_bytes.end(), version_extension_bytes.begin(), version_extension_bytes.end() );
        auto key_share_result = generate_key_share_extension_bytes( context );
        if ( !key_share_result ) {
            return std::unexpected( key_share_result.error() );
        }
        auto& key_share_bytes = key_share_result.value();
        extensions_bytes.insert( extensions_bytes.end(), key_share_bytes.begin(), key_share_bytes.end() );
        return extensions_bytes; 
    }

    // =======================
    //  Generate Server Hello
    // =======================

    std::expected<server_hello_result,std::string> generate_server_hello( const server_hello_context& context ) {
        std::vector<uint8_t> server_hello_bytes;
        auto version_bytes = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( context.version ) );
        server_hello_bytes.insert( server_hello_bytes.end(), version_bytes.begin(), version_bytes.end() );
        auto random_bytes = generate_tls_random( context.version );
        server_hello_bytes.insert( server_hello_bytes.end(), random_bytes.begin(), random_bytes.end() );
        server_hello_bytes.push_back( static_cast<uint8_t>( 0x00 ) );
        auto cipher_suite_bytes = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( context.c_suite ) );
        server_hello_bytes.insert( server_hello_bytes.end(), cipher_suite_bytes.begin(), cipher_suite_bytes.end() );
        server_hello_bytes.push_back( static_cast<uint8_t>( 0x00 ) );

        auto extensions_result = generate_server_hello_extension_bytes( context );
        if ( !extensions_result ) {
            return std::unexpected( extensions_result.error() ) ;
        }    
        auto& extensions_bytes = extensions_result.value();
        auto extensions_len = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( extensions_bytes.size() ) );
        server_hello_bytes.insert( server_hello_bytes.end(), extensions_len.begin(), extensions_len.end() );
        server_hello_bytes.insert( server_hello_bytes.end(), extensions_bytes.begin(), extensions_bytes.end() );
        auto key_share = context.key_share;
        auto public_key = context.public_key;
        auto private_key = context.private_key;
        return server_hello_result{ std::move( server_hello_bytes ), key_share, std::move( context.public_key ), std::move( context.private_key ) };
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<server_hello_result,std::string> generate_server_hello( std::span<const uint8_t> client_hello_bytes ) {
        auto info_result = get_client_hello_info( client_hello_bytes );
        if ( !info_result ) {
            return std::unexpected( info_result.error() );
        }
        auto& c_hello_info = info_result.value();
        auto config_result = get_server_config();
        if ( !config_result ) {
            return std::unexpected( config_result.error() );
        }
        auto& config = config_result.value();
        auto context_result = get_server_hello_context( c_hello_info, config );
        if ( !context_result ) {
            return std::unexpected( context_result.error() );
        }
        return generate_server_hello( context_result.value() );
    }

} // namespace ntk


