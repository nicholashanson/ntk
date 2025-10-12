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
        std::vector<uint8_t> buffer( 1024, '\0' );  
        ssize_t n = read( client_fd, buffer.data(), buffer.size() );
        if ( n > 0 ) {
            buffer.resize( n );           
            auto client_hello_result = parse_client_hello( buffer );
            if ( !client_hello_result ) {
                std::cout << client_hello_result.error() << std::endl;
                return;
            }
            auto& client_hello = client_hello_result.value();
            ntk::print_client_hello( client_hello );
            write( client_fd, buffer.data(), buffer.size() ); 
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
            for ( auto& v :  c_hello.extensions->supported_versions.value() ) {
                if ( std::any_of( server_config.supported_versions.begin(),
                                  server_config.supported_versions.end(),
                                  [&]( auto& version) { return version == v; } ) ) {
                    context.version = v;
                }
            }
        }
        return context;
    }

    // =======================
    //  Generate Server Hello
    // =======================

    std::expected<std::vector<uint8_t>,std::string> generate_server_hello( const server_hello_context& context ) {
        std::vector<uint8_t> server_hello_bytes;
        auto version_bytes = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( context.version ) );
        server_hello_bytes.insert( server_hello_bytes.end(), version_bytes.begin(), version_bytes.end() );
        auto random_bytes = generate_tls_random( context.version );
        server_hello_bytes.insert( server_hello_bytes.end(), random_bytes.begin(), random_bytes.end() );
        server_hello_bytes.push_back( static_cast<uint8_t>( 0x00 ) );
        auto cipher_suite_bytes = get_big_endian_byte_encoding<uint16_t,2>( static_cast<uint16_t>( context.c_suite ) );
        server_hello_bytes.insert( server_hello_bytes.end(), cipher_suite_bytes.begin(), cipher_suite_bytes.end() );
        server_hello_bytes.push_back( static_cast<uint8_t>( 0x00 ) );
        server_hello_bytes.insert( server_hello_bytes.end(), { 0x00, 0x00 } );
        return server_hello_bytes;
    }

} // namespace ntk


