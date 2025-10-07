#include <io.hpp>

namespace ntk {

    // ========================
    //  Read Packets From File
    // ========================

    session read_packets_from_file( const std::string& packet_data_file ) {
        std::vector<std::vector<uint8_t>> packets;
        std::ifstream file_handle( packet_data_file );
        if ( !file_handle.is_open() ) {
            std::cerr << "Failed to open file: " << packet_data_file << '\n';
            return packets;
        }
        std::string line;
        while ( std::getline( file_handle, line ) ) {
            std::vector<uint8_t> packet;
            std::istringstream iss( line );
            std::string byte_string;
            while ( iss >> byte_string ) {
                const uint8_t byte = static_cast<uint8_t>( std::stoul( byte_string, nullptr, 16 ) );
                packet.push_back( byte );
            }

            if ( !packet.empty() ) {
                packets.push_back( packet );
            }
        }
        return packets;
    }

    // ==============
    //  Print Vector
    // ==============

    void print_vector( std::span<const uint8_t> data ) {
        for ( auto byte : data ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << ( static_cast<int>( byte ) & 0xff ) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    // ====================
    //  Print Packet Array
    // ====================

    void print_packet_array( const unsigned char* packet_data, const size_t packet_len ) {
        for ( size_t i = 0; i < packet_len; ++i ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( packet_data[ i ] ) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    // =======================
    //  Print TCP Stream Info
    // =======================

    void print_tcp_stream_info( const std::map<uint32_t, std::vector<uint8_t>>& stream ) {
        for ( const auto& [ seq_num, data ] : stream ) {
            std::cout << "Seq: " << seq_num 
                      << ", Size: " << data.size() << " bytes\n";
        }
    }

    // ===================
    //  Print TCP Options
    // ===================

    void print_tcp_options( const tcp_header& header ) {
        for ( const auto& opt : header.options ) {
            std::cout << "Option kind: " << static_cast<int>( opt.type ) << " -> data bytes: ";
            for ( const auto& byte : opt.option ) {
                std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
            }
            std::cout << std::dec << std::endl;  
        }
    }

    // ================
    //  Parse Hex Line
    // ================
    
    std::vector<uint8_t> parse_hex_line( const std::string& line ) {     
        std::vector<uint8_t> bytes;
        std::istringstream iss( line );
        std::string byte_str;
        while ( iss >> byte_str ) {
            uint8_t byte = static_cast<uint8_t>( std::stoul( byte_str, nullptr, 16 ) );
            bytes.push_back( byte );
        }
        return bytes;
    }

    // ====================
    //  Index Line Offsets
    // ====================

    std::vector<std::streampos> index_line_offsets( const std::string& filename ) {
        std::ifstream file( filename );
        std::vector<std::streampos> offsets;
        if ( !file.is_open() ) {
            std::cerr << "Failed to open file: " << filename << '\n';
            return offsets;
        }
        std::string line;
        while ( file ) {
            offsets.push_back( file.tellg() );
            std::getline( file, line );
        }
        return offsets;
    }

    // =============================
    //  Get Packets By Line Numbers 
    // =============================

    std::vector<std::vector<uint8_t>> get_packets_by_line_numbers( const std::string& filename,
                                                                   const std::vector<int>& line_numbers ) {
        std::ifstream file( filename );
        std::vector<std::vector<uint8_t>> packets;
        if ( !file.is_open() ) {
            std::cerr << "Failed to open file: " << filename << '\n';
            return packets;
        }
        auto offsets = index_line_offsets( filename );
        for ( int line_num : line_numbers ) {
            if ( line_num <= 0 || line_num > static_cast<int>( offsets.size() ) ) {
                continue;
            }
            file.clear(); 
            file.seekg( offsets[ line_num - 1 ] );
            std::string line;
            std::getline( file, line );
            packets.push_back( parse_hex_line( line ) );
        }
        return packets;
    }

    // ==================
    //  Print TCP Option
    // ==================

    void print_tcp_option( const tcp_option& opt, std::ostream& os ) {
        os << "    Option[" << static_cast<int>( opt.type )
           << "]: Type: " << static_cast<int>( opt.type ) << ", Data: [";
        for ( size_t i = 0; i < opt.option.size(); ++i ) {
            os << std::hex << std::setw( 2 ) << std::setfill( '0' )
               << static_cast<int>( opt.option[ i ] );
            if ( i != opt.option.size() - 1 )
                os << " ";
        }
        os << std::dec << std::setfill( ' ' ) << "]\n";
    }

    // ==================
    //  Print TCP Header
    // ==================

    void print_tcp_header( const tcp_header& header, std::ostream& os ) {
        const int label_width = 26;
        os << std::dec << std::setfill( ' ' );
        os << "===== TCP HEADER BEGIN =====\n";

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        print_field( "Source Port:", header.src_port );
        print_field( "Destination Port:", header.dest_port );
        print_field( "Sequence Number:", header.seq_number );
        print_field( "Acknowledgment Number:", header.ack_number );
        print_field( "Data Offset:", static_cast<uint32_t>( header.data_offset ) ); 

        os << std::left << std::setw( label_width ) << "Flags:"
           << "0x" << std::hex << static_cast<int>( header.flags ) << std::dec << "\n";
        print_field( "Window Size:", header.window_size );
        
        os << std::left << std::setw( label_width ) << "Checksum:"
           << "0x" << std::hex << std::setw( 4 ) << std::setfill( '0' )
           << header.checksum << std::dec << std::setfill( ' ' ) << "\n";
        print_field( "Urgent Pointer:", header.urgent_ptr );

        os << std::left << std::setw( label_width ) << "Options:";
        if ( header.options.empty() ) {
            os << "None\n";
        } else {
            os << "\n";
            for ( const auto& opt : header.options ) {
                print_tcp_option( opt, os );
            }
        }
        os << "===== TCP HEADER END =====\n\n";
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    void print_tcp_header( std::span<const uint8_t> packet, std::ostream& os ) {
        auto result = get_parsed_tcp_header_from_ethernet( packet );
        if ( !result ) {
            os << result.error() << "\n";
        }
        print_tcp_header( result.value(), os );
    }

    // ================================
    //  TCP Live Stream :: Operator <<
    // ================================

    std::ostream& operator<<( std::ostream& os, const tcp_live_stream& live_stream ) {
        os << "===== SYN HEADER BEGIN =====\n";
        print_tcp_header( live_stream.m_handshake_feed.m_handshake.syn, os );
        os << "===== SYN HEADER END =====\n";
        os << "===== SYN-ACK HEADER BEGIN =====\n";
        print_tcp_header( live_stream.m_handshake_feed.m_handshake.syn_ack, os );
        os << "===== SYN-ACK HEADER END =====\n";
        os << "===== ACK HEADER BEGIN =====\n";
        print_tcp_header( live_stream.m_handshake_feed.m_handshake.ack, os );
        os << "===== ACK HEADER END =====\n";

        auto& closing_sequence = std::get<fin_ack_fin_ack>( live_stream.m_termination_feed.m_termination.closing_sequence );

        os << "===== FIN_1 HEADER BEGIN =====\n";
        print_tcp_header( closing_sequence.initiator_fin, os );
        os << "===== FIN_1 HEADER END =====\n";
        os << "===== ACK_1 HEADER BEGIN =====\n";
        print_tcp_header( closing_sequence.responder_ack, os );
        os << "===== ACK_1 HEADER END =====\n";
        os << "===== FIN_2 HEADER BEGIN =====\n";
        print_tcp_header( closing_sequence.responder_fin, os );
        os << "===== FIN_2 HEADER END =====\n";
        os << "===== ACK_2 HEADER BEGIN =====\n";
        print_tcp_header( closing_sequence.initiator_ack, os );
        os << "===== ACK_2 HEADER END =====\n";

        return os;
    }

    // ====================
    //  Print Client Hello
    // ====================

    void print_client_hello( const client_hello& c_hello, std::ostream& os ) {
        const int label_width = 26;

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        os << std::dec << std::setfill( ' ' );
        os << "===== CLIENT HELLO BEGIN =====\n";
        print_field("Session ID:", session_id_to_hex( c_hello.session_id ) );
        print_field("Client Version:", tls_version_names.at( c_hello.client_version ) );
        print_field("Client Random:", client_random_to_hex( c_hello.random ) );
        os << std::left << std::setw( label_width ) << "Cipher-Suites:";
        for ( std::size_t i = 0; i + 1 < c_hello.cipher_suites.size(); i += 2 ) {
            uint16_t val = ( static_cast<uint16_t>( c_hello.cipher_suites[ i ] ) << 8 ) |
                             c_hello.cipher_suites[ i + 1 ];
            cipher_suite suite = static_cast<cipher_suite>( val );
            if ( i != 0 ) {
                os << std::setw( label_width ) << " ";
            }
            auto it = tls_cipher_suite_names.find( suite );
            if ( it != tls_cipher_suite_names.end() ) {
                os << it->second;
            } else {
                os << std::hex << std::setw( 4 ) << std::setfill( '0' ) << val << std::dec;
            }
            os << "\n";
        }
        os << "===== CLIENT HELLO END =====\n\n";
    }

    // ====================
    //  Print Server Hello
    // ====================

    void print_server_hello( const server_hello& s_hello, std::ostream& os ) {
        const int label_width = 26;

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        os << std::dec << std::setfill( ' ' );
        os << "===== SERVER HELLO BEGIN =====\n";
        print_field( "Server Random:", client_random_to_hex( s_hello.random ) );
        print_field( "TLS Version:", tls_version_names.at( s_hello.server_version ) );
        print_field( "Cipher Suite:", tls_cipher_suite_names.at( static_cast<cipher_suite>( s_hello.cipher_suite ) ) );
        os << "===== SERVER HELLO END =====\n\n";
    } 

    // ================================
    //  TLS Live Stream :: Operator <<
    // ================================

    std::ostream& operator<<( std::ostream& os, const tls_live_stream& live_stream ) {
        print_client_hello( live_stream.m_client_hello, os );
        print_server_hello( live_stream.m_server_hello, os );
        return os;
    }

    // ============
    //  Print Four
    // ============

    void print_four( const four_tuple& four, std::ostream& os ) {
        const int label_width = 26;

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        os << std::dec << std::setfill( ' ' );
        os << "===== FOUR TUPLE BEGIN =====\n";
        print_field( "Client IP:", four.src_ip );
        print_field( "Server IP:", four.dest_ip );
        print_field( "Client Port:", four.src_port );
        print_field( "Server Port:", four.dest_port );
        os << "===== FOUR TUPLE END =====\n\n";
    }

    // ===============
    //  Output Packet
    // ===============

    void output_packet( const std::vector<uint8_t> packet, std::ofstream& ofs ) {
        for ( size_t i = 0; i < packet.size(); ++i ) {
            ofs << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( packet[ i ] );
            if ( i != packet.size() - 1 ) {
                ofs << ' ';
            }
        }
        ofs << '\n';
    };

    // =======================
    //  Output Stream To File
    // =======================

    void output_stream_to_file( const std::string& filename, const tcp_live_stream& live_stream ) {
        std::ofstream ofs( filename );
        if ( !ofs ) {
            throw std::runtime_error( "Failed to open output file: " + filename );
        }
        
        auto print_packet = [&]( const std::vector<uint8_t> packet ) {
            for ( size_t i = 0; i < packet.size(); ++i ) {
                ofs << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( packet[ i ] );
                if ( i != packet.size() - 1 ) {
                    ofs << ' ';
                }
            }
            ofs << '\n';
        };

        const auto& handshake = live_stream.m_handshake_feed.m_handshake;
        std::vector<std::vector<uint8_t>> handshake_packets = { handshake.syn, handshake.syn_ack, handshake.ack };
        for ( const auto& packet : handshake_packets ) {
            print_packet( packet );
        }
        for ( const auto& packet : live_stream.m_traffic ) {
            print_packet( packet );
        }
        if ( std::holds_alternative<fin_ack_fin_ack>( live_stream.m_termination_feed.m_termination.closing_sequence ) ) {
            auto& closing_sequence = std::get<fin_ack_fin_ack>( live_stream.m_termination_feed.m_termination.closing_sequence );
            for ( const auto* packet : { &closing_sequence.initiator_fin, &closing_sequence.responder_ack, &closing_sequence.responder_fin, &closing_sequence.initiator_ack } ) {
                print_packet( *packet );
            }
        }
    }

    // ==================
    //  Print TLS Record
    // ==================

    void print_tls_record( const tls_record& record ) {
        const int label_width = 26;

        auto print_field = [&]( const std::string& label, auto value ) {
            std::cout << std::left << std::setw( label_width ) << label << value << "\n";
        };

        std::cout << std::dec << std::setfill( ' ' );
        std::cout << "===== TLS RECORD BEGIN =====\n";
        print_field( "Content Type:", tls_content_type_names.at( record.content_type ) );
        print_field( "Version:", tls_version_names.at( record.version ) );
        if ( is_http_response( record.payload ) ) {
            print_http_response( record.payload );
        } else {
            print_vector( record.payload );
        }
        std::cout << "===== TLS RECORD END =====\n\n";
    }

    // ===================
    //  Print TLS Secrets
    // ===================

    void print_tls_secrets( const secrets& keys ) {
        const int label_width = 40;

        auto print_field = [&]( const std::string& label, auto value ) {
            std::cout << std::left << std::setw( label_width ) << label << value << "\n";
        };

        std::cout << std::dec << std::setfill( ' ' );
        for ( auto [ client_random, secret ] : keys ) {
            std::cout << "===== TLS SECRETS BEGIN "
                      << client_random
                      << " =====\n";
            for ( auto& label : tls_secret_labels ) {
                print_field( label, string_to_hex( secret[ label ] ) );
            }
            std::cout << "===== TLS SECRETS END =====\n\n";
        }
    }

    // ================
    //  Four To String
    // ================

    std::string four_to_string( const four_tuple& four ) {
        return ip_to_string( four.src_ip ) + "_" +
               std::to_string( four.src_port ) + "_" +
               ip_to_string( four.dest_ip ) + "_" +
               std::to_string( four.dest_port) ;
    }

    // ====================
    //  Print HTTP Request
    // ====================

    void print_http_request( const http_request& request, std::ostream& os ) {
        const int label_width = 20;
        os << std::left << std::setfill(' ');
        os << "===== HTTP REQUEST BEGIN =====\n";
        os << request.request_line.method_token << " "
           << request.request_line.request_target << " "
           << request.request_line.http_version << "\n\n";

        if ( request.headers.empty() ) {
            os << "No Headers\n";
        } else {
            for ( const auto& [ key, value ] : request.headers ) {
                os << std::left << std::setw( label_width ) << ( key + ":" ) << value << "\n";
            }
        }
        os << "===== HTTP REQUEST END =====\n\n";
    }

    void print_http_request( std::span<const uint8_t> payload, std::ostream& os ) {
        auto parse_result = get_http_request( payload );
        if ( !parse_result ) {
            return;
        } 
        print_http_request( parse_result.value() );
    }

    // =====================
    //  Print HTTP Response
    // =====================

    void print_http_response( const http_response& response, std::ostream& os ) {
        const int label_width = 40;
        os << std::left << std::setfill(' ');
        os << "===== HTTP RESPONSE BEGIN =====\n";
        os << response.status_line.http_version << " "
           << response.status_line.status_code << " "
           << response.status_line.reason_phrase << "\n\n";

        if ( response.headers.empty() ) {
            os << "No Headers\n";
        } else {
            for ( const auto& [ key, value ] : response.headers ) {
                os << std::left << std::setw( label_width ) << ( key + ":" ) << value << "\n";
            }
        }
        os << std::left << std::setw( label_width ) << "Payload_Length: " << response.body.size() << "\n";
        os << "===== HTTP RESPONSE END =====\n\n";
    };

    void print_http_response( std::span<const uint8_t> payload, std::ostream& os ) {
        auto parse_result = get_http_response( payload );
        if ( !parse_result ) {
            std::cout << parse_result.error() << std::endl;
        }
        print_http_response( parse_result.value(), os );
    }

    // =======================
    //  Write Payload To File
    // =======================

    void write_payload_to_file( const std::vector<uint8_t>& payload, const std::string& filename ) {
        std::ofstream out( filename, std::ios::binary );
        if ( !out ) {
            throw std::runtime_error( "Failed to open file for writing: " + filename );
        }
        out.write( reinterpret_cast<const char*>( payload.data() ), payload.size() );
    }

    // =======================
    //  Print TCP Termination
    // =======================

    void print_tcp_termination( const tcp_termination& termination ) {
        if ( std::holds_alternative<ntk::fin_ack_fin_ack>( termination.closing_sequence ) ) {
            for ( auto& packet : std::get<ntk::fin_ack_fin_ack>( termination.closing_sequence ) ) {
                auto header_result = get_parsed_tcp_header_from_ethernet( packet );
                if ( !header_result ) {
                    std::cout << header_result.error() << std::endl;
                }
                print_tcp_header( header_result.value() );
            } 
        } else {
            auto& reset = std::get<ntk::rst>( termination.closing_sequence );
            auto header_result = get_parsed_tcp_header_from_ethernet( reset );
            if ( !header_result ) {
                std::cout << header_result.error() << std::endl;
            } 
            print_tcp_header( header_result.value() );
        }
    }

    // =======================
    //  Print Tbs Certificate
    // =======================

    void print_tbs_certificate( std::span<const uint8_t> certificate ) {
        auto tbs_parse_result = get_tbs_certificate( certificate );
        if ( !tbs_parse_result ) {
            std::cout << tbs_parse_result.error() << std::endl;
            return;
        }
        auto& tbs_cert = tbs_parse_result.value();
        auto algorithm_result = get_algorithm_identifier( tbs_cert.algorithm_identifier );
        if ( !algorithm_result ) {
            std::cout << algorithm_result.error() << std::endl;
            return;
        }
        std::cout << "Signature: " << algorithm_result.value() << std::endl;
        auto issuer_rdn_result = get_tbs_rdns( tbs_cert.issuer_rdn );
        if ( !issuer_rdn_result ) {
            std::cout << issuer_rdn_result.error() << std::endl;
            return;
        } 
        print_rdns( issuer_rdn_result.value() );
        auto validity_result = get_tbs_validity( tbs_cert.validity );
        if ( !validity_result ) {
            std::cout << validity_result.error() << std::endl;
            return;
        }
        auto subject_rdn_reuslt = get_tbs_rdns( tbs_cert.subject_rdn );
        if ( !subject_rdn_reuslt ) {
            std::cout << subject_rdn_reuslt.error() << std::endl;
            return;
        }
        print_rdns( subject_rdn_reuslt.value() );
        auto public_key_info_result = get_subject_public_key_info( tbs_cert.subject_public_key_info );
        if ( !public_key_info_result ) {
            std::cout << public_key_info_result.error() << std::endl;
            return;
        }
        print_subject_public_key_info( public_key_info_result.value() );
        if ( tbs_cert.extensions ) {
            auto extensions_result = get_extensions( tbs_cert );
            if ( !extensions_result ) {
                std::cout << extensions_result.error() << std::endl;
                return;
            }
            print_tbs_extensions( extensions_result.value() );
        }
    }

    // =====================
    //  Print Tbs Extension
    // =====================

    void print_tbs_extension( const extension& ext ) {
        auto dotted_string_result = convert_oid_to_dotted_string( ext.id );
        if ( !dotted_string_result ) {
            std::cout << "Failed to convert OID to Dotted String" << dotted_string_result.error() << std::endl;
            return;
        }
        auto& dotted_string = dotted_string_result.value();
        std::cout << object_identifier_names.at( dotted_string ) << " (" << dotted_string << ')' << std::endl;
    }

    // ======================
    //  Print Tbs Extensions
    // ======================

    void print_tbs_extensions( std::span<extension> extensions ) {
        for ( auto& extension : extensions ) {
            print_tbs_extension( extension );
        }
    }

    // ============
    //  Print RDNs
    // ============

    void print_rdns( std::span<const tbs_rdn> rdns ) {
        for ( auto& rdn : rdns ) {
            auto string_result = convert_oid_to_dotted_string( rdn.oid );
            if ( !string_result ) {
                std::cout << "Failed to convert RDN OID to string" << std::endl;
                continue;
            }
            auto& oid = string_result.value();
            std::cout << oid << ": " << rdn.value << std::endl;
        }
    }

    // ===============================
    //  Print Subject Public Key Info
    // ===============================

    void print_subject_public_key_info( const subject_public_key_info& public_key_info ) {
        auto algorithm_result = convert_oid_to_dotted_string( public_key_info.algorithm );
        if ( !algorithm_result ) {
            std::cout << algorithm_result.error() << std::endl;
            return;
        }
        std::cout << object_identifier_names.at( algorithm_result.value() ) << std::endl;
        auto parameters_result = convert_oid_to_dotted_string( public_key_info.parameters );
        if ( !parameters_result ) {
            std::cout << parameters_result.error() << std::endl;
            return;
        }
        std::cout << object_identifier_names.at( parameters_result.value() ) << std::endl;
        std::cout << "Key: " << bytes_to_hex_string( public_key_info.key ) << std::endl;
    }

} // namespace ntk


    