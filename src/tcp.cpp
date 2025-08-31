#include <tcp.hpp>

namespace ntk {

    // ==============================
    //       Get TCP Seq Number
    // ==============================

    std::expected<uint32_t,std::string> get_seq_number( std::span<const uint8_t> packet ) {
        auto result = get_raw_tcp_header( packet );
        if ( !result ) {
            return std::unexpected( result.error() );
        }
        return read_uint32_be( result.value(), tcp_header_offset::seq_number ); 
    }

    // ==============================
    //       Get TCP Ack Number
    // ==============================

    std::expected<uint32_t,std::string> get_ack_number( std::span<const uint8_t> packet ) {
        auto result = get_raw_tcp_header( packet );
        if ( !result ) {
            return std::unexpected( result.error() );
        }
        return read_uint32_be( result.value(), tcp_header_offset::ack_number );
    }

    // ==============================
    //      Get TCP Header Len
    // ==============================

    std::size_t get_tcp_header_len( const unsigned char* ethernet_frame, const std::size_t tcp_header_start ) {  
        constexpr std::size_t bytes_per_offset = 4;
        const std::size_t data_offset_pos = tcp_header_start + tcp_header_offset::data_offset;
        const uint8_t data_offset_byte = ethernet_frame[ data_offset_pos ];
        const std::size_t tcp_header_len = extract_high_nibble( data_offset_byte ) * bytes_per_offset;
        return tcp_header_len;
    }

    // ==============================
    //      Get Raw TCP Header
    // ==============================

    std::vector<uint8_t> get_raw_tcp_header( const unsigned char* ethernet_frame, const std::size_t ipv4_header_len ) {
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        
        std::vector<uint8_t> tcp_header;
        const std::size_t tcp_header_offset = ethernet_header_len + ipv4_header_len;
        const std::size_t tcp_header_len = get_tcp_header_len( ethernet_frame, tcp_header_offset );
        
        tcp_header.resize( tcp_header_len );
        std::memcpy( tcp_header.data(), ethernet_frame + tcp_header_offset, tcp_header_len );

        return tcp_header;
    }

    std::expected<std::vector<uint8_t>,std::string> get_raw_tcp_header( const unsigned char* ethernet_frame ) {
        auto ipv4_header_len_result = get_ipv4_header_len( ethernet_frame );
        if ( !ipv4_header_len_result ) {
            return std::unexpected( ipv4_header_len_result.error() );
        }
        return get_raw_tcp_header( ethernet_frame, ipv4_header_len_result.value() );
    }

    std::expected<std::vector<uint8_t>,std::string> get_raw_tcp_header( const std::span<const uint8_t> packet ) {
        return get_raw_tcp_header( packet.data() );
    }

    // ==============================
    //        Get TCP Payload
    // ==============================

    std::expected<std::vector<uint8_t>,std::string> get_tcp_payload( const unsigned char* ethernet_frame ) { 
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        
        auto ipv4_header_len_result = get_ipv4_header_len( ethernet_frame ); 
        if ( !ipv4_header_len_result ) {
            return std::unexpected( ipv4_header_len_result.error() );
        }
        const uint16_t total_length = read_uint16_be( ethernet_frame, ethernet_header_len + 2 );
        const std::size_t tcp_header_offset = ethernet_header_len + ipv4_header_len_result.value();
        const std::size_t tcp_header_len = get_tcp_header_len( ethernet_frame, tcp_header_offset );
        
        const std::size_t payload_len = total_length - ipv4_header_len_result.value() - tcp_header_len;
        const uint8_t* payload_ptr = ethernet_frame + tcp_header_offset + tcp_header_len;

        std::vector<uint8_t> payload( payload_len );
        std::memcpy( payload.data(), payload_ptr, payload_len );

        return payload;
    }

    std::expected<std::vector<uint8_t>,std::string> get_tcp_payload( const std::span<const uint8_t> packet ) {
        return get_tcp_payload( packet.data() );
    }

    // ==============================
    //      Extract TCP Option
    // ==============================

    std::expected<std::optional<tcp_option>,std::string> get_tcp_option( std::span<const uint8_t>& tcp_options_list_bytes ) {
        constexpr std::size_t option_data_offset = 2;
        auto kind_opt = get_tcp_option_type( tcp_options_list_bytes.front() );
        if ( !kind_opt ) {
            return std::unexpected( "Unrecognized TCP Option Type" );
        }
        auto kind = kind_opt.value();
    
        if ( kind == tcp_option_type::end_of_options_list ) {
            tcp_options_list_bytes = tcp_options_list_bytes.subspan( 1 /* consume the kind byte */ );
            return std::nullopt;
        } else if ( kind == tcp_option_type::nop ) {
            tcp_options_list_bytes = tcp_options_list_bytes.subspan( 1 /* consume the kind byte */ );
            return tcp_option { kind, {} /* NOP option has no value */ };
        } else {
            const uint8_t length = tcp_options_list_bytes[ 1 ];
            std::vector<uint8_t> data;
            if ( length + option_data_offset > tcp_options_list_bytes.size()  ) {
                data.insert( data.end(), 
                             tcp_options_list_bytes.begin() + option_data_offset,
                             tcp_options_list_bytes.begin() + length );
            } else {
                return std::unexpected( "TCP Option is truncated" );
            }
            tcp_options_list_bytes = tcp_options_list_bytes.subspan( length ); 
            return tcp_option { kind, data };
        }
    }

    std::optional<tcp_option_type> get_tcp_option_type( const uint8_t option_type_byte ) {
        auto option_type = static_cast<tcp_option_type>( option_type_byte );
        auto it = std::ranges::find( look_up::tcp_option_types, option_type );
        if ( it == look_up::tcp_option_types.end() ) {
            return std::nullopt;
        }
        return *it;
    }

    std::expected<std::vector<tcp_option>,std::string> get_parsed_tcp_options( std::span<const uint8_t>& tcp_options_list_bytes ) {
        std::vector<tcp_option> options;
        while ( !tcp_options_list_bytes.empty() ) {
            auto option_result = get_tcp_option( tcp_options_list_bytes );
            if ( !option_result ) {
                return std::unexpected( option_result.error() );
            } 
            if ( option_result.value().has_value() ) {
                options.push_back( option_result.value().value() );
            }
        }
        return options;
    }

    // ==============================
    //     Get Parsed TCP Header
    // ==============================

    std::expected<tcp_header,std::string> get_parsed_tcp_header( std::span<const uint8_t> raw_tcp_header ) {
        constexpr std::size_t basic_header_len = 20;
        if ( raw_tcp_header.size() < basic_header_len ) {
            return std::unexpected( "Invalid TCP header size" );
        }

        tcp_header header;
        header.src_port = read_uint16_be( raw_tcp_header, tcp_header_offset::src_port ); 
        header.dest_port = read_uint16_be( raw_tcp_header, tcp_header_offset::dest_port );  
        header.seq_number = read_uint32_be( raw_tcp_header, tcp_header_offset::seq_number ); 
        header.ack_number = read_uint32_be( raw_tcp_header, tcp_header_offset::seq_number );
        header.data_offset = extract_high_nibble( raw_tcp_header[ tcp_header_offset::data_offset ] );  
        header.flags = raw_tcp_header[ tcp_header_offset::flags ];
        header.window_size = read_uint16_be( raw_tcp_header, tcp_header_offset::window_size ); 
        header.checksum = read_uint16_be( raw_tcp_header, tcp_header_offset::checksum ); 
        header.urgent_ptr = read_uint16_be( raw_tcp_header, tcp_header_offset::urgent_ptr );

        if ( header.data_offset == 5 /* data offset of header with no options */ ) 
            return header;

        raw_tcp_header = raw_tcp_header.subspan( basic_header_len );

        auto options_result = get_parsed_tcp_options( raw_tcp_header );
        if ( !options_result ) {
            return std::unexpected( options_result.error() );
        }
        options_result = std::move( options_result.value() ); 

        return header;
    }

    std::expected<tcp_header,std::string> get_parsed_tcp_header( const unsigned char* ethernet_frame ) {
        auto result = get_raw_tcp_header( ethernet_frame );
        if ( !result ) {
            return std::unexpected( result.error() );
        }
        return get_parsed_tcp_header( result.value() );
    }

    std::expected<tcp_header,std::string> get_parsed_tcp_header_from_ethernet( std::span<const uint8_t> packet ) {
        auto result = get_raw_tcp_header( packet );
        if ( !result ) {
            return std::unexpected( result.error() );
        }
        return get_parsed_tcp_header( result.value() );
    }

    // ==============================
    //      Get Raw TCP Stream
    // ==============================

    std::vector<raw_tcp_frame> get_raw_tcp_stream( const session& tcp_session ) {
        std::vector<raw_tcp_frame> tcp_stream;

        for ( auto& packet : tcp_session ) {
            auto header = get_raw_tcp_header( packet );
            if ( !header ) {
                continue;
            }
            auto body = get_tcp_payload( packet );
            if ( !body ) {
                continue;
            }

            if ( body.value().empty() ) {
                continue;
            }

            raw_tcp_frame frame = {
                .header = header.value(),
                .body = body.value()
            };

            tcp_stream.push_back( frame );
        }

        return tcp_stream;
    }

    // ==============================
    //        Get TCP Stream
    // ==============================

    tcp_stream get_tcp_stream( const std::vector<raw_tcp_frame>& raw_stream ) {
        tcp_stream stream;
        for ( auto& tcp_frame : raw_stream ) {
            auto parse_result = get_parsed_tcp_header( tcp_frame.header );
            if ( !parse_result ) {
                continue;
            }
            auto parsed_tcp_header = parse_result.value();
            stream[ parsed_tcp_header.seq_number ] = tcp_frame.body;
        }
        return stream;
    } 

    bool is_non_overlapping_stream( const tcp_stream& stream ) {
        if ( stream.empty() ) return true;
        uint32_t last_end_seq = 0;
        bool first = true;

        for ( const auto& [ seq, payload ] : stream ) {
            uint32_t start_seq = seq;
            uint32_t length = static_cast<uint32_t>( payload.size() );
            uint32_t end_seq = start_seq + length;

            if ( !first && start_seq < last_end_seq ) {
                return false;
            }

            last_end_seq = end_seq;
            first = false;
        }
        return true;
    }

    tcp_stream merge_tcp_stream_non_overlapping( const tcp_stream& stream ) {
        tcp_stream merged;
        uint32_t end_of_last = 0;

        for ( const auto& [ seq, data ] : stream ) {
            if ( seq >= end_of_last ) {
                merged[ seq ] = data;
                end_of_last = seq + data.size();
            } else if ( seq + data.size() <= end_of_last ) {
                continue;
            } else {
                size_t overlap = end_of_last - seq;
                std::vector<uint8_t> trimmed( data.begin() + overlap, data.end() );
                merged[ end_of_last ] = trimmed;
                end_of_last += trimmed.size();
            }
        }

        return merged;
    }

    // ==============================
    //      Merge TCP Stream
    // ==============================

    tcp_stream get_merged_tcp_stream( const session& packet_data ) {
        auto raw_stream = get_raw_tcp_stream( packet_data );
        auto tcp_stream = get_tcp_stream( raw_stream );
        auto merged_tcp_stream = merge_tcp_stream_non_overlapping( tcp_stream );
        return merged_tcp_stream;
    }

    // ==============================
    //         TCP Predicates
    // ==============================

    std::expected<bool,std::string> is_tcp( const unsigned char* packet ) {
        auto parse_result = get_parsed_ipv4_header( packet );
        if ( !parse_result ) {
            return std::unexpected( parse_result.error() );
        }
        return static_cast<protocol>( parse_result.value().protocol ) == protocol::tcp;
    }

    std::expected<bool,std::string> is_tcp_v( const std::vector<uint8_t>& packet ) {
        return is_tcp( packet.data() );
    }

    std::expected<bool,std::string> have_same_sequence_number( std::span<const uint8_t> lhs, std::span<const uint8_t> rhs ) {
        auto lhs_result = get_seq_number( lhs );
        if ( !lhs_result ) {
            std::unexpected( lhs_result.error() );
        }
        auto rhs_result = get_seq_number( rhs );
        if ( !rhs_result ) {
            std::unexpected( rhs_result.error() );
        }
        return lhs_result.value() == rhs_result.value();
    }

    // ==============================
    //     Is Same TCP Connection
    // ==============================

    bool is_same_connection( const four_tuple& lhs, const four_tuple& rhs )  { 
        return lhs == rhs || lhs == flip_four( rhs );
    }

    std::expected<bool,std::string> is_same_connection( std::span<const uint8_t> packet, const four_tuple& four ) {
        auto four_result = get_four_from_ethernet( packet );
        if ( !four_result ) {
            return std::unexpected( four_result.error() );
        }
        return is_same_connection( four_result.value(), four );
    }

    std::expected<bool,std::string> is_same_connection( std::span<const uint8_t> lhs, std::span<const uint8_t> rhs ) {
        auto lhs_four_result = get_four_from_ethernet( lhs );
        if ( !lhs_four_result ) {
            return std::unexpected( lhs_four_result.error() );
        }
        auto rhs_four_result = get_four_from_ethernet( rhs );
        if ( !rhs_four_result ) {
            return std::unexpected( rhs_four_result.error() );
        } 
        return is_same_connection( lhs_four_result.value(), rhs_four_result.value() );
    }

    // ==============================
    //        SYN Predicates
    // ==============================

    bool is_syn( const tcp_header& packet_tcp_header ) {
        return flags_contains( packet_tcp_header.flags, tcp_flags::syn ) && 
               !flags_contains( packet_tcp_header.flags, tcp_flags::ack );
    }

    std::expected<bool,std::string> is_syn( std::span<const uint8_t> packet ) {
        auto parse_result = get_parsed_tcp_header( packet );
        if ( !parse_result ) {
            return std::unexpected( parse_result.error() );
        }
        return is_syn( parse_result.value() );
    }

    // ==============================
    //        ACK Predicates
    // ==============================

    bool is_ack( const tcp_header& packet_tcp_header ) {
        return flags_contains( packet_tcp_header.flags, tcp_flags::ack );
    }

    std::expected<bool,std::string> is_ack( std::span<const uint8_t> packet ) {
        auto parse_result = get_parsed_tcp_header( packet );
        if ( !parse_result ) {
            return std::unexpected( parse_result.error() );
        }
        return is_ack( parse_result.value() );
    }

    // ==============================
    //       SYNACK Predicates
    // ==============================

    bool is_syn_ack( const tcp_header& packet_tcp_header ) {
        return flags_contains( packet_tcp_header.flags, tcp_flags::syn ) && 
               flags_contains( packet_tcp_header.flags, tcp_flags::ack );
    }

    std::expected<bool,std::string> is_syn_ack( std::span<const uint8_t> packet ) {
        auto parse_result = get_parsed_tcp_header( packet );
        if ( !parse_result ) {
            return std::unexpected( parse_result.error() );
        }
        return is_syn_ack( parse_result.value() );
    }

    // ==============================
    //          Is SYN Of
    // ==============================

    bool is_syn_of( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        return is_syn( packet ) && is_same_connection( packet, four );
    }

    // ==============================
    //         Is SYNACK Of
    // ==============================

    bool is_syn_ack_of( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        return is_syn_ack( packet ) && is_same_connection( packet, four );
    }

    // ==============================
    //           Is ACK Of
    // ==============================

    bool is_ack_of( std::span<const uint8_t> packet, const four_tuple& four ) {
        return is_ack( packet ) && is_same_connection( packet, four );
    }

    // ==============================
    //         Is Ack Of Seq
    // ==============================

    std::expected<bool,std::string> is_ack_of_seq( std::span<const uint8_t> data_sender_packet, std::span<const uint8_t> data_reciever_packet ) {
        auto seq_number_result = get_seq_number( data_sender_packet );
        if ( !seq_number_result ) {
            return std::unexpected( seq_number_result.error() );
        }
        auto ack_number_result = get_ack_number( data_reciever_packet );
        if ( !ack_number_result ) {
            return std::unexpected( ack_number_result.error() );
        }
        return is_ack_of_seq( seq_number_result.value(), ack_number_result.value() );
    }

    bool is_ack_of_seq( const tcp_header& data_sender_header, const tcp_header& data_reciever_header ) {
        return is_ack_of_seq( data_sender_header.seq_number, data_reciever_header.ack_number );
    }

    std::expected<bool,std::string> is_ack_of_seq( std::span<const uint8_t> data_sender_packet, const tcp_header& data_reciever_header ) {
        auto seq_number_result = get_seq_number( data_sender_packet );
        if ( !seq_number_result ) {
            return std::unexpected( seq_number_result.error() );
        }
        return is_ack_of_seq( seq_number_result.value(), data_reciever_header.ack_number );
    }

    std::expected<bool,std::string> is_ack_of_seq( const tcp_header& data_sender_header, std::span<const uint8_t> data_reciever_packet ) {
        auto ack_number_result = get_ack_number( data_reciever_packet );
        if ( !ack_number_result ) {
            return std::unexpected( ack_number_result.error() );
        }
        return is_ack_of_seq( data_sender_header.seq_number, ack_number_result.value() );
    }

    bool is_ack_of_seq( const uint32_t seq_number, const uint32_t ack_number ) {
        return ack_number == seq_number + 1;
    }

    // ==============================
    //           Is FYNACK
    // ==============================

    std::expected<bool,std::string> is_fin_ack( std::span<const uint8_t> packet ) {
        auto parse_result = ntk::get_parsed_tcp_header( packet );
        if ( !parse_result ) {
            return std::unexpected( parse_result.error() );
        }
        return is_fin_ack( parse_result.value() );
    };

    bool is_fin_ack( const tcp_header& header ) {
        return flags_contains( header.flags, tcp_flags::fin_ack );
    }

    // ==============================
    //         Flags Contains
    // ==============================

    bool flags_contains( const uint8_t header_flags, const tcp_flags flags ) {
        return ( header_flags & static_cast<uint8_t>( flags ) ) == static_cast<uint8_t>( flags );
    }

    // ==============================
    //        RESET Predicates
    // ==============================

    std::expected<bool,std::string> is_reset( std::span<const uint8_t> packet ) {
        auto parse_result = get_parsed_tcp_header( packet );
        if ( !parse_result ) {
            return std::unexpected( parse_result.error() );
        }
        return flags_contains( parse_result.value().flags, tcp_flags::rst );
    }

    bool has_four( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        auto packet_four = get_four_from_ethernet( packet );
        return packet_four == four;
    }

    bool has_flipped_four( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        auto packet_four = get_four_from_ethernet( packet );
        return packet_four == flip_four( four );
    }

    // ==============================
    //         TCP Handshake
    // ==============================

    std::optional<tcp_handshake> get_handshake( const four_tuple& four, const session& packets ) {
        session connection_packets = packets 
            | std::views::filter( [ & ] ( const auto& packet ) { 
                auto result = is_same_connection( packet, four );
                return result.has_value() && result.value(); 
            } ) 
            | std::ranges::to<std::vector>();
        return get_handshake( connection_packets ); 
    }

    std::optional<tcp_handshake> get_handshake( const session& packets ) {
        for ( auto&& window : std::views::slide( packets, 3 ) ) {
            const auto [ syn, synack, ack ] = make_triple( window );
            if ( is_valid_handshake( syn, synack, ack ) ) {
                return tcp_handshake{ syn, synack, ack };
            }
        }
        return std::nullopt; 
    }

    std::vector<tcp_handshake> get_handshakes( const four_tuple& four, const session& packets ) {
        session connection_packets = packets 
            | std::views::filter( [ & ] ( const auto& packet ) { 
                auto result = is_same_connection( packet, four );
                return result.has_value() && result.value(); 
            } ) 
            | std::ranges::to<std::vector>();
        return get_handshakes( connection_packets ); 
    }
        
    std::vector<tcp_handshake> get_handshakes( const session& packets ) {        
        std::vector<tcp_handshake> handshakes;
        for ( auto&& window : std::views::slide( packets, 3 ) ) {
            const auto [ syn, synack, ack ] = make_triple( window );
            if ( is_valid_handshake( syn, synack, ack ) ) {
                handshakes.emplace_back( syn, synack, ack );
            }
        }
        return handshakes; 
    }

    const std::vector<uint8_t>* get_end_of_handshake( const session& packets, const tcp_handshake& handshake ) {   
        for ( auto&& window : std::views::slide( packets, 3 ) ) {
            const auto [ maybe_syn, maybe_synack, maybe_ack ] = make_triple( window );
            if ( have_same_sequence_number( handshake.syn, maybe_syn ) && is_valid_handshake( maybe_syn, maybe_synack, maybe_ack ) ) {
                return &maybe_ack;
            }
        }
        return nullptr;
    }

    // ==============================
    //    TCP Handshake Predicates
    // ==============================

    bool is_valid_handshake( const tcp_handshake& handshake ) {
        return is_valid_handshake( handshake.syn, handshake.syn_ack, handshake.ack );
    }

    bool is_valid_handshake( const tcp_header& syn_header, const tcp_header& synack_header, const tcp_header& ack_header ) {
        return is_ack_of_seq( syn_header, synack_header ) && is_ack_of_seq( synack_header, ack_header );
    }

    bool is_valid_handshake( const std::vector<uint8_t>& syn, const std::vector<uint8_t>& synack, const std::vector<uint8_t>& ack ) {
        return is_ack_of_seq( syn, synack ) && is_ack_of_seq( synack, ack );
    }

    // ==============================
    //     TCP Handshake Feed
    // ==============================

    std::expected<bool,std::string> tcp_handshake_feed::feed_packet( std::span<const uint8_t> packet ) {
        auto parse_result = get_parsed_tcp_header( packet );
        if ( !parse_result ) {
            return std::unexpected( parse_result.error() );
        }

        if ( is_syn( parse_result.value() ) ) {
            reset();
            m_syn = std::vector<uint8_t>( packet.begin(), packet.end() );
            return true;
        }

        if ( m_syn && !m_syn_ack && is_syn_ack( parse_result.value() ) &&
             is_ack_of_seq( get_parsed_tcp_header( m_syn.value() ).value(), parse_result.value() ) ) {
            m_syn_ack = std::vector<uint8_t>( packet.begin(), packet.end() );
            return true;
        }

        if ( m_syn_ack && is_ack( packet ) &&
             is_ack_of_seq( get_parsed_tcp_header( m_syn_ack.value() ).value(), parse_result.value() ) ) {
            m_ack = std::vector<uint8_t>( packet.begin(), packet.end() );
            return true;
        }

        return false;
    }

    std::expected<bool,std::string> tcp_handshake_feed::feed( std::span<const uint8_t> packet ) { 
        auto feed_result = feed_packet( packet );
        if ( !feed_result ) {
            return std::unexpected( feed_result.error() );
        }
        bool accepted = feed_result.value();
        if ( !accepted ) return false;

        if ( m_syn && m_syn_ack && m_ack ) {
            m_handshake = tcp_handshake {
                .syn = *m_syn,
                .syn_ack = *m_syn_ack,
                .ack = *m_ack
            };
            m_complete = true;
        }

        return true;
    };

    // ==============================
    //        TCP Termination 
    // ==============================

    tcp_termination::tcp_termination( const maybe_termination& maybe ) {
        *this = maybe;
    }

    tcp_termination& tcp_termination::operator=( const maybe_termination& maybe ) {
        closing_sequence = fin_ack_fin_ack{ *maybe.initiator_fin, *maybe.responder_ack, *maybe.responder_fin, *maybe.initiator_ack };
        return *this;
    }

    // ==============================
    //        Maybe Termination 
    // ==============================

    std::expected<bool,std::string> maybe_termination::feed( std::span<const uint8_t> packet ) {
        auto parse_result = get_parsed_tcp_header( packet );
        if ( !parse_result ) {
            return std::unexpected( parse_result.error() );
        }
        if ( !initiator_fin && is_fin_ack( parse_result.value() ) ) {
            initiator_fin = std::vector<uint8_t>( packet.begin(), packet.end() );
            return true;
        }
        if ( !responder_fin && is_fin_ack( parse_result.value() ) ) {
            responder_fin = std::vector<uint8_t>( packet.begin(), packet.end() );
            if ( is_ack_of_seq( *initiator_fin, parse_result.value() ) ) {
                responder_ack = std::vector<uint8_t>( packet.begin(), packet.end() );
            }
            return true;
        }
        if ( initiator_fin && !responder_ack ) {
            if ( is_ack( packet ) && is_ack_of_seq( *initiator_fin, parse_result.value() ) ) {
                responder_ack = std::vector<uint8_t>( packet.begin(), packet.end() );
                return true;
            }
        }
        if ( responder_fin && !initiator_ack && is_ack( parse_result.value() ) ) {
            if ( is_ack_of_seq( *responder_fin, parse_result.value() ) ) {
                initiator_ack = std::vector<uint8_t>( packet.begin(), packet.end() );
                return true;
            }
        }
        return false;
    }

    maybe_termination::operator bool() const {
        return initiator_fin && responder_ack && responder_fin && initiator_ack;
    }

    void maybe_termination::reset() {
        initiator_fin = responder_ack = responder_fin = initiator_ack = std::nullopt;
    }

    // ==============================
    //      Get TCP Termination
    // ==============================

    std::optional<tcp_termination> get_termination( const four_tuple& four, const session& packets ) {
        std::vector<std::vector<uint8_t>> connection_packets;

        for ( const auto& packet : packets ) {
            if ( is_same_connection( packet, four ) ) {
                connection_packets.push_back( packet );
            }
        }

        maybe_termination termination;

        for ( const auto& packet : connection_packets ) {
            termination.feed( packet );
        }

        if ( termination ) {
            tcp_termination result; 
            result = termination;
            return result;
        }

        for ( const auto& packet : connection_packets ) {
            if ( is_reset( packet ) ) { 
                return tcp_termination { rst{ packet } };
            }
        }

        return std::nullopt;
    }

    std::vector<tcp_termination> get_terminations( const four_tuple& four, const session& packets ) {
        std::vector<tcp_termination> terminations;
        std::vector<std::vector<uint8_t>> connection_packets;

        for ( const auto& packet : packets ) {
            if ( is_same_connection( packet, four ) ) {
                connection_packets.push_back( packet );
            }
        }

        maybe_termination termination;

        for ( const auto& packet : connection_packets ) {
            auto packet_tcp_header = get_parsed_tcp_header( packet );
            termination.feed( packet );
            if ( termination ) {
                terminations.push_back( termination );
                termination.reset();
            }
        }

        for ( const auto& packet : connection_packets ) {
            if ( is_reset( packet ) ) { 
                terminations.push_back( tcp_termination{ rst { packet} } );
             }
        }

        return terminations;
    }

    // ==============================
    //  Get Start of TCP Termination
    // ==============================

    const std::vector<uint8_t>* get_start_of_termination( const session& packets, const tcp_termination& termination ) {
        return std::visit( [ & ] ( const auto& closing ) -> const std::vector<uint8_t>* {
            if constexpr ( std::is_same_v<std::decay_t<decltype( closing )>, fin_ack_fin_ack> ) {
                for ( const auto& packet : packets ) {
                    if ( have_same_sequence_number( packet, closing.initiator_fin ) ) {
                        return &packet;
                    }
                }
            } else if constexpr ( std::is_same_v<std::decay_t<decltype( closing )>, rst> ) {
                for ( const auto& packet : packets ) {
                    if (have_same_sequence_number( packet, closing ) ) {
                        return &packet;
                    }
                }
            } 
            return nullptr;
        }, termination.closing_sequence );
    }

    // ==============================
    //  TCP Termination Predicates
    // ==============================

    bool is_valid_fin_ack_fin_ack( const fin_ack_fin_ack& closing_sequence ) {
        return is_ack_of_seq( closing_sequence.initiator_fin, closing_sequence.responder_ack ) &&
               is_ack_of_seq( closing_sequence.responder_fin, closing_sequence.initiator_ack );

    }

    bool is_valid_fin_ack_fin_ack( const tcp_termination& termination ) {
        if ( std::holds_alternative<fin_ack_fin_ack>( termination.closing_sequence ) ) {
            return is_valid_fin_ack_fin_ack( std::get<fin_ack_fin_ack>( termination.closing_sequence ) );
        } else {
            return false;
        }
    }

    // ==============================
    //      TCP Termination Feed
    // ==============================

    std::expected<bool,std::string> tcp_termination_feed::feed( std::span<const uint8_t> packet ) {
        auto feed_result = feed_packet( packet );
        if ( !feed_result ) {
            return std::unexpected( feed_result.error() );
        } 
        
        if ( m_maybe_termination ) {
            m_termination = m_maybe_termination;
            m_complete = true;
        }

        return feed_result.value();
    }

    std::expected<bool,std::string> tcp_termination_feed::feed_packet( std::span<const uint8_t> packet ) {
        auto feed_result = m_maybe_termination.feed( packet );
        if ( !feed_result ) {
            return std::unexpected( feed_result.error() );
        }
        return feed_result.value();
    }

    // ==============================
    //            Classes
    // ==============================
    
    tcp_transfer::tcp_transfer( const four_tuple& four ) 
        : m_four( four ) {} 

    void tcp_transfer::load( const session& packet_data ) {
        tcp_handshake handshake = *get_handshake( m_four, packet_data );
        tcp_termination termination = *get_termination( m_four, packet_data );
        m_handshake = handshake;
        m_termination = termination;
        split_stream( packet_data );
    }

    void tcp_transfer::split_stream( const session& packet_data ) {
        auto syn_header = get_parsed_tcp_header( m_handshake.syn );
        auto syn_ack_header = get_parsed_tcp_header( m_handshake.syn_ack );
        auto handshake_ack_ptr = get_end_of_handshake( packet_data, m_handshake );
        handshake_ack_ptr++;
        auto termination_ptr = get_start_of_termination( packet_data, m_termination );
        auto size = static_cast<size_t>( termination_ptr - handshake_ack_ptr );
        auto packet_span = std::span{ handshake_ack_ptr, size };

        for ( auto& packet : packet_span ) {
            if ( is_data_packet( packet ) && has_four( packet, m_four ) ) {
                m_client_traffic.push_back( packet );
                continue;
            }
            if ( is_data_packet( packet ) && has_flipped_four( packet, m_four ) ) {
                m_server_traffic.push_back( packet );
                continue;
            }
            if ( is_ack( packet ) && has_four( packet, m_four ) ) {
                m_client_acks.push_back( packet );
                continue;
            }
            if ( is_ack( packet ) && has_flipped_four( packet, m_four ) ) {
                m_server_acks.push_back( packet );
                continue;
            }
        }
    }

    tcp_live_stream::tcp_live_stream( const four_tuple& four ) 
        : m_four( four ), m_handshake_feed( four ), m_termination_feed( four ) {}

    bool tcp_live_stream::operator==( const tcp_live_stream& other ) const {

        return m_four == other.m_four && m_handshake_feed.m_handshake == other.m_handshake_feed.m_handshake && 
            m_termination_feed.m_termination == other.m_termination_feed.m_termination;
    }

    bool tcp_live_stream::is_complete() const {
        return m_termination_feed.m_complete;
    }

    std::expected<bool,std::string> tcp_live_stream::feed( std::span<const uint8_t> packet ) {
        if ( is_complete() ) return false;
        if ( !is_same_connection( packet, m_four ) ) return false;
        bool is_handshake_packet = false;
        bool is_termination_packet = false;
        
        if ( !m_handshake_feed.m_complete ) { 
            auto feed_result = m_handshake_feed.feed( packet );
            if ( !feed_result ) {
                return std::unexpected( feed_result.error() );
            } 
            is_handshake_packet = feed_result.value();
        }
        if ( is_handshake_packet ) return true;

        if ( !m_termination_feed.m_complete ) {
            auto feed_result = m_termination_feed.feed( packet );
            if ( !feed_result ) {
                return std::unexpected( feed_result.error() );
            }
            is_termination_packet = feed_result.value();
        }
        if ( is_termination_packet ) return true;

        m_traffic.emplace_back( packet.begin(), packet.end() );
        return true;
    }

    const four_tuple& tcp_live_stream::get_four_tuple() const {
        return m_four;
    }

    bool tcp_live_stream::is_client_packet( std::span<const uint8_t> packet ) const { 
        return has_four( packet, m_four ); 
    }

    bool tcp_live_stream::is_server_packet( std::span<const uint8_t> packet ) const { 
        return has_flipped_four( packet, m_four ); 
    }

    tcp_live_stream_session::tcp_live_stream_session() 
        : m_offload_queue( nullptr ) {}

    tcp_live_stream_session::tcp_live_stream_session( transfer_queue_interface<tcp_live_stream>* offload_queue )
        : m_offload_queue( offload_queue ) {}

    std::expected<bool,std::string> tcp_live_stream_session::feed_packet( std::span<const uint8_t> packet ) {
        auto four_result = get_four_from_ethernet( packet );
        if ( !four_result ) {
            std::unexpected( four_result.error() );
        }

        if ( !m_four_tuples.contains( four_result.value() ) && !m_four_tuples.contains( flip_four( four_result.value() ) ) ) {
            m_four_tuples.insert( four_result.value() );
            m_live_streams.emplace_back( tcp_live_stream{ four_result.value() } );
        } 

        if ( !m_offload_queue ) {
            for ( auto& stream : m_live_streams ) {
                auto feed_result = stream.feed( packet );
                if ( !feed_result ) {
                    return std::unexpected( feed_result.error() );
                }
                if ( feed_result.value() ) return true;
            }
        }

        std::vector<tcp_live_stream> updated_streams;
        for ( auto& stream : m_live_streams ) {
            auto feed_result = stream.feed( packet );
            if ( !feed_result ) {
                return std::unexpected( feed_result.error() );
            }
            if ( feed_result.value() ) { 
                if ( stream.is_complete() ) { 
                    offload( std::move( stream ) );
                    continue;
                }
            }
            updated_streams.push_back( std::move( stream ) );
        }
        
        m_live_streams = std::move( updated_streams );
    }

    void tcp_live_stream_session::offload( tcp_live_stream&& stream ) {
        if ( m_offload_queue ) {
            m_offload_queue->push( std::move( stream ) );
        }
    }

    size_t tcp_live_stream_session::number_of_completed_transfers() {
        size_t n_completed_sessions = std::count_if( m_live_streams.begin(), m_live_streams.end(), [&]( const auto& stream ) {
            return stream.is_complete();
        });
        return n_completed_sessions;
    }

    // ==============================
    //   TCP Transfer Friend Helper
    // ==============================

    const tcp_handshake& tcp_transfer_friend_helper::handshake( const tcp_transfer& t ) {
        return t.m_handshake;
    }

    const tcp_termination& tcp_transfer_friend_helper::termination( const tcp_transfer& t ) {
        return t.m_termination;
    }

    const std::vector<std::vector<uint8_t>>& tcp_transfer_friend_helper::client_acks( const tcp_transfer& t ) {
        return t.m_client_acks;
    }

    const std::vector<std::vector<uint8_t>>& tcp_transfer_friend_helper::server_acks( const tcp_transfer& t ) {
        return t.m_server_acks;
    }

    const std::vector<std::vector<uint8_t>>& tcp_transfer_friend_helper::client_traffic( const tcp_transfer& t ) {
        return t.m_client_traffic;
    }

    const std::vector<std::vector<uint8_t>>& tcp_transfer_friend_helper::server_traffic( const tcp_transfer& t ) {
        return t.m_server_traffic;
    }

    const four_tuple& tcp_transfer_friend_helper::four( const tcp_transfer& t ) {
        return t.m_four;
    }

    // ==============================
    //  TCP Live Stream Friend Helper
    // ==============================

    const tcp_handshake_feed& tcp_live_stream_friend_helper::handshake_feed( const tcp_live_stream& t ) {
        return t.m_handshake_feed;
    }

    const tcp_termination_feed& tcp_live_stream_friend_helper::termination_feed( const tcp_live_stream& t ) {
        return t.m_termination_feed;
    }

    const std::vector<std::vector<uint8_t>>& tcp_live_stream_friend_helper::traffic( const tcp_live_stream& t ) {
        return t.m_traffic;
    }

    const four_tuple& tcp_live_stream_friend_helper::four( const tcp_live_stream& t ) {
        return t.m_four;
    }

    bool tcp_live_stream_friend_helper::is_client_packet( const tcp_live_stream& t, const std::vector<uint8_t>& packet ) {
        return t.is_client_packet( packet );
    }

    bool tcp_live_stream_friend_helper::is_server_packet( const tcp_live_stream& t, const std::vector<uint8_t>& packet ) {
        return t.is_server_packet( packet );
    }

    const tcp_live_stream& tcp_live_stream_session_friend_helper::get_live_stream( const tcp_live_stream_session& t, const four_tuple& four ) {
        auto matched_live_stream = std::find_if( t.m_live_streams.begin(), t.m_live_streams.end(), [&]( const auto& live_stream ) { 
            auto& live_stream_four = tcp_live_stream_friend_helper::four( live_stream );
            return live_stream_four == four;
        });
        if ( matched_live_stream == t.m_live_streams.end() ) {
            throw std::runtime_error( "Live stream with given four tuple not found" );
        }
        return *matched_live_stream;
    }

    const std::vector<tcp_live_stream>& tcp_live_stream_session_friend_helper::live_streams( const tcp_live_stream_session& t ) {
        return t.m_live_streams;
    }

    const std::unordered_set<four_tuple>& tcp_live_stream_session_friend_helper::four_tuples( const tcp_live_stream_session& t ) {
        return t.m_four_tuples;
    }

    // ==============================
    //         Flip Four Tuple
    // ==============================

    four_tuple flip_four( const four_tuple& four ) {
        four_tuple flipped;
        flipped.client_ip = four.server_ip;
        flipped.server_ip = four.client_ip;
        flipped.server_port = four.client_port;
        flipped.client_port = four.server_port;
        return flipped;
    }

    std::expected<four_tuple,std::string> get_four_from_ethernet( std::span<const uint8_t> packet ) {
        return get_four_from_ethernet( packet.data() );
    }

    std::expected<four_tuple,std::string> get_four_from_ethernet( const unsigned char* packet ) {
        auto tcp_parse_result = get_parsed_tcp_header( packet );
        if ( !tcp_parse_result ) {
            return std::unexpected( "Failed to extract four from Ethernet: " + tcp_parse_result.error() );
        }
        auto ipv4_parse_result = get_parsed_ipv4_header( packet );
        if ( !ipv4_parse_result ) {
            return std::unexpected( "Failed to extract four from Ethernet: " + ipv4_parse_result.error() );
        }
        return four_tuple {
            .client_ip = ipv4_parse_result.value().source_ip_addr,      
            .server_ip = ipv4_parse_result.value().destination_ip_addr,
            .client_port = tcp_parse_result.value().src_port,
            .server_port = tcp_parse_result.value().dest_port
        };
    }

    // ==============================
    //         Get Four Tuples
    // ==============================

    std::unordered_set<four_tuple> get_four_tuples( const session& packets ) {
        std::unordered_set<four_tuple> four_tuples;
        for ( auto& packet : packets ) {
            auto four_result = get_four_from_ethernet( packet );
            if ( !four_result ) {
                continue;
            }
            auto flipped = flip_four( four_result.value() );
            if ( four_tuples.contains( four_result.value() ) || four_tuples.contains( flipped ) ) {
                continue;
            }
            four_tuples.insert( four_result.value() );
        }
        return four_tuples;
    }

    // ==============================
    //     Data Packet Predicates
    // ==============================

    std::expected<bool,std::string> is_data_packet( std::span<const uint8_t> packet ) {
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        auto ipv4_header_len_result = get_ipv4_header_len( packet );
        if ( !ipv4_header_len_result ) {
            return std::unexpected( ipv4_header_len_result.error() );
        }
        const std::size_t tcp_header_offset = ethernet_header_len + ipv4_header_len_result.value();
        auto tcp_header_len = get_tcp_header_len( packet.data(), tcp_header_offset );
        const std::size_t payload_len = packet.size() - tcp_header_offset - tcp_header_len;
        return payload_len > 0;
    }

    // ==============================
    //         Is ACK Only
    // ==============================

    bool is_ack_only_packet( const std::vector<uint8_t>& packet ) {
        return !is_data_packet( packet ) && is_ack( packet );
    }

    // ==============================
    //        Extract Payloads
    // ==============================

    std::vector<std::vector<uint8_t>> extract_payloads( const four_tuple& four, const std::vector<std::vector<uint8_t>>& packets ) {
        std::vector<std::vector<uint8_t>> payloads;
        for ( auto& packet : packets ) {
            auto four_result = get_four_from_ethernet( packet );
            if ( !four_result ) {
                continue;
            }
            if ( four_result.value() == four ) {
                auto payload_result = get_tcp_payload( packet );
                if ( !payload_result ) {
                    continue;
                }
                if ( payload_result.value().size() > 0 ) payloads.push_back( payload_result.value() );
            }
        }
        return payloads;
    } 

    // ==============================
    //         Split Payloads
    // ==============================

    std::expected<client_server_payloads,std::string> split_payloads( const session& packets ) {
        client_server_payloads payloads;
        auto handshake_opt = get_handshake( packets );
        if ( !handshake_opt ) { 
            std::unexpected( "No hanshake found" );
        }
        auto client_four = get_four_from_ethernet( handshake_opt->syn ).value();
        auto server_four = get_four_from_ethernet( handshake_opt->syn_ack ).value();
        payloads.client_payloads = extract_payloads( client_four, packets );
        payloads.server_payloads = extract_payloads( server_four, packets );
        return payloads;
    }

} // namespace ntk
