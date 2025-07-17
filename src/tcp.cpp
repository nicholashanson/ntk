#include <tcp.hpp>

namespace ntk {

    tcp_termination& tcp_termination::operator=( const maybe_termination& maybe ) {
        closing_sequence = fin_ack_fin_ack{ *maybe.initiator_fin, *maybe.responder_ack, *maybe.responder_fin, *maybe.initiator_ack };
        return *this;
    }

    void maybe_termination::feed( const std::vector<uint8_t>& packet ) {
        auto packet_tcp_header = get_tcp_header( packet.data() );

        if ( !initiator_fin && is_fin_ack( packet ) ) {
            initiator_fin = packet;
            return;
        }

        if ( !responder_fin && is_fin_ack( packet ) ) {
            responder_fin = packet;
            if ( is_ack_of_seq( *initiator_fin, packet ) ) {
                responder_ack = packet;
            }
            return;
        }

        if ( initiator_fin && !responder_ack ) {
            if ( is_ack( packet ) && is_ack_of_seq( *initiator_fin, packet ) ) {
                responder_ack = packet;
                return;
            }
        }

        if ( responder_fin && !initiator_ack && is_ack( packet ) ) {
            if ( is_ack_of_seq( *responder_fin, packet ) ) {
                initiator_ack = packet;
                return;
            }
        }
    }

    maybe_termination::operator bool() const {
        return initiator_fin && responder_ack && responder_fin && initiator_ack;
    }

    uint32_t get_seq_number( const std::vector<uint8_t>& packet ) {
        auto raw_tcp_header = get_raw_tcp_header( packet );
        return read_uint32_be( raw_tcp_header, tcp_header_offset::SEQ_NUMBER ); 
    }

    uint32_t get_ack_number( const std::vector<uint8_t>& packet ) {
        auto raw_tcp_header = get_raw_tcp_header( packet );
        return read_uint32_be( raw_tcp_header, tcp_header_offset::ACK_NUMBER );
    }

    // ==============================
    //      Get TCP Header Len
    // ==============================

    std::size_t get_tcp_header_len( const unsigned char* ethernet_frame, const std::size_t tcp_header_offset ) {  
        constexpr std::size_t bytes_per_offset = 4;
        const std::size_t data_offset_pos = tcp_header_offset + static_cast<std::size_t>( tcp_header_offset::DATA_OFFSET );
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

    std::vector<uint8_t> get_raw_tcp_header( const unsigned char* ethernet_frame ) {
        auto ipv4_header_len = get_ipv4_header_len( ethernet_frame );
        return get_raw_tcp_header( ethernet_frame, ipv4_header_len );
    }

    std::vector<uint8_t> get_raw_tcp_header( const std::vector<uint8_t>& packet ) {
        return get_raw_tcp_header( packet.data() );
    }

    // ==============================
    //        Get TCP Payload
    // ==============================

    std::vector<uint8_t> get_tcp_payload( const unsigned char* ethernet_frame ) { 
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        
        const auto ipv4_header_len = get_ipv4_header_len( ethernet_frame ); 
        const uint16_t total_length = read_uint16_be( ethernet_frame, ethernet_header_len + 2 );
        const std::size_t tcp_header_offset = ethernet_header_len + ipv4_header_len;
        const std::size_t tcp_header_len = get_tcp_header_len( ethernet_frame, tcp_header_offset );
        
        size_t payload_len = total_length - ipv4_header_len - tcp_header_len;
        const uint8_t* payload_ptr = ethernet_frame + tcp_header_offset + tcp_header_len;

        std::vector<uint8_t> payload( payload_len );
        std::memcpy( payload.data(), payload_ptr, payload_len );

        return payload;
    }

    // ==============================
    //      Extract TCP Option
    // ==============================

    std::optional<tcp_option> extract_tcp_option( std::span<const uint8_t>& tcp_options_list ) {
        constexpr std::size_t option_data_offset = 2;
        option_type kind = static_cast<option_type>( tcp_options_list[ 0 ] );
    
        if ( kind == option_type::END_OF_OPTIONS_LIST ) {
            tcp_options_list = tcp_options_list.subspan( 1 );
            return std::nullopt;
        } else if ( kind == option_type::NOP ) {
            tcp_options_list = tcp_options_list.subspan( 1 );
            return tcp_option { kind, {} };
        } else {
            uint8_t length = tcp_options_list[ 1 ];
            std::vector<uint8_t> data;
            if ( length > option_data_offset ) {
                data.insert( data.end(), 
                             tcp_options_list.begin() + option_data_offset,
                             tcp_options_list.begin() + length );
            }
            tcp_options_list = tcp_options_list.subspan( length ); 
            return tcp_option { kind, data };
        }
    }  

    // ==============================
    //     Get Parsed TCP Header
    // ==============================

    tcp_header get_parsed_tcp_header( std::span<const uint8_t> raw_tcp_header ) {
        constexpr std::size_t basic_header_len = 20;

        if ( raw_tcp_header.size() < basic_header_len ) {
            throw std::runtime_error( "Invalid TCP header size" );
        }

        tcp_header header;

        header.src_port = read_uint16_be( raw_tcp_header, tcp_header_offset::SRC_PORT ); 
        header.dest_port = read_uint16_be( raw_tcp_header, tcp_header_offset::DEST_PORT );  
        header.seq_number = read_uint32_be( raw_tcp_header, tcp_header_offset::SEQ_NUMBER ); 
        header.ack_number = read_uint32_be( raw_tcp_header, tcp_header_offset::ACK_NUMBER );
        header.data_offset = extract_high_nibble( raw_tcp_header[ static_cast<size_t>( tcp_header_offset::DATA_OFFSET ) ] );  
        header.flags = raw_tcp_header[ static_cast<size_t>( tcp_header_offset::FLAGS ) ];
        header.window_size = read_uint16_be( raw_tcp_header, tcp_header_offset::WINDOW_SIZE ); 
        header.checksum = read_uint16_be( raw_tcp_header, tcp_header_offset::CHECKSUM ); 
        header.urgent_ptr = read_uint16_be( raw_tcp_header, tcp_header_offset::URGENT_PTR );

        if ( header.data_offset == 5 ) // header doesn't have options
            return header;

        raw_tcp_header = raw_tcp_header.subspan( basic_header_len );

        while ( !raw_tcp_header.empty() ) {
            if ( auto opt = extract_tcp_option( raw_tcp_header ) ) {
                header.options.push_back( *opt );
            }
        }

        return header;
    }

    tcp_header get_parsed_tcp_header( const unsigned char* ethernet_frame ) {
        ipv4_header header = get_ipv4_header( ethernet_frame );
        return parse_tcp_header( extract_tcp_header( ethernet_frame, header.ihl ) );
    }

    tcp_header get_parsed_tcp_header( const std::vector<uint8_t>& packet ) {
        return get_tcp_header( packet.data() );
    }

    // ==============================
    //      Get Raw TCP Stream
    // ==============================

    std::vector<raw_tcp_frame> get_raw_tcp_stream( const session& tcp_session ) {
        std::vector<raw_tcp_frame> tcp_stream;

        for ( auto& packet : tcp_session ) {
            auto header = extract_raw_tcp_header( packet_data );
            auto body = extract_tcp_payload( packet_data );

            if ( body.empty() ) {
                continue;
            }

            raw_tcp_frame frame = {
                .header = header,
                .body = body
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
            auto parsed_tcp_header = parse_tcp_header( tcp_frame.header );
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
        auto raw_stream = extract_raw_tcp_stream( packet_data );
        auto tcp_stream = get_tcp_stream( raw_stream );
        auto merged_tcp_stream = merge_tcp_stream_non_overlapping( tcp_stream );
        return merged_tcp_stream;
    }

    // ==============================
    //         TCP Predicates
    // ==============================

    bool is_tcp( const unsigned char* packet ) {
        auto header = get_ipv4_header( packet );
        return static_cast<protocol>( header.protocol ) == protocol::TCP;
    }

    bool is_tcp_v( const std::vector<uint8_t>& packet ) {
        return is_tcp( packet.data() );
    }

    bool have_same_sequence_number( const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs ) {
        return get_seq_number( lhs ) == get_seq_number( rhs );
    }

    // ==============================
    //     Is Same TCP Connection
    // ==============================

    bool is_same_connection( const ipv4_header& packet_ip_header, const tcp_header& packet_tcp_header, const four_tuple& four )  { 
        bool ip_match = ( packet_ip_header.source_ip_addr == four.client_ip || packet_ip_header.destination_ip_addr == four.client_ip ) &&
                        ( packet_ip_header.source_ip_addr == four.server_ip || packet_ip_header.destination_ip_addr == four.server_ip );
        bool port_match = ( packet_tcp_header.src_port == four.client_port || packet_tcp_header.dest_port == four.client_port ) &&
                          ( packet_tcp_header.src_port == four.server_port || packet_tcp_header.dest_port == four.server_port );
        return ip_match && port_match;
    }

    bool is_same_connection( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        tcp_header packet_tcp_header = get_parsed_tcp_header( packet );
        ipv4_header packet_ip_header = get_parsed_ipv4_header( packet );
        return is_same_connection( packet_ip_header, packet_tcp_header, four );
    }

    // ==============================
    //        SYN Predicates
    // ==============================

    bool is_syn( const tcp_header& packet_tcp_header ) {
        return flags_contains( packet_tcp_header.flags, tcp_flags::SYN ) && 
               !flags_contains( packet_tcp_header.flags, tcp_flags::ACK );
    }

    bool is_syn( const std::vector<uint8_t>& packet ) {
        tcp_header header = get_tcp_header( packet.data() );
        return is_syn( header );
    }

    // ==============================
    //        ACK Predicates
    // ==============================

    bool is_ack( const tcp_header& packet_tcp_header ) {
        return flags_contains( packet_tcp_header.flags, tcp_flags::ACK );
    }

    bool is_ack( const std::vector<uint8_t>& packet ) {
        tcp_header header = get_tcp_header( packet.data() );
        return is_ack( header );
    }

    // ==============================
    //       SYNACK Predicates
    // ==============================

    bool is_syn_ack( const tcp_header& packet_tcp_header ) {
        return flags_contains( packet_tcp_header.flags, tcp_flags::SYN ) && 
               flags_contains( packet_tcp_header.flags, tcp_flags::ACK );
    }

    bool is_syn_ack( const std::vector<uint8_t>& packet ) {
        tcp_header header = get_tcp_header( packet.data() );
        return is_syn_ack( header );
    }

    // ==============================
    //          Is SYN Of
    // ==============================

    bool is_syn_of( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        ipv4_header packet_ip_header = get_ipv4_header( packet.data() );
        return is_syn( packet_tcp_header ) && is_same_connection( packet_ip_header, packet_tcp_header, four );
    }

    // ==============================
    //         Is SYNACK Of
    // ==============================

    bool is_syn_ack_of( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        ipv4_header packet_ip_header = get_ipv4_header( packet.data() );
        return is_syn_ack( packet_tcp_header ) && is_same_connection( packet_ip_header, packet_tcp_header, four );
    }

    // ==============================
    //           Is ACK Of
    // ==============================

    bool is_ack_of( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        ipv4_header packet_ip_header = get_ipv4_header( packet.data() );
        return is_ack( packet_tcp_header ) && is_same_connection( packet_ip_header, packet_tcp_header, four );
    }

    // ==============================
    //         Is Ack Of Seq
    // ==============================

    bool is_ack_of_seq( const std::vector<uint8_t>& data_sender_packet, const std::vector<uint8_t>& data_reciever_packet ) {
        auto seq_number = get_seq_number( data_sender_packet );
        auto ack_number = get_ack_number( data_reciever_packet );
        return is_ack_of_seq( ack_number, seq_number );
    }

    bool is_ack_of_seq( const tcp_header& data_sender_header, const tcp_header& data_reciever_header ) {
        return is_ack_of_seq( data_sender_header.seq_number, data_reciever_header.ack_number );
    }

    bool is_ack_of_seq( const uint32_t seq_number, const uint32_t ack_number ) {
        return ack_number == seq_number + 1;
    }

    // ==============================
    //           Is FYNACK
    // ==============================

    bool is_fin_ack( const std::vector<uint8_t>& packet ) {
        auto packet_tcp_header = ntk::get_tcp_header( packet.data() );
        return flags_contains( packet_tcp_header.flags, ntk::tcp_flags::FIN_ACK );
    };

    // ==============================
    //         Flags Contains
    // ==============================

    bool flags_contains( const uint8_t header_flags, const tcp_flags flags ) {
        return ( header_flags & static_cast<uint8_t>( flags ) ) == static_cast<uint8_t>( flags );
    }

    // ==============================
    //        RESET Predicates
    // ==============================

    bool is_reset( const std::vector<uint8_t>& packet ) {
        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        return flags_contains( packet_tcp_header.flags, tcp_flags::RST );
    }

    // ==============================
    //         TCP Handshake
    // ==============================

    std::optional<tcp_handshake> get_handshake( const four_tuple& four, const session& packets ) {
        auto connection_packets = std::views::filter( packets, [&]( const auto& packet ) {
            return is_same_connection( packet, four );
        });
        return get_handshake( connection_packets ); 
    }

    std::optional<tcp_handshake> get_handshake( const session& packets ) {
        tcp_handshake handshake;
        for ( auto&& [ syn, synack, ack ] : std::views::slide( packets, 3 ) ) {
            if ( is_valid_handshake( syn, synack, ack ) ) {
                return tcp_handshake{ syn, synack, ack };
            }
        }
        return std::nullopt; 
    }

    std::vector<tcp_handshake> get_handshakes( const four_tuple& four, const session& packets ) {
        auto connection_packets = std::views::filter( packets, [&]( const auto& packet ) {
            return is_same_connection( packet, four );
        });
        return get_handshake( connection_packets ); 
    }
        
    std::vector<tcp_handshake> get_handshakes( const session& packets ) {        
        std::vector<tcp_handshake> handshakes;
        for ( auto&& [ syn, synack, ack ] : std::views::slide( packets, 3 ) ) {
            if ( is_valid_handshake( syn, synack, ack ) ) {
                handshakes.emplace_back( syn, synack, ack );
            }
        }
        return handshakes; 
    }

    const std::vector<uint8_t>* get_end_of_handshake( const session& packets, const tcp_handshake& handshake ) {   
        for ( auto&& [ maybe_syn, maybe_synack, maybe_ack ] : std::views::slide( packets, 3 ) ) {
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
        return is_ack_of_seq( syn, syn_ack ) && is_ack_of_seq( synack, ack );
    }

    // ==============================
    //     TCP Handshake Feed
    // ==============================

    bool tcp_handshake_feed::feed_packet( const std::vector<uint8_t>& packet ) {
        auto packet_tcp_header = get_tcp_header( packet.data() );

        if ( is_syn( packet ) ) {
            reset();
            m_syn = packet;
            return true;
        }

        if ( m_syn && !m_syn_ack && is_syn_ack( packet ) &&
             packet_tcp_header.ack_number == get_tcp_header( m_syn.value().data() ).seq_number + 1 ) {
            m_syn_ack = packet;
            return true;
        }

        if ( m_syn_ack && is_ack( packet ) &&
             packet_tcp_header.ack_number == get_tcp_header( m_syn_ack.value().data() ).seq_number + 1 )  {
            m_ack = packet;
            return true;
        }

        return false;
    }

    bool tcp_handshake_feed::feed( const std::vector<uint8_t>& packet ) { 
        bool accepted = feed_packet( packet );
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
                return tcp_termination {
                    .closing_sequence = packet
                };
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

        std::optional<std::vector<uint8_t>> fin_1;
        std::optional<std::vector<uint8_t>> ack_1; 
        std::optional<std::vector<uint8_t>> fin_2; 
        std::optional<std::vector<uint8_t>> ack_2;

        uint32_t fin_1_seq_number = std::numeric_limits<uint32_t>::max();
        uint32_t fin_2_seq_number = std::numeric_limits<uint32_t>::max();

        auto is_fin_ack = [&]( const auto& packet_tcp_header ) {
            return ( packet_tcp_header.flags & static_cast<uint8_t>( tcp_flags::FIN_ACK ) ) == static_cast<uint8_t>( tcp_flags::FIN_ACK );
        };

        auto is_ack_of_fin_ack = [&]( const auto& tcp_header, uint32_t fin_ack_seq_number ) {
            return tcp_header.ack_number == fin_ack_seq_number + 1;
        };

        for ( const auto& packet : connection_packets ) {
    
            auto packet_tcp_header = get_tcp_header( packet.data() );

            if ( !fin_1 && is_fin_ack( packet_tcp_header ) ) {
                fin_1 = packet;
                fin_1_seq_number = packet_tcp_header.seq_number;
            } else if ( !fin_2 && is_fin_ack( packet_tcp_header ) ) {
                if ( packet_tcp_header.seq_number == fin_1_seq_number ) continue;
                fin_2 = packet;
                fin_2_seq_number = packet_tcp_header.seq_number;
            } else if ( fin_1 && !ack_1 && is_ack( packet_tcp_header ) && is_ack_of_fin_ack( packet_tcp_header, fin_1_seq_number ) ) {
                ack_1 = packet;
            } else if ( fin_2 && !ack_2 && is_ack( packet_tcp_header ) && is_ack_of_fin_ack( packet_tcp_header, fin_2_seq_number ) ) {
                ack_2 = packet;
            }

            if ( fin_1 && ack_1 && fin_2 && ack_2 ) {
                terminations.push_back( tcp_termination {
                    .closing_sequence = fin_ack_fin_ack{ *fin_1, *ack_1, *fin_2, *ack_2 }
                } );
                fin_1 = ack_1 = fin_2 = ack_2 = std::nullopt;
                fin_1_seq_number = fin_2_seq_number = std::numeric_limits<uint32_t>::max();
            }
        }

        for ( const auto& packet : connection_packets ) {
            if ( is_reset( packet ) ) { 
                terminations.push_back( tcp_termination {
                    .closing_sequence = packet
                } );
            }
        }

        return terminations;
    }

    // ==============================
    //  Get Start of TCP Termination
    // ==============================

    const std::vector<uint8_t>* get_start_of_termination( const session& packets, const tcp_termination& termination ) {
        if ( std::holds_alternative<fin_ack_fin_ack>( termination.closing_sequence ) ) {
            const fin_ack_fin_ack& seq = std::get<fin_ack_fin_ack>( termination.closing_sequence );        
            for ( auto& packet : packets ) {
                if ( have_same_sequence_number( packet, seq.initiator_fin ) ) {
                    return &packet;
                }
            }   
        } else if ( std::holds_alternative<rst>( termination.closing_sequence ) ) {
            const rst& reset = std::get<rst>( termination.closing_sequence );
            for ( auto& packet : packets ) {
                if ( have_same_sequence_number( packet, reset ) ) {
                    return &packet;
                }
            }   
        } else {
            return nullptr;
        }
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

    bool tcp_termination_feed::feed( const std::vector<uint8_t>& packet ) {
        bool accepted = feed_packet( packet );
        if ( !accepted ) return false;
        
        if ( m_fin_1 && m_ack_1 && m_fin_2 && m_ack_2 ) {
            m_termination.closing_sequence = fin_ack_fin_ack{ *m_fin_1, *m_ack_1, *m_fin_2, *m_ack_2 };
            m_complete = true;
        }

        return true;
    }

    bool tcp_termination_feed::feed_packet( const std::vector<uint8_t>& packet ) {

        auto packet_tcp_header = get_tcp_header( packet.data() );

        if ( !m_fin_1 && is_fin_ack( packet ) ) {
            m_fin_1 = packet;
            m_fin_1_seq_number = packet_tcp_header.seq_number;
            return true;
        }

        if ( !m_fin_2 && is_fin_ack( packet ) ) {
            if ( packet_tcp_header.seq_number == m_fin_1_seq_number ) return false;
            m_fin_2 = packet;
            m_fin_2_seq_number = packet_tcp_header.seq_number;
            
            if ( packet_tcp_header.ack_number == m_fin_1_seq_number + 1 ) {
                m_ack_1 = packet;
            }
            return true;
        }

        if ( m_fin_1 && !m_ack_1 ) {
            if ( is_ack( packet_tcp_header ) &&
                 packet_tcp_header.ack_number == m_fin_1_seq_number + 1 ) {
                m_ack_1 = packet;
                return true;
            }
        }

        if ( m_fin_2 && !m_ack_2 && is_ack( packet_tcp_header ) ) {
            if ( packet_tcp_header.ack_number == m_fin_2_seq_number + 1 ) {
                m_ack_2 = packet;
                return true;
            }
        }

        return false;
    }

    // ==============================
    //            Classes
    // ==============================
    
    tcp_transfer::tcp_transfer( const four_tuple& four ) 
            : m_four( four ) {} 

    void tcp_transfer::load( const session& packet_data ) {

        tcp_handshake handshake = get_handshake( m_four, packet_data );
        tcp_termination termination = *get_termination( m_four, packet_data );

        m_handshake = handshake;
        m_termination = termination;

        split_stream( packet_data );
    }

    void tcp_transfer::split_stream( const session& packet_data ) {

        auto syn_header = get_tcp_header( m_handshake.syn.data() );
        auto syn_ack_header = get_tcp_header( m_handshake.syn_ack.data() );

        auto handshake_ack_ptr = get_end_of_handshake( packet_data, m_four, m_handshake );
        handshake_ack_ptr++;

        auto termination_ptr = get_start_of_termination( packet_data, m_four, m_termination );

        auto size = static_cast<size_t>( termination_ptr - handshake_ack_ptr );

        auto packet_span = std::span{ handshake_ack_ptr, size };

        for ( auto& packet : packet_span ) {
            if ( is_data_packet( packet ) && get_four_from_ethernet( packet ) == m_four ) {
                m_client_traffic.push_back( packet );
                continue;
            }
            if ( is_data_packet( packet ) && get_four_from_ethernet( packet ) == flip_four( m_four ) ) {
                m_server_traffic.push_back( packet );
                continue;
            }
            if ( is_ack( packet ) && get_four_from_ethernet( packet ) == m_four ) {
                m_client_acks.push_back( packet );
                continue;
            }
            if ( is_ack( packet ) && get_four_from_ethernet( packet ) == flip_four( m_four ) ) {
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

    bool tcp_live_stream::feed( const std::vector<uint8_t>& packet ) {

        if ( is_complete() ) return false;
        if ( !is_same_connection( packet, m_four ) ) return false;

        bool handshake_packet = false;
        bool termination_packet = false;
        
        if ( !m_handshake_feed.m_complete ) handshake_packet = m_handshake_feed.feed( packet );
        if ( handshake_packet ) return true;

        if ( !m_termination_feed.m_complete ) termination_packet = m_termination_feed.feed( packet );
        if ( termination_packet ) return true;

        m_traffic.push_back( packet );

        return true;
    }

        const four_tuple& tcp_live_stream::get_four_tuple() const {
        return m_four;
    }

    tcp_live_stream_session::tcp_live_stream_session() 
        : m_offload_queue( nullptr ) {}

    tcp_live_stream_session::tcp_live_stream_session( transfer_queue_interface<tcp_live_stream>* offload_queue )
        : m_offload_queue( offload_queue ) {}

    void tcp_live_stream_session::feed( const std::vector<uint8_t>& packet ) {
        auto packet_four = get_four_from_ethernet( packet );

        if ( !m_four_tuples.contains( packet_four ) && !m_four_tuples.contains( flip_four( packet_four ) ) ) {
            m_four_tuples.insert( packet_four );
            m_live_streams.emplace_back( tcp_live_stream{ packet_four } );
        } 

        if ( !m_offload_queue ) {
            for ( auto& stream : m_live_streams ) {
                bool accepted = stream.feed( packet );
                if ( accepted ) return;
            }
        }

        std::vector<tcp_live_stream> updated_streams;

        for ( auto& stream : m_live_streams ) {
            bool accepted = stream.feed( packet );
            if ( accepted ) {
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
    //         Helper Classes
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

    // tcp live stream

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
    //          Four Tuple 
    // ==============================

    four_tuple flip_four( const four_tuple& four ) {
        four_tuple flipped;

        flipped.client_ip = four.server_ip;
        flipped.server_ip = four.client_ip;
        flipped.server_port = four.client_port;
        flipped.client_port = four.server_port;

        return flipped;
    }

    four_tuple get_four_from_ethernet( const std::vector<uint8_t>& packet ) {
        return get_four_from_ethernet( packet.data() );
    }

    four_tuple get_four_from_ethernet( const unsigned char* packet ) {
        tcp_header packet_tcp_header = get_tcp_header( packet );
        ipv4_header packet_ip_header = get_ipv4_header( packet );

        return four_tuple {
            .client_ip = packet_ip_header.source_ip_addr,      
            .server_ip = packet_ip_header.destination_ip_addr,
            .client_port = packet_tcp_header.src_port,
            .server_port = packet_tcp_header.dest_port
        };
    }

    std::unordered_set<four_tuple> get_four_tuples( const session& packets ) {
        std::unordered_set<four_tuple> four_tuples;

        for ( auto& packet : packets ) {
            auto four = get_four_from_ethernet( packet );
            auto flipped = flip_four( four );
            if ( four_tuples.contains( four ) || four_tuples.contains( flipped ) ) {
                continue;
            }
            four_tuples.insert( four );
        }
        
        return four_tuples;
    }

    // ==============================
    //     Data Packet Predicates
    // ==============================

    bool is_data_packet( const std::vector<uint8_t>& packet ) {
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        
        auto ipv4_header_len = get_ipv_header_len( packet );
        const std::size_t tcp_header_offset = ethernet_header_len + ipv4_header_len;
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

    std::vector<std::vector<uint8_t>> extract_payloads( const four_tuple& four, const std::vector<std::vector<uint8_t>>& packets ) {
        std::vector<std::vector<uint8_t>> payloads;
        for ( auto& packet : packets ) {
            if ( get_four_from_ethernet( packet ) == four ) {
                auto payload = extract_tcp_payload( packet );
                if ( payload.size() > 0 ) payloads.push_back( payload );
            }
        }
        return payloads;
    } 

    std::expected<client_server_payloads,std::string> split_payloads( const session& packets ) {
        client_server_payloads payloads;

        auto handshake = get_handshake( packets );
        if ( handshake.empty() ) return std::unexpected( "No hanshake found" );

        auto client_four = get_four_from_ethernet( handshake.syn );
        auto server_four = get_four_from_ethernet( handshake.syn_ack );

        payloads.client_payloads = extract_payloads( client_four, packets );
        payloads.server_payloads = extract_payloads( server_four, packets );

        return payloads;
    }

} // namespace ntk
