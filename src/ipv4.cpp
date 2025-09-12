
#include <ipv4.hpp>

namespace ntk {

    // ==============================
    //      Get IPV4 Header Len
    // ==============================

    std::expected<std::size_t,std::string> get_ipv4_header_len_from_ethernet( const unsigned char* ethernet_frame ) {
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        return get_ipv4_header_len_from_ihl( ethernet_frame[ ethernet_header_len ] );
    }

    std::expected<std::size_t,std::string> get_ipv4_header_len_from_ethernet( const std::span<const uint8_t> packet ) {
        return get_ipv4_header_len_from_ethernet( packet.data() );
    }

    std::expected<std::size_t,std::string> get_ipv4_header_len_from_ihl( const uint8_t ihl_byte ) {
        constexpr std::size_t bytes_per_offset = 4;
        const uint8_t ihl = extract_low_nibble( ihl_byte );
        const std::size_t header_length = ihl * bytes_per_offset;
        if ( header_length < 20 ) {
            return std::unexpected( "IHL is too small for an IPV4 Header: " + std::to_string( header_length ) );
        }
        if ( header_length > 60 ) {
            return std::unexpected( "IHL is too big for an IPV4 Header: " + std::to_string( header_length ) );
        }
        return header_length;
    }

    // ==============================
    //     Get Raw IPV4 Header
    // ==============================

    std::expected<std::vector<uint8_t>,std::string> get_raw_ipv4_header( const unsigned char* ethernet_frame ) {
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        std::vector<uint8_t> ipv4_header;
        auto header_len_result = get_ipv4_header_len_from_ethernet( ethernet_frame );
        if ( !header_len_result ) {
            return std::unexpected( header_len_result.error() );
        }
        ipv4_header.resize( header_len_result.value() );
        std::memcpy( ipv4_header.data(), ethernet_frame + ethernet_header_len, header_len_result.value() );
        return ipv4_header;  
    }

    // ==============================
    //     Get Parsed IPV4 Header
    // ==============================

    std::expected<ipv4_header,std::string> get_parsed_ipv4_header( const std::span<const uint8_t> raw_ipv4_header ) {
        if ( raw_ipv4_header.size() < 20 ) {
            return std::unexpected( "Buffer is too short for an IPV4 Header" );
        }
        ipv4_header header;
        auto ihl_result = get_ipv4_header_len_from_ihl( raw_ipv4_header[ static_cast<std::size_t>( ipv4_header_offset::IHL ) ] ); 
        if ( !ihl_result ) {
            return std::unexpected( ihl_result.error() );
        }
        header.ihl = ihl_result.value();
        header.total_length = read_uint16_be( raw_ipv4_header, ipv4_header_offset::TOTAL_LEN );
        header.time_to_live = raw_ipv4_header[ static_cast<std::size_t>( ipv4_header_offset::TIME_TO_LIVE ) ];
        header.protocol = raw_ipv4_header[ static_cast<std::size_t>( ipv4_header_offset::PROTOCOL ) ];
        header.header_checksum = read_uint16_be( raw_ipv4_header, ipv4_header_offset::CHECKSUM );
        header.source_ip_addr = read_uint32_be( raw_ipv4_header, ipv4_header_offset::SRC_IP_ADDR );;
        header.destination_ip_addr = read_uint32_be( raw_ipv4_header, ipv4_header_offset::DEST_IP_ADDR );;

        if ( header.ihl == 20 /* header length of header with no options */ ) {
            return header;
        }

        return header;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<ipv4_header,std::string> get_parsed_ipv4_header_from_ethernet( const unsigned char* ethernet_frame ) {
        auto result = get_raw_ipv4_header( ethernet_frame );
        if ( !result ) {
            return std::unexpected( result.error() );
        }
        return get_parsed_ipv4_header( result.value() );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<ipv4_header,std::string> get_parsed_ipv4_header_from_ethernet( std::span<const uint8_t> packet ) {
        return get_parsed_ipv4_header_from_ethernet( packet.data() );
    }

    // ==============================
    //    Get IPV4 Sender-Reciever
    // ==============================

    std::expected<sender_reciever,std::string> get_sender_reciever( const unsigned char* ethernet_frame ) {
        auto result = get_raw_ipv4_header( ethernet_frame );
        if ( !result ) {
            return std::unexpected( result.error() );
        }
        auto parsed_header = get_parsed_ipv4_header( result.value() ).value();
        return std::make_pair( parsed_header.source_ip_addr, parsed_header.destination_ip_addr );
    }

    // ==============================
    //    Flip IPV4 Sender-Reciever
    // ==============================

    sender_reciever flip_sender_reciever( const sender_reciever& src_dest ) {
        sender_reciever dest_src;
        dest_src.first = src_dest.second;
        dest_src.second = src_dest.first;
        return dest_src;
    }

    // ==============================
    //         IP To String
    // ==============================

    std::string ip_to_string( uint32_t ip ) {
        auto extract_octet = []( uint32_t ip, int shift ) {
            return ( ip >> shift ) & 0xff;
        };
        return std::format( "{}.{}.{}.{}",
            extract_octet( ip, 24 ),
            extract_octet( ip, 16 ),
            extract_octet( ip, 8 ),
            extract_octet( ip, 0 )
        );
    }

} // namespace ntk
