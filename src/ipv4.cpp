
#include <ipv4.hpp>

namespace ntk {

    // ==============================
    //      Get IPV4 Header Len
    // ==============================

    std::size_t get_ipv4_header_len( const unsigned char* ethernet_frame ) {
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        constexpr std::size_t bytes_per_offset = 4;
        const uint8_t ihl = extract_low_nibble( ethernet_frame[ ethernet_header_len ] );
        return ihl * bytes_per_offset;
    }

    std::size_t get_ipv4_header_len( const std::vector<uint8_t>& packet ) {
        return get_ipv4_header_len( packet.data() );
    }

    // ==============================
    //     Get Raw IPV4 Header
    // ==============================

    std::vector<uint8_t> get_raw_ipv4_header( const unsigned char* ethernet_frame ) {
        constexpr std::size_t ethernet_header_len = constants::ethernet_header_len;
        std::vector<uint8_t> ipv4_header;
        auto ipv4_header_len = get_ipv4_header_len( ethernet_frame );
        ipv4_header.resize( ipv4_header_len );
        std::memcpy( ipv4_header.data(), ethernet_frame + ethernet_header_len, ipv4_header_len );
        return ipv4_header;  
    }

    // ==============================
    //     Get Parsed IPV4 Header
    // ==============================

    ipv4_header get_parsed_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header ) {
        ipv4_header header;
        header.ihl = get_ipv4_header_len( raw_ipv4_header );
        header.total_length = read_uint16_be( raw_ipv4_header, ipv4_header_offset::TOTAL_LEN );
        header.time_to_live = raw_ipv4_header[ static_cast<std::size_t>( ipv4_header_offset::TIME_TO_LIVE ) ];
        header.protocol = raw_ipv4_header[ static_cast<std::size_t>( ipv4_header_offset::PROTOCOL ) ];
        header.header_checksum = read_uint16_be( raw_ipv4_header, ipv4_header_offset::CHECKSUM );
        header.source_ip_addr = read_uint32_be( raw_ipv4_header, ipv4_header_offset::SRC_IP_ADDR );;
        header.destination_ip_addr = read_uint32_be( raw_ipv4_header, ipv4_header_offset::DEST_IP_ADDR );;
        return header;
    }

    ipv4_header get_parsed_ipv4_header( const unsigned char* ethernet_frame ) {
        return get_parsed_ipv4_header( get_raw_ipv4_header( ethernet_frame ) );
    }

    // ==============================
    //    Get IPV4 Sender-Reciever
    // ==============================

    sender_reciever get_sender_reciever( const unsigned char* ethernet_frame ) {
        auto header = get_parsed_ipv4_header( get_raw_ipv4_header( ethernet_frame ) );
        return std::make_pair( header.source_ip_addr, header.destination_ip_addr );
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
