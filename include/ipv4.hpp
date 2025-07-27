#ifndef IPV4_HPP
#define IPV4_HPP

#include <algorithm>

#include <array>
#include <map>
#include <string>
#include <vector>
#include <tuple>
#include <unordered_map>
#include <sstream>
#include <ranges>

#include <cstdint>
#include <cstring>

#include <optional>
#include <stdexcept>

#include <constants.hpp>
#include <utils.hpp>

namespace ntk {

    // ==============================
    //      IPV4 Header Offset
    // ==============================
    enum class ipv4_header_offset : uint8_t {
        IHL =          0,
        TOTAL_LEN    = 2,
        TIME_TO_LIVE = 8,
        PROTOCOL     = 9,
        CHECKSUM     = 10,
        SRC_IP_ADDR  = 12,
        DEST_IP_ADDR = 16
    };

    // ==============================
    //            Protocol
    // ==============================

    enum class protocol : uint8_t {
        TCP = 0x06,
        UDP = 0x11
    };

    // ==============================
    //          Port Numbers
    // ==============================

    enum class port_numbers : uint16_t {
        HTTP = 0x50,    // HTTP: 80
        HTTPS = 0x01bb  // HTTPS: 443
    };

    // ==============================
    //        Ethernet Header
    // ==============================

    struct ethernet_header {
        uint64_t src_mac_addr;
        uint64_t dest_mac_addr;
        uint16_t ethernet_type;
    };

    // ==============================
    //           IPV4 Header
    // ==============================

    struct ipv4_header {
        size_t ihl;
        uint16_t total_length;
        uint8_t time_to_live;
        uint8_t protocol;
        uint16_t header_checksum;
        uint32_t source_ip_addr;
        uint32_t destination_ip_addr;
    };

    // ==============================
    //         Sender-Reciever
    // ==============================

    using sender_reciever = std::pair<uint32_t,uint32_t>;

    // ==============================
    //      IPV4 Header Parsing
    // ==============================

    std::size_t get_ipv4_header_len( const unsigned char* ethernet_frame );

     std::size_t get_ipv4_header_len( const std::vector<uint8_t>& packet );

    std::vector<uint8_t> get_raw_ipv4_header( const unsigned char* ethernet_frame );

    ipv4_header get_parsed_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header );

    ipv4_header get_parsed_ipv4_header( const unsigned char* ethernet_frame );

    struct ipv4_filter {
        uint32_t ip_addr;

        bool operator()( const std::vector<uint8_t>& packet ) const {
            auto header = get_parsed_ipv4_header( packet );
            return ( header.source_ip_addr == ip_addr ) || ( header.destination_ip_addr == ip_addr );
        }
    };

    sender_reciever get_sender_reciever( const unsigned char* ethernet_frame );

    sender_reciever flip_sender_reciever( const sender_reciever& src_dest );

    inline decltype(auto) filter_by_ip( const session& packets, const sender_reciever& src_dest ) {
        return std::views::all( packets ) | std::views::filter( [ & ] ( const auto& packet ) {
            return get_sender_reciever( packet.data() ) == src_dest;
        });
    }

    inline decltype(auto) filter_by_ip_duplex( const session& packets, const sender_reciever& src_dest ) {
        auto dest_src = flip_sender_reciever( src_dest );
        return std::views::all( packets ) | std::views::filter( [ & ] ( const auto& packet ) {
            auto ip_pair = get_sender_reciever( packet.data() );
            return ip_pair == src_dest || ip_pair == dest_src;
        });
    }

    // ==============================
    //           Predicates
    // ==============================

    bool is_ipv4( const unsigned char* ethernet_frame );

    // ==============================
    //           Helpers
    // ==============================

    std::string ip_to_string( uint32_t ip );
    
} // namespace ntk

#endif
