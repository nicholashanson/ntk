#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <cstddef>
#include <cstdint>

#include <map>
#include <vector>

namespace ntk {

    using tcp_stream = std::map<uint32_t,std::vector<uint8_t>>; 

    using session = std::vector<std::vector<uint8_t>>;

    namespace constants {

        // protocols
        constexpr std::size_t ethernet_header_len = 14;
        constexpr std::size_t udp_header_len = 8;

        // tls records
        constexpr std::size_t record_header_len = 5;
        constexpr std::size_t handshake_header_len = 4;

        // tls handshake messages
        constexpr std::size_t version_len = 2;
        constexpr std::size_t random_len = 32;
        constexpr std::size_t minimum_handshake_message_len = version_len + random_len + 1 /* session id length byte */; 

        // packet-capture
        constexpr std::size_t max_snap_len = 65535; 
    
    } // namespace constants

} // namespace ntk

#endif
