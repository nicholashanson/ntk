#include <utils.hpp>

namespace ntk {

    uint16_t read_uint16_be( const unsigned char* buffer, std::size_t offset ) {
        return ( buffer[ offset ] << 8 ) | buffer[ offset + 1 ];
    }

    uint16_t read_uint16_be( std::initializer_list<const char> bytes ) {
        auto it = bytes.begin();
        return ( *it << 8 ) | *( it + 1 );
    }

    uint32_t read_uint32_be( const unsigned char* buffer, std::size_t offset ) {
        return ( buffer[ offset ]     << 24 ) | ( buffer[ offset + 1 ] << 16 ) |
               ( buffer[ offset + 2 ] <<  8 ) |   buffer[ offset + 3 ];
    }

    std::string bytes_to_hex_string( std::span<const uint8_t> bytes ) {
        std::ostringstream oss;
        for ( auto byte : bytes) {
            oss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << ( int )byte;
        }
        return oss.str();
    }

} // namespace ntk