#include <utils.hpp>

namespace ntk {

    uint16_t read_uint16_be( const unsigned char* buffer, size_t offset ) {
        return ( buffer[ offset ] << 8 ) | buffer[ offset + 1 ];
    }

    uint16_t read_uint16_be( const std::vector<uint8_t>& buffer, size_t offset ) {
        return read_uint16_be( buffer.data(), offset );
    }

    uint32_t read_uint32_be( const unsigned char* buffer, size_t offset ) {
        return ( buffer[ offset ]     << 24 ) | ( buffer[ offset + 1 ] << 16 ) |
               ( buffer[ offset + 2 ] <<  8 ) |   buffer[ offset + 3 ];
    }

    uint32_t read_uint32_be( const std::vector<uint8_t>& buffer, size_t offset ) {
        return read_uint32_be( buffer.data(), offset );
    }

} // namespace ntk