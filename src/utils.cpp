#include <utils.hpp>

namespace ntk {

    uint16_t read_uint16_be( const unsigned char* buffer, size_t offset ) {
        return ( buffer[ offset ] << 8 ) | buffer[ offset + 1 ];
    }

    uint32_t read_uint32_be( const unsigned char* buffer, size_t offset ) {
        return ( buffer[ offset ]     << 24 ) | ( buffer[ offset + 1 ] << 16 ) |
               ( buffer[ offset + 2 ] <<  8 ) |   buffer[ offset + 3 ];
    }

} // namespace ntk