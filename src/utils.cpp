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

    // ================
    //  Output to File
    // ================

    void output_to_file( const std::string& content, const std::string& filename ) {
        std::ofstream out( filename );
        if ( !out ) {
            throw std::runtime_error( "Failed to open file for writing: " + filename );
        }
        out.write( content.data(), content.size() );
        out.close();
    }

    // =================
    //  Hex Char to Int
    // =================

    std::expected<uint8_t,std::string> hex_char_to_int( char c ) {
        if ( c >= '0' && c <= '9') return c - '0';
        if ( c >= 'a' && c <= 'f') return c - 'a' + 10;
        if ( c >= 'A' && c <= 'F') return c - 'A' + 10;
        return std::unexpected( "Invalid Hex Character" );
    }

    // =====================
    //  Hex String to Bytes
    // =====================

    std::expected<std::vector<uint8_t>,std::string> hex_string_to_bytes( const std::string& hex ) {
        if ( hex.size() % 2 != 0 ) {
            return std::unexpected( "Hex String must have even Length" );
        }
        std::vector<uint8_t> bytes;
        bytes.reserve( hex.size() / 2 );
        for ( std::size_t i = 0; i < hex.size(); i += 2 ) {
            auto high_result = hex_char_to_int( hex[ i ] );
            if ( !high_result ) {
                return std::unexpected( high_result.error() );
            }
            auto& high = high_result.value();
            auto low_result  = hex_char_to_int( hex[ i + 1 ] );
            if ( !low_result ) {
                return std::unexpected( low_result.error() );
            }
            auto& low = low_result.value();
            bytes.push_back( ( high << 4 ) | low );
        }
        return bytes;
    }

    // =================
    //  To Uint24 Bytes
    // =================

    std::array<uint8_t,3> to_uint24_bytes( uint32_t value ) {
        if ( value > 0xffffff ) { 
            throw std::runtime_error( "Value too large for 3 bytes" );
        }
        return { 
            static_cast<uint8_t>( ( value >> 16 ) & 0xff ),
            static_cast<uint8_t>( ( value >>  8 ) & 0xff ),
            static_cast<uint8_t>(   value &         0xff )
        };
    }

    // ================
    //  Read From File
    // ================

    std::expected<std::vector<uint8_t>,std::string> read_from_file( const std::string& path ) {
        std::ifstream file( path, std::ios::binary | std::ios::ate );
        if ( !file ) {
            return std::unexpected( "Failed to open file: " + path );
        }
        std::streamsize size = file.tellg();
        if ( size < 0 ) {
            return std::unexpected( "Failed to get file size: " + path );
        }
        file.seekg( 0, std::ios::beg );

        std::vector<uint8_t> buffer( static_cast<std::size_t>( size ) );
        if (!file.read( reinterpret_cast<char*>( buffer.data() ), size ) ) {
            return std::unexpected( "Failed to read file: " + path );
        }

        return buffer;
    }

} // namespace ntk