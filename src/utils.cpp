#include <utils.hpp>

namespace ntk {

    // ========================
    //  Read Uint16 Big Endian
    // ========================

    uint16_t read_uint16_be( const unsigned char* buffer, std::size_t offset ) {
        return ( buffer[ offset ] << 8 ) | buffer[ offset + 1 ];
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    uint16_t read_uint16_be( std::initializer_list<const char> bytes ) {
        auto it = bytes.begin();
        return ( *it << 8 ) | *( it + 1 );
    }

    // ========================
    //  Read Uint32 Big Endian
    // ========================

    uint32_t read_uint32_be( const unsigned char* buffer, std::size_t offset ) {
        return ( buffer[ offset ]     << 24 ) | ( buffer[ offset + 1 ] << 16 ) |
               ( buffer[ offset + 2 ] <<  8 ) |   buffer[ offset + 3 ];
    }

    // =====================
    //  Bytes to Hex String
    // =====================

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
            static_cast<uint8_t>(   value         & 0xff )
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
        if ( !file.read( reinterpret_cast<char*>( buffer.data() ), size ) ) {
            return std::unexpected( "Failed to read file: " + path );
        }

        return buffer;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<std::vector<uint8_t>,std::string> read_from_file( const std::string& path, 
                                                                    const std::size_t byte_from, 
                                                                    const std::size_t byte_to ) {
        std::ifstream file( path, std::ios::binary | std::ios::ate );
        if ( !file ) {
            return std::unexpected( "Failed to open file: " + path );
        }
        std::streamsize size = file.tellg();
        if ( byte_from > byte_to ) {
            return std::unexpected( "Start Line can not be less than End Line" );
        }
        if ( byte_to > static_cast<std::size_t>( size ) ) {
            return std::unexpected( "End Line can not exceed the File Size" );
        }
        std::size_t bytes_to_read = byte_to - byte_from;
        std::vector<uint8_t> result;
        result.reserve( bytes_to_read );
        file.seekg( byte_from );
        const std::size_t chunk_size = 1024;
        while ( bytes_to_read > 0 ) {
            std::size_t read_size = std::min( chunk_size, bytes_to_read );
            std::vector<uint8_t> buffer( read_size );
            file.read( reinterpret_cast<char*>( buffer.data() ), read_size );
            if ( !file ) {
                return std::unexpected( "Error reading from File" );
            }
            result.insert( result.end(), buffer.begin(), buffer.end() );
            bytes_to_read -= read_size;
        }
        return result;
    }

    // =============
    //  Swap Endian
    // =============

    uint32_t swap_endian( uint32_t value ) {
        return ( ( value & 0x000000ff ) << 24 ) |
               ( ( value & 0x0000ff00 ) <<  8 ) |
               ( ( value & 0x00ff0000 ) >>  8 ) |
               ( ( value & 0xff000000 ) >> 24 );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    uint16_t swap_endian( uint16_t value ) {
        return ( ( value & 0x00ff ) << 8 ) |
               ( ( value & 0xff00 ) >> 8 );
    }

} // namespace ntk