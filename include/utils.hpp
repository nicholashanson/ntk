#ifndef UTILS_HPP
#define UTILS_HPP

#include <span>
#include <cstdint>
#include <concepts>

namespace ntk {

    uint16_t read_uint16_be( const unsigned char* buffer, size_t offset );

    uint16_t read_uint16_be( const std::span<const uint8_t> buffer, size_t offset );

    uint32_t read_uint32_be( const unsigned char* buffer, size_t offset );

    uint32_t read_uint32_be( const std::span<const uint8_t> buffer, size_t offset );

    template<typename T>
    concept is_8bit_integral = 
    	( std::integral<T> && sizeof( T ) == 1 ) ||  
    	( std::is_enum_v<T> && sizeof( T ) == 1 && std::is_integral_v<std::underlying_type_t<T>> );

    template<typename T>
    concept is_16bit_integral = 
    	( std::integral<T> && sizeof( T ) == 2 ) ||  
    	( std::is_enum_v<T> && sizeof( T ) == 2 && std::is_integral_v<std::underlying_type_t<T>> );

    template<is_8bit_integral T>
    uint8_t extract_low_nibble( T t ) {
    	return static_cast<uint8_t>( static_cast<uint8_t>( t ) & 0x0f );
    }

    template<is_8bit_integral T>
    uint8_t extract_high_nibble( T t ) {
    	return static_cast<uint8_t>( ( static_cast<uint8_t>( t ) >> 4 ) & 0x0f );
    }

    template<is_16bit_integral T>
    uint8_t extract_least_significant_byte( T t ) {
    	return static_cast<uint8_t>( static_cast<uint16_t>( t ) & 0xff );
    }

    template<is_16bit_integral T>
    uint8_t extract_most_significant_byte( T t ) {
    	return static_cast<uint8_t>( static_cast<uint16_t>( t ) >> 8 );
    }

} // namespace ntk

#endif // UTILS_HPP