#ifndef UTILS_HPP
#define UTILS_HPP

#include <span>
#include <cstdint>
#include <concepts>

namespace ntk {

	enum class bitmask_8bit : uint8_t {
		LOW_NIBBLE    = 0x0f,
		FULL_BYTE     = 0xff
	};

    uint16_t read_uint16_be( const unsigned char* buffer, size_t offset );

    uint16_t read_uint16_be( const std::span<const uint8_t> buffer, size_t offset );

    uint32_t read_uint32_be( const unsigned char* buffer, size_t offset );

    uint32_t read_uint32_be( const std::span<const uint8_t> buffer, size_t offset );

    template<typename MaskEnum,typename Integral>
	constexpr auto apply_and_mask( Integral value, MaskEnum mask ) {
	    using underlying = std::underlying_type_t<MaskEnum>;
	    static_assert( sizeof( Integral ) >= sizeof( underlying ),
                       "Integral type must be at least as large as mask underlying type" );
	    if constexpr ( std::is_enum_v<Integral> )
	    	return static_cast<std::underlying_type_t<Integral>>( value ) & static_cast<underlying>( mask );
	    else {  
	    	return value & static_cast<underlying>( mask );
	    }
	}

	template<size_t shift_by,typename Integral>
	constexpr auto right_shift( Integral value ) {
		const size_t size_in_bits = sizeof( Integral ) * 8;
	    static_assert( shift_by < size_in_bits,
                       "Right-shifting by that value causes undefined-behavior" );
	   	if constexpr ( std::is_enum_v<Integral> )
	    	return static_cast<std::underlying_type_t<Integral>>( value ) >> shift_by;
	    else {  
	    	return value >> shift_by;
	    }
	}

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
    	return static_cast<uint8_t>( apply_and_mask( t, bitmask_8bit::LOW_NIBBLE ) );
    }

    template<is_8bit_integral T>
    uint8_t extract_high_nibble( T t ) {
    	uint8_t shifted = right_shift<4>( t );
    	return static_cast<uint8_t>( apply_and_mask( shifted, bitmask_8bit::LOW_NIBBLE ) );
    }

    template<is_16bit_integral T>
    uint8_t extract_least_significant_byte( T t ) {
    	return static_cast<uint8_t>( apply_and_mask( t, bitmask_8bit::FULL_BYTE ) );
    }

    template<is_16bit_integral T>
    uint8_t extract_most_significant_byte( T t ) {
    	return static_cast<uint8_t>( right_shift<8>( t ) );
    }

} // namespace ntk

#endif // UTILS_HPP