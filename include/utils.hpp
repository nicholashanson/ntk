#ifndef UTILS_HPP
#define UTILS_HPP

#include <span>
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <concepts>

namespace ntk {

    // ==============================
    //            BITMASK
    // ==============================

    enum class bitmask_8bit : uint8_t {
        LOW_NIBBLE    = 0x0f,
        FULL_BYTE     = 0xff
    };

    // ==============================
    //       BYTES TO INTEGERS
    // ==============================

    uint16_t read_uint16_be( const unsigned char* buffer, size_t offset );

    template<typename Index> 
    uint16_t read_uint16_be( std::span<const uint8_t> buffer, Index offset ) {
        return read_uint16_be( buffer.data(), static_cast<size_t>( offset ) );
    }

    uint32_t read_uint32_be( const unsigned char* buffer, size_t offset );

    template<typename Index>
    uint32_t read_uint32_be( std::span<const uint8_t> buffer, Index offset ) {
        return read_uint32_be( buffer.data(), static_cast<size_t>( offset ) );
    }

    // ==============================
    //         APPLY AND MASK
    // ==============================

    template<typename MaskEnum,typename Integral>
    constexpr auto apply_and_mask( Integral value, MaskEnum mask ) {
        using enum_underlying = std::underlying_type_t<MaskEnum>;
        static_assert( sizeof( Integral ) >= sizeof( enum_underlying ),
                       "Integral type must be at least as large as mask underlying type" );
        if constexpr ( std::is_enum_v<Integral> ) {
            using integral_underlying = std::underlying_type_t<Integral>;
            return static_cast<integral_underlying>( value ) & static_cast<enum_underlying>( mask );
        } else {  
            return value & static_cast<enum_underlying>( mask );
        }
    }

    // ==============================
    //         RIGHT SHIFT
    // ==============================

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

    // ==============================
    //           CONCEPTS
    // ==============================

    template<typename T>
    concept is_8bit_integral = 
    	( std::integral<T> && sizeof( T ) == 1 ) ||  
    	( std::is_enum_v<T> && sizeof( T ) == 1 && std::is_integral_v<std::underlying_type_t<T>> );

    template<typename T>
    concept is_16bit_integral = 
    	( std::integral<T> && sizeof( T ) == 2 ) ||  
    	( std::is_enum_v<T> && sizeof( T ) == 2 && std::is_integral_v<std::underlying_type_t<T>> );


    // ==============================
    //       Bit Manipulation
    // ==============================

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

    template<typename T>
    struct triple {
        const T& first;
        const T& second;
        const T& third;

        const T& get( std::size_t i ) const {
            switch ( i ) {
                case 0: return first;
                case 1: return second;
                case 2: return third;
                default: throw std::out_of_range( "Triple index out of range.");
            }

        }
    };

} // namespace ntk

namespace std {

    template<typename T>
    struct tuple_size<ntk::triple<T>> : std::integral_constant<std::size_t,3> {};

    template<typename T>
    struct tuple_element<0,ntk::triple<T>> { using type = T; };
    template<typename T>
    struct tuple_element<1,ntk::triple<T>> { using type = T; };
    template<typename T>
    struct tuple_element<2,ntk::triple<T>> { using type = T; };

    template <std::size_t I,typename T>
    const T& get( const ntk::triple<T>& t ) {
        if constexpr ( I == 0 ) return t.first;
        else if constexpr ( I == 1 ) return t.second;
        else if constexpr ( I == 2 ) return t.third;
    }

} // namespace std

namespace ntk {

    template<typename T>
    triple<T> make_triple( const std::span<const T>& window ) {
        assert( window.size() == 3 ); 
        return triple<T>{ window[ 0 ], window[ 1 ], window[ 2 ] };
    }

} // namespace ntk

#endif // UTILS_HPP