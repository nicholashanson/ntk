#include <x_509.hpp>

namespace ntk {

	// ===================
    //  Parse Ans1 Length 
    // ===================

	std::expected<std::size_t,std::string> parse_ans1_length( std::span<const uint8_t> certificate_bytes ) {
		constexpr std::size_t minimum_len = 2 /* ans1 byte + single-byte length field */; 
		constexpr std::size_t sb = 1 /* single-byte length field offset */;
		if ( certificate_bytes.size() < minimum_len ) {
			return std::unexpected( "Certificate is too short for Single-Byte Length Field" );
		}
		std::size_t length{};
		if ( certificate_bytes[ sb ] < 0x80 /* length is <= 127 */ ) {
			return certificate_bytes[ sb ];
		} else {
			std::size_t num_len_bytes = certificate_bytes[ sb ] & 0x7f /* clear the highest bit */;
			if ( certificate_bytes.size() < minimum_len + num_len_bytes ) {
				return std::unexpected( "Certificate is too short for Multi-Byte Length Field" );
			}
			for ( std::size_t i = 0; i < num_len_bytes; ++i ) {
				length = ( length << 8 ) | certificate_bytes[ minimum_len + i ];
			}
			return length;
		}
	}

} // namespace ntk
