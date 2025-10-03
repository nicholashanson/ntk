#include <x_509.hpp>

namespace ntk {

	std::expected<std::size_t,std::string> parse_ans1_length( std::span<const uint8_t> certificate_bytes ) {
		if ( certificate_bytes.size() < 2 ) {
			return std::unexpected( "Certificate is too short" );
		}
		std::size_t length{};
		if ( certificate_bytes[ 1 ] < 0x80 ) {
			return certificate_bytes[ 1 ];
		} else {
			std::size_t num_len_bytes = certificate_bytes[ 1 ] & 0x7f;
			if ( certificate_bytes.size() < 2 + num_len_bytes ) {
				return std::unexpected( "Certificate is too short for Length Field" );
			}
			for ( std::size_t i = 0; i < num_len_bytes; ++i ) {
				length = ( length << 8 ) | certificate_bytes[ 2 + i ];
			}
			return length;
		}
	}

} // namespace ntk
