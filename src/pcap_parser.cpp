#include <pcap_parser.hpp>

namespace ntk {

	bool is_pcap_magic_number( uint32_t magic_number ) {
		return magic_number == pcap_magic_number || magic_number == swap_endian( pcap_magic_number );
	}

	std::expected<bool,std::string> is_pcap_file( std::span<const uint8_t> first_four_bytes ) {
		if ( first_four_bytes.size() != 4 ) {
			return std::unexpected( "PCAP Magic Number should be only four bytes" );
		}
		auto magic_number = read_uint32_be( first_four_bytes, 0 );
		return is_pcap_magic_number( magic_number );
	}

} // namespace ntk
