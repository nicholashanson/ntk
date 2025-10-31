#ifndef PCAP_PARSER_HPP
#define PCAP_PARSER_HPP

#include <utils.hpp>

namespace ntk {

	namespace pcap_global_header_offset {

		constexpr std::size_t magic_number = 0;
		constexpr std::size_t version_major = 4;
		constexpr std::size_t version_minor = 6;
		constexpr std::size_t this_zone = 8;
		constexpr std::size_t sig_figs = 12;
		constexpr std::size_t snap_len = 16;
		constexpr std::size_t network = 20;

	} // namesapce pcap_global_header_offset

	namespace pcap_global_header_len {

		constexpr std::size_t magic_number = 4;
		constexpr std::size_t version_major = 2;
		constexpr std::size_t version_minor = 2;
		constexpr std::size_t this_zone = 4;
		constexpr std::size_t sig_figs = 4;
		constexpr std::size_t snap_len = 4;
		constexpr std::size_t network = 4;

	} // namespace pcap_global_header_len

	enum class pcap_version_major : uint16_t {
		version_2 = 0x0002
	};

	enum class pcap_version_minor : uint16_t {
		version_4 = 0x0004
	};

	enum class pcap_network : uint32_t {
		ethernet = 0x00000001
	};

	struct pcap_global_header {
		uint32_t magic_number;
		pcap_version_major version_major;
		pcap_version_minor version_minor;
		uint32_t this_zone;
		uint32_t sig_figs;
		uint32_t snap_len;
		pcap_network network;

		bool operator==( const pcap_global_header& other ) const {
			return ( magic_number == swap_endian( other.magic_number ) || magic_number == other.magic_number ) &&
				   enum_compare_helper( version_major, other.version_major ) &&
				   enum_compare_helper( version_minor, other.version_minor ) &&
				   ( this_zone 	== swap_endian( other.this_zone ) || this_zone == other.this_zone ) &&
				   ( sig_figs 	== swap_endian( other.sig_figs  ) || sig_figs  == other.sig_figs  ) &&
				   ( snap_len 	== swap_endian( other.snap_len  ) || snap_len  == other.snap_len  ) &&
				   enum_compare_helper( network, other.network ); 
		}
	};

	struct gh_parse_result {
		pcap_global_header header;
		std::span<const uint8_t> buffer;
	};

	constexpr uint32_t pcap_magic_number = 0xa1b2c3d4;

	constexpr std::size_t pcap_global_header_total_len = 24;

	bool is_pcap_magic_number( const uint32_t magic_number );

	std::expected<gh_parse_result,std::string> parse_magic_number( gh_parse_result p_result );

	std::expected<gh_parse_result,std::string> parse_version_major( gh_parse_result p_result );

	std::expected<gh_parse_result,std::string> parse_version_minor( gh_parse_result p_result );

	std::expected<gh_parse_result,std::string> parse_this_zone( gh_parse_result p_result );

	std::expected<gh_parse_result,std::string> parse_sig_figs( gh_parse_result p_result );

	std::expected<gh_parse_result,std::string> parse_snap_len( gh_parse_result p_result );

	std::expected<gh_parse_result,std::string> parse_network( gh_parse_result p_result );

	std::expected<gh_parse_result,std::string> parse_global_header( std::span<const uint8_t> buffer );

} // namespace ntk

#endif // PCAP_PARSE_HPP