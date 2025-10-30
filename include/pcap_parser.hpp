#ifndef PCAP_PARSER_HPP
#define PCAP_PARSER_HPP

#include <utils.hpp>

namespace ntk {

	constexpr uint32_t pcap_magic_number = 0xa1b2c3d4;

	bool is_pcap_magic_number( const uint32_t magic_number );

} // namespace ntk

#endif // PCAP_PARSE_HPP