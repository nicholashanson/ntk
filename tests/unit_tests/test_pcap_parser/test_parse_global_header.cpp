#include <gtest/gtest.h>

#include <pcap_parser.hpp>

TEST( UnitTest, ParseGlobalHeader ) {
	auto read_result = ntk::read_from_file( "capture_output.pcap", 0, ntk::pcap_global_header_total_len );
	ASSERT_TRUE( read_result ) << read_result.error();
	auto& first_24_bytes = read_result.value();
	ASSERT_EQ( first_24_bytes.size(), 24 );
	ntk::pcap_global_header expected{
		ntk::pcap_magic_number,
		ntk::pcap_version_major::version_2,
		ntk::pcap_version_minor::version_4,
		0x00000000,
		0x00000000,
		0x0000ffff,
		ntk::pcap_network::ethernet
	};
	auto parse_result = ntk::parse_global_header( first_24_bytes );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	EXPECT_EQ( expected, parse_result.value().header );
}