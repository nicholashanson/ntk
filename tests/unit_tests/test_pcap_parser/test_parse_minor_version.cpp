#include <gtest/gtest.h>

#include <pcap_parser.hpp>
#include <utils.hpp>

TEST( UnitTest, ParseVersionMinor ) {
	auto read_result = ntk::read_from_file( "capture_output.pcap", 0, ntk::pcap_global_header_offset::version_minor +
																	  ntk::pcap_global_header_len::version_minor );
	ASSERT_TRUE( read_result ) << read_result.error();
	auto& first_eight_bytes = read_result.value();
	ASSERT_EQ( first_eight_bytes.size(), 8 );
	ntk::gh_parse_result parse_result_before{
		ntk::pcap_global_header{},
		std::span( first_eight_bytes.data(), first_eight_bytes.size() )
	};
	auto parse_result = ntk::parse_version_minor( parse_result_before );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	auto& parse_result_after = parse_result.value();
	auto& header = parse_result_after.header;
	EXPECT_TRUE( ntk::enum_compare_helper( header.version_minor, ntk::pcap_version_minor::version_4 ) );
}