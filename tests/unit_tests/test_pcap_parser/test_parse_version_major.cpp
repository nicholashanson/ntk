#include <gtest/gtest.h>

#include <pcap_parser.hpp>
#include <utils.hpp>

TEST( UnitTest, ParseVersionMajor ) {
	auto read_result = ntk::read_from_file( "capture_output.pcap", 0, 
											ntk::pcap_global_header_offset::version_major + ntk::pcap_global_header_len::version_major );
	ASSERT_TRUE( read_result ) << read_result.error();
	auto& first_six_bytes = read_result.value();
	ASSERT_EQ( first_six_bytes.size(), 6 );
	ntk::gh_parse_result parse_result_before{
		ntk::pcap_global_header{},
		std::span<const uint8_t>( first_six_bytes.data(), first_six_bytes.size() )
	};
	auto parse_result = ntk::parse_version_major( parse_result_before );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	auto& parse_result_after = parse_result.value();
	auto& global_header = parse_result_after.header;
	EXPECT_TRUE( ntk::enum_compare_helper( global_header.version_major, 
										   ntk::pcap_version_major::version_2 ) );
}