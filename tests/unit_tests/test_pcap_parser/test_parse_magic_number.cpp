#include <gtest/gtest.h>

#include <pcap_parser.hpp>
#include <utils.hpp>

TEST( UnitTest, ParseMagicNumber ) {
	auto read_result = ntk::read_from_file( "capture_output.pcap", 0, 4 );
	ASSERT_TRUE( read_result ) << read_result.error();
	auto& first_four_bytes = read_result.value();
	ntk::gh_parse_result p_result_before{ 
		ntk::pcap_global_header{}, 
		std::span<const uint8_t>( first_four_bytes.data(), first_four_bytes.size() ) 
	};
	auto parse_result = ntk::parse_magic_number( p_result_before );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	auto& p_result_after = parse_result.value();
	auto& global_header = p_result_after.header;
	EXPECT_TRUE( ntk::is_pcap_magic_number( global_header.magic_number ) );
}