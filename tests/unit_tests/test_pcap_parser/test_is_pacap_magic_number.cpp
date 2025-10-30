#include <gtest/gtest.h>

#include <pcap_parser.hpp>
#include <utils.hpp>

TEST( UnitTest, IsPcapMagicNumber ) {
	auto read_result = ntk::read_from_file( "capture_output.pcap", 0, 4 );
	ASSERT_TRUE( read_result ) << read_result.error();
	auto& first_four_bytes = read_result.value();
	auto magic_number = ntk::read_uint32_be( first_four_bytes, 0 );
	EXPECT_TRUE( ntk::is_pcap_magic_number( magic_number ) );
}
