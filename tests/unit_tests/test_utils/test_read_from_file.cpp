#include <gtest/gtest.h>

#include <utils.hpp>

TEST( UnitTest, ReadFromFile ) {
	auto read_result = ntk::read_from_file( "capture_output.pcap", 0, 4 );
	ASSERT_TRUE( read_result ) << read_result.error();
	auto& first_four_bytes = read_result.value();
	EXPECT_EQ( first_four_bytes.size(), 4 );

}