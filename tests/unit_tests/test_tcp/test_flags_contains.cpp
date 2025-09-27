#include <gtest/gtest.h>

#include <tcp.hpp>

TEST( UnitTest, FlagsContains_0x02ContainsAck ) {
	ASSERT_FALSE( ntk::flags_contains( 0x02, ntk::tcp_flags::ack ) );
}

TEST( UnitTest, FlagsContains_0x10ContainsSyn ) {
	ASSERT_FALSE( ntk::flags_contains( 0x10, ntk::tcp_flags::syn ) );
}

TEST( UnitTest, FlagsContains_0x12ContainsAck ) {
	ASSERT_TRUE( ntk::flags_contains( 0x12, ntk::tcp_flags::ack ) );
}

TEST( UnitTest, FlagsContains_0x10ContainsAck ) {
	ASSERT_TRUE( ntk::flags_contains( 0x10, ntk::tcp_flags::ack ) );
}
