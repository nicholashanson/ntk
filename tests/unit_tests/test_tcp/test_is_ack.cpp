#include <gtest/gtest.h>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsAck ) {
	auto result = ntk::is_ack( test_constants::tcp_ack_packet );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_TRUE( result.value() );
}

TEST( UnitTest, IsAck_Header ) {
	ASSERT_TRUE( ntk::is_ack( test_constants::tcp_synack_parsed_tcp_header ) );
}

TEST( UnitTest, IsAck_CounterCase ) {
	auto result = ntk::is_ack( test_constants::tcp_syn_packet );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_FALSE( result.value() );
}

TEST( UnitTest, IsAck_CounterCase_Header ) {
	ASSERT_TRUE( ntk::is_ack( test_constants::tcp_synack_parsed_tcp_header ) );
}