#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, FlipFour ) {
	auto syn_four_result = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
	ASSERT_TRUE( syn_four_result ) << syn_four_result.error() << std::endl;
	auto synack_four_result = ntk::get_four_from_ethernet( test_constants::tcp_synack_packet );
	ASSERT_TRUE( synack_four_result ) << synack_four_result.error() << std::endl;
	ASSERT_EQ( syn_four_result.value(), ntk::flip_four( synack_four_result.value() ) );
}

TEST( UnitTest, FlipFour_CounterCase ) {
	auto syn_four_result = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
	ASSERT_TRUE( syn_four_result ) << syn_four_result.error() << std::endl;
	auto ack_four_result = ntk::get_four_from_ethernet( test_constants::tcp_ack_packet );
	ASSERT_TRUE( ack_four_result ) << ack_four_result.error() << std::endl;
	ASSERT_NE( syn_four_result.value(), ntk::flip_four( ack_four_result.value() ) );
}