#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, HasFlippedFour ) {
	auto four_result = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto result = ntk::has_flipped_four( test_constants::tcp_synack_packet, four_result.value() );
	ASSERT_TRUE( result );
	ASSERT_TRUE( result.value() );
}

TEST( UnitTest, HasFlippedFour_CounterCase ) {
	auto four_result = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto result = ntk::has_flipped_four( test_constants::tcp_ack_packet, four_result.value() );
	ASSERT_TRUE( result );
	ASSERT_FALSE( result.value() );
}