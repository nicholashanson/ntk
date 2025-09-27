#include <gtest/gtest.h>

#include <tcp.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsTcp ) {
	auto result = ntk::is_tcp( test_constants::tcp_syn_packet );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_TRUE( result.value() );
}

TEST( UnitTest, IsTcp_CounterCase ) {
	auto result = ntk::is_tcp( test::ethernet_frame_udp );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_FALSE( result.value() );
}