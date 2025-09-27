#include <gtest/gtest.h>

#include <tcp.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsSynOf ) {
	auto result = ntk::is_syn_of( test_constants::tcp_syn_packet, test_constants::tcp_syn_four );
	ASSERT_TRUE( result );
}

TEST( UnitTest, IsSynOf_CounterCase ) {
	auto result = ntk::is_syn_of( test::ethernet_frame_tcp, test_constants::tcp_syn_four );
	ASSERT_TRUE( result );
}