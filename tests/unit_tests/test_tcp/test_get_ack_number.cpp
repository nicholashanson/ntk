#include <gtest/gtest.h>

#include <tcp.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetAckNumber ) { 
	auto result = ntk::get_ack_number( test_constants::tcp_synack_packet );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_EQ( result.value(), 0xb920c9b4 );
 }