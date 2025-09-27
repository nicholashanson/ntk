#include <gtest/gtest.h>

#include <tcp.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsSynAck_Packet ) {
	auto result = ntk::is_syn_ack( test_constants::tcp_synack_packet );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_TRUE( result.value() );
}

TEST( UnitTest, IsSynAck_Header ) {
	auto result = ntk::is_syn_ack( test_constants::tcp_synack_parsed_tcp_header );
	ASSERT_TRUE( result );
}

TEST( UnitTest, IsSynAck_CounterCase_Syn_Packet) {
	auto result = ntk::is_syn_ack( test_constants::tcp_syn_packet );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_FALSE( result.value() );
} 

TEST( UnitTest, IsSynAck_CounterCase_Syn_Header ) {
	auto result = ntk::is_syn_ack( test_constants::tcp_syn_parsed_tcp_header );
	ASSERT_FALSE( result );
}

TEST( UnitTest, IsSynAck_CounterCase_Ack_Packet ) {
	auto result = ntk::is_syn_ack( test_constants::tcp_ack_packet );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_FALSE( result.value() );
}

TEST( UnitTest, IsSynAck_CounterCase_Ack_Header ) {
	auto result = ntk::is_syn_ack( test_constants::tcp_ack_parsed_tcp_header );
	ASSERT_FALSE( result );
}