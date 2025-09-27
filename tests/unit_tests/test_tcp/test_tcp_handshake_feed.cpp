#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, TcpHandshakeFeed_Syn ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto four = *ntk::get_four_from_ethernet( packet_data.front() );
	ntk::tcp_handshake_feed hanshake_feed( four );
	hanshake_feed.feed( packet_data.front() );
	ASSERT_TRUE( hanshake_feed.m_syn );
}

TEST( UnitTest, TcpHandshakeFeed_SynAck ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto four = *ntk::get_four_from_ethernet( packet_data.front() );
	ntk::tcp_handshake_feed hanshake_feed( four );
	hanshake_feed.feed( packet_data.front() );
	hanshake_feed.feed( packet_data[ 1 ] );
	ASSERT_TRUE( hanshake_feed.m_syn_ack );
}

TEST( UnitTest, TcpHandshakeFeed_Ack ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto four = *ntk::get_four_from_ethernet( packet_data.front() );
	ntk::tcp_handshake_feed hanshake_feed( four );
	hanshake_feed.feed( packet_data.front() );
	hanshake_feed.feed( packet_data[ 1 ] );
	hanshake_feed.feed( packet_data[ 2 ] );
	ASSERT_TRUE( hanshake_feed.m_ack );
}

TEST( UnitTest, TcpHandshakeFeed ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto four = *ntk::get_four_from_ethernet( packet_data.front() );
	ntk::tcp_handshake_feed hanshake_feed( four );
	const std::size_t read_up_to = 3;
	for ( std::size_t i = 0; i < read_up_to; ++i ) {
		auto feed_result = hanshake_feed.feed( packet_data[ i ] );
		ASSERT_TRUE( feed_result ) << feed_result.error() << std::endl;
	}
	ASSERT_TRUE( hanshake_feed.m_complete );
}
