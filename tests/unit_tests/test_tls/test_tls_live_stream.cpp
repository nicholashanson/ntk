#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, TlsLiveStream ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& client_hello_packet = packet_data[ 3 ];
	auto four = ntk::get_four_from_ethernet( client_hello_packet );
	ntk::tls_live_stream live_stream( four );
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_FALSE( client_hello_populated );
}

TEST( UnitTest, TlsLiveStream_HandshakeFeed_Complete ) {
	std::vector<uint8_t> tcp_syn_packet( std::begin( test_constants::tcp_syn_packet), std::end( test_constants::tcp_syn_packet ) );
	std::vector<uint8_t> tcp_synack_packet( std::begin( test_constants::tcp_synack_packet), std::end( test_constants::tcp_synack_packet ) );  
	std::vector<uint8_t> tcp_ack_packet( std::begin( test_constants::tcp_ack_packet), std::end( test_constants::tcp_ack_packet ) ); 
	auto four = ntk::get_four_from_ethernet( tcp_syn_packet );
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( tcp_syn_packet );
	live_stream.feed( tcp_synack_packet );
	live_stream.feed( tcp_ack_packet );
	auto handshake_complete = ntk::tcp_live_stream_friend_helper::handshake_feed( live_stream ).m_complete;
	ASSERT_TRUE( handshake_complete );
}

TEST( UnitTest, TlsLiveStream_ClientHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& syn = packet_data[ 0 ];
	auto& synack = packet_data[ 1 ];
	auto& ack = packet_data[ 2 ];
	auto& client_hello_packet = packet_data[ 3 ];
	auto four = ntk::get_four_from_ethernet( client_hello_packet );
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( syn );
	live_stream.feed( synack );
	live_stream.feed( ack ); 
	live_stream.feed( client_hello_packet );
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_TRUE( client_hello_populated );
}

TEST( UnitTest, TlsLiveStream_ClientHelloPopulated_CounterCase ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& client_hello_packet = packet_data[ 3 ];
	auto four = ntk::get_four_from_ethernet( client_hello_packet );
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( client_hello_packet );
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_FALSE( client_hello_populated );
}