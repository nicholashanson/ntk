#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, TlsLiveStream_Initialization_ClientHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& client_hello_packet = packet_data[ 3 ];
	auto four = ntk::get_four_from_ethernet( client_hello_packet );
	ntk::tls_live_stream live_stream( four );
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_FALSE( client_hello_populated );
}

TEST( UnitTest, TLSLiveStream_Initialization_LinesConsumed ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake"] );
	auto& tcp_syn_packet = packet_data.front();
	auto four = ntk::get_four_from_ethernet( tcp_syn_packet );
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	auto lines_consumed = ntk::tls_live_stream_friend_helper::lines_consumed( live_stream );
	ASSERT_EQ( lines_consumed, 0 );
}

TEST( UnitTest, TLSLiveStream_Initialization_ClientTrafficSeqNumber ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake"] );
	auto& tcp_syn_packet = packet_data.front();
	auto four = ntk::get_four_from_ethernet( tcp_syn_packet );
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	auto client_traffic_seq_number = ntk::tls_live_stream_friend_helper::client_traffic_seq_number( live_stream );
	ASSERT_EQ( client_traffic_seq_number, 0 );
}

TEST( UnitTest, TLSLiveStream_Initialization_ServerTrafficSeqNumber ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake"] );
	auto& tcp_syn_packet = packet_data.front();
	auto four = ntk::get_four_from_ethernet( tcp_syn_packet );
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	auto server_traffic_seq_number = ntk::tls_live_stream_friend_helper::server_traffic_seq_number( live_stream );
	ASSERT_EQ( server_traffic_seq_number, 0 );
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

	auto client_hello_from_ethernet = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
	auto client_hello_from_tls_live_stream = *ntk::tls_live_stream_friend_helper::get_client_hello( live_stream );
	ASSERT_EQ( client_hello_from_ethernet, client_hello_from_tls_live_stream );
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

TEST( UnitTest, TlsLiveStream_ServerHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& syn = packet_data[ 0 ];
	auto& synack = packet_data[ 1 ];
	auto& ack = packet_data[ 2 ];
	auto& client_hello_packet = packet_data[ 3 ];
	auto& server_hello_packet = packet_data[ 5 ];
	auto four = ntk::get_four_from_ethernet( client_hello_packet );
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( syn );
	live_stream.feed( synack );
	live_stream.feed( ack ); 
	live_stream.feed( client_hello_packet );
	live_stream.feed( server_hello_packet );
	auto server_hello_populated = ntk::tls_live_stream_friend_helper::server_hello_populated( live_stream );
	ASSERT_TRUE( server_hello_populated );
}

TEST( UnitTest, TlsLiveStream_ServerHelloPopulated_CounterCase ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& server_hello_packet = packet_data[ 4 ];
	auto four = ntk::get_four_from_ethernet( server_hello_packet );
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( server_hello_packet );
	auto server_hello_populated = ntk::tls_live_stream_friend_helper::server_hello_populated( live_stream );
	ASSERT_FALSE( server_hello_populated );
}

TEST( UnitTest, TLSLiveStream_GetTlsSecretsDynamically ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake"] );
	std::string ssl_keys_log = "tls_session_keys.log";
	auto& syn = packet_data[ 0 ];
	auto& synack = packet_data[ 1 ];
	auto& ack = packet_data[ 2 ];
	auto& client_hello_packet = packet_data[ 3 ];
	auto& server_hello_packet = packet_data[ 5 ];
	auto four = ntk::get_four_from_ethernet( client_hello_packet );
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	live_stream.feed( syn );
	live_stream.feed( synack );
	live_stream.feed( ack ); 
	live_stream.feed( client_hello_packet );
	live_stream.feed( server_hello_packet );
	auto lines_consumed = ntk::tls_live_stream_friend_helper::lines_consumed( live_stream );
	ASSERT_EQ( lines_consumed, 10 );
}
