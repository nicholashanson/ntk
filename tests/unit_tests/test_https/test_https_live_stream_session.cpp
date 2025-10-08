#include <gtest/gtest.h>

#include <https.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, HttpsLiveStreamSession_FourTuples ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
	ASSERT_FALSE( packet_data.empty() ); 
	ntk::https_live_stream_session live_stream_session( "../server/session_keys.log" );
	live_stream_session.feed( packet_data.front() );
	auto four_tuples = ntk::https_live_stream_session_friend_helper::four_tuples( live_stream_session );
	ASSERT_FALSE( four_tuples.empty() );
}

TEST( UnitTest, HttpsLiveStreamSession_LiveStreams ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
	ASSERT_FALSE( packet_data.empty() ); 
	ntk::https_live_stream_session live_stream_session( "../server/session_keys.log" );
	live_stream_session.feed( packet_data.front() );
	const auto& live_streams = ntk::https_live_stream_session_friend_helper::live_streams( live_stream_session );
	ASSERT_FALSE( live_streams.empty() );
}

TEST( UnitTest, HttpsLiveStreamSession ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
	ASSERT_FALSE( packet_data.empty() );
	ntk::https_live_stream_session live_stream_session( "../server/session_keys.log" );
	for ( std::size_t i = 0; i < packet_data.size(); ++i ) {
		live_stream_session.feed( packet_data[ i ] );
	}
	auto files_written = ntk::https_live_stream_session_friend_helper::files_written( live_stream_session );
	ASSERT_TRUE( files_written );
	ASSERT_EQ( files_written->size(), 1 );
}

TEST( UnitTest, HttpsLiveStreamSession_ClientHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture_crash" ] );
	ASSERT_FALSE( packet_data.empty() );
	ntk::https_live_stream_session live_stream_session( "../server/session_keys_.log" );
	const std::size_t read_to = 4;
	for ( std::size_t i = 0; i < read_to; ++i ) {
		live_stream_session.feed( packet_data[ i ] );
	}
	auto& live_streams = ntk::https_live_stream_session_friend_helper::live_streams( live_stream_session );
	auto& live_stream = live_streams.front(); 
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( *live_stream );
	ASSERT_TRUE( client_hello_populated );
}

TEST( UnitTest, HttpsLiveStreamSession_ServerHelloPopulated_HasClientTrafficSecret ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture_crash" ] );
	ASSERT_FALSE( packet_data.empty() );
	ntk::https_live_stream_session live_stream_session( "../server/session_keys_.log" );
	const std::size_t read_to = 6;
	for ( std::size_t i = 0; i < read_to; ++i ) {
		live_stream_session.feed( packet_data[ i ] );
	}
	auto& live_streams = ntk::https_live_stream_session_friend_helper::live_streams( live_stream_session );
	auto& live_stream = live_streams.front(); 
	auto server_hello_populated = ntk::tls_live_stream_friend_helper::server_hello_populated( *live_stream );
	ASSERT_TRUE( server_hello_populated );
	ASSERT_FALSE( live_stream->has_client_traffic_secret() );
} 