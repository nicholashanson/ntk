#include <gtest/gtest.h>

#include <https.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, HttpsLiveStream_ServerHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	std::string ssl_keys_log = "";
	auto four = ntk::get_four_from_ethernet( packet_data.front() );
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 7;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto server_hello_populated = ntk::tls_live_stream_friend_helper::server_hello_populated( live_stream );
	ASSERT_TRUE( server_hello_populated );
}

TEST( UnitTest, HttpsLiveStream_TlsSecrets ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	std::string ssl_keys_log = "sslkeys.log";
	auto four = ntk::get_four_from_ethernet( packet_data.front() );
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 7;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto tls_secrets = ntk::tls_live_stream_friend_helper::tls_secrets( live_stream );
	ntk::print_tls_secrets( tls_secrets );
	auto client_hello = *ntk::tls_live_stream_friend_helper::get_client_hello( live_stream );
	auto client_random_hex = ntk::client_random_to_hex( client_hello.get().random );
	ASSERT_TRUE( ntk::is_complete_secrets( tls_secrets[ client_random_hex ] ) );
}

TEST( UnitTest, HttpsLiveStream_IncompleteRequestResponse_HttpRequest ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	std::string ssl_keys_log = "sslkeys.log";
	auto four = ntk::get_four_from_ethernet( packet_data.front() );
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 12;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto incomplete_request_response = ntk::https_live_stream_friend_helper::get_incomplete_request_response( live_stream );
	ASSERT_TRUE( incomplete_request_response.request );
}

TEST( UnitTest, HttpsLiveStream_Initialization_ExpectedData ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	std::string ssl_keys_log = "sslkeys.log";
	auto four = ntk::get_four_from_ethernet( packet_data.front() );
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	auto expected_data = ntk::https_live_stream_friend_helper::expected_data( live_stream );	
	ASSERT_FALSE( expected_data );
}

TEST( UnitTest, HttpsLiveStream_ExpectedData ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	std::string ssl_keys_log = "sslkeys.log";
	auto four = ntk::get_four_from_ethernet( packet_data.front() );
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 12;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto expected_data = ntk::https_live_stream_friend_helper::expected_data( live_stream );	
	ASSERT_TRUE( expected_data );
}

TEST( UnitTest, HttpsLiveStream_ExpectedData_MimeType ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	std::string ssl_keys_log = "sslkeys.log";
	auto four = ntk::get_four_from_ethernet( packet_data.front() );
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 12;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto expected_data = ntk::https_live_stream_friend_helper::expected_data( live_stream );	
	ASSERT_EQ( expected_data, ntk::mime_type::VIDEO_MP2T );
}

TEST( UnitTest, HttpsLiveStream_IncompleteRequestResponse_IncompleteHttpResponse ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	std::string ssl_keys_log = "sslkeys.log";
	auto four = ntk::get_four_from_ethernet( packet_data.front() );
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 14;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto incomplete_request_response = ntk::https_live_stream_friend_helper::get_incomplete_request_response( live_stream );
	auto decrypted_data = ntk::tls_live_stream_friend_helper::decrypted_record( live_stream ); 
	ntk::print_vector( decrypted_data.value().payload );
	ASSERT_TRUE( incomplete_request_response.response );
	ASSERT_EQ( ( *incomplete_request_response.response ).body.size(), 15848 );
	ASSERT_EQ( ( *incomplete_request_response.response ).content_length, 384836 );
	ASSERT_FALSE( ( *incomplete_request_response.response ).http_response_complete() );
}
