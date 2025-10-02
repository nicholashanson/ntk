#include <gtest/gtest.h>

#include <https.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, HttpsDecryptionContext_ServerHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto four_result = ntk::get_four_from_ethernet( packet_data.front() );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_decryption_context ctx( four_result.value(), ssl_keys_log );
	const std::size_t read_packets_to = 7 /* server hello */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		ctx.feed( packet_data[ i ] );
	}
	auto is_server_hello_populated = ntk::tls_decryption_context_friend_helper::is_server_hello_populated( ctx );
	auto has_secrets = ntk::tls_decryption_context_friend_helper::has_secrets( ctx );
	EXPECT_TRUE( is_server_hello_populated );
	EXPECT_TRUE( has_secrets );
}

TEST( UnitTest, HttpsDecryptionContext_IncompleteRequestResponse ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_decryption_context ctx( four, ssl_keys_log );
	const std::size_t read_packets_to = 27 /* first part of first record of third http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		ctx.feed( packet_data[ i ] );
	}
	auto expected_bytes = ntk::https_decryption_context_friend_helper::get_expected_bytes( ctx );
	auto recieved_bytes = ntk::https_decryption_context_friend_helper::get_recieved_bytes( ctx );
	EXPECT_EQ( expected_bytes, 384836 );
	EXPECT_EQ( recieved_bytes, 15848 );
	auto incomplete_request_response = ntk::https_decryption_context_friend_helper::get_incomplete_request_response( ctx );
	ASSERT_TRUE( incomplete_request_response->response );
	EXPECT_EQ( incomplete_request_response->response->body.size(), 15848 );
}

TEST( UnitTest, HttpsDecryptionContext_IncompleteRequestResponse_Complete ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_decryption_context ctx( four, ssl_keys_log );
	std::size_t read_packets_to = 97 /* last part of last record of tnird http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		ctx.feed( packet_data[ i ] );
	}
	auto expected_bytes = ntk::https_decryption_context_friend_helper::get_expected_bytes( ctx );
	auto recieved_bytes = ntk::https_decryption_context_friend_helper::get_recieved_bytes( ctx );
	auto incomplete_request_response = ntk::https_decryption_context_friend_helper::get_incomplete_request_response( ctx );
	EXPECT_EQ( expected_bytes, 0 );
	EXPECT_EQ( recieved_bytes, 0 );
	EXPECT_EQ( incomplete_request_response->response->body.size(), 384836 );
}