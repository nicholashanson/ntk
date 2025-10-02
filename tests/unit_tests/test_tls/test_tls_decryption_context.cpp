#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, TlsDecryptionContext ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto four_result = ntk::get_four_from_ethernet( packet_data.front() );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	ntk::tls_decryption_context ctx( four_result.value() );
	auto client_traffic_seq_number = ntk::tls_decryption_context_friend_helper::get_client_traffic_seq_number( ctx );
	auto server_traffic_seq_number = ntk::tls_decryption_context_friend_helper::get_server_traffic_seq_number( ctx );
	EXPECT_EQ( client_traffic_seq_number, 0 );
	EXPECT_EQ( server_traffic_seq_number, 0 ); 
}

TEST( UnitTest, TlsDecryptionContext_ClientHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto four_result = ntk::get_four_from_ethernet( packet_data.front() );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	ntk::tls_decryption_context ctx( four_result.value() );
	const std::size_t read_packets_to = 7 /* client hello */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		ctx.feed( packet_data[ i ] );
	}
	auto is_client_hello_populated = ntk::tls_decryption_context_friend_helper::is_client_hello_populated( ctx );
	EXPECT_TRUE( is_client_hello_populated );
}

TEST( UnitTest, TlsDecryptionContext_ServerHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto four_result = ntk::get_four_from_ethernet( packet_data.front() );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_decryption_context ctx( four_result.value(), ssl_keys_log );
	const std::size_t read_packets_to = 7 /* server hello */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		ctx.feed( packet_data[ i ] );
	}
	auto is_server_hello_populated = ntk::tls_decryption_context_friend_helper::is_server_hello_populated( ctx );
	auto has_secrets = ntk::tls_decryption_context_friend_helper::has_secrets( ctx );
	EXPECT_TRUE( is_server_hello_populated );
	EXPECT_TRUE( has_secrets );
}

TEST( UnitTest, TlsDecryptionContext_NonEmptyTaskQueue ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_decryption_context ctx( four, ssl_keys_log );
	const std::size_t read_packets_to = 27 /* last part of first record of third http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		ctx.feed( packet_data[ i ] );
	}
	auto task_queue_size = ntk::tls_decryption_context_friend_helper::get_task_queue_size( ctx );
	EXPECT_EQ( task_queue_size, 3 );
}

