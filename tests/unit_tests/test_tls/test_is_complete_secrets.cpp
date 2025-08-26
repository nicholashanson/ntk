#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsCompleteSecrets ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& client_hello_packet = packet_data[ 3 ];
	auto client_hello = *ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
	auto client_random = client_hello.random;
	auto secrets = ntk::get_tls_secrets( "tls_session_keys.log", client_random );
	ASSERT_TRUE( ntk::is_complete_secrets( secrets[ ntk::client_random_to_hex( client_random ) ] ) );  
}

TEST( UnitTest, IsCompleteSecrets_LongStream ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto& client_hello_packet = packet_data[ 3 ];
	auto client_hello = *ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
	auto client_random = client_hello.random;
	auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_random );
	ASSERT_TRUE( ntk::is_complete_secrets( secrets[ ntk::client_random_to_hex( client_random ) ] ) );  
}