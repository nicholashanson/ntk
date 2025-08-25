#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetTlsSecretsDynamically ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& client_hello_packet = packet_data[ 3 ];
	auto client_hello = *ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
	std::ifstream file_hanlde( "tls_session_keys.log" );
	auto [ tls_secrets, line_reached ] = ntk::get_tls_secrets_dynamically( file_hanlde, client_hello.random );
	ASSERT_EQ( line_reached, 10 );
}


