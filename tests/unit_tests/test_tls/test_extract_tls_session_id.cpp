#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, ExtractTlsSessionId ) {
	const std::size_t session_id_pos = 35;
	const std::size_t session_id_len = 32;
	auto session_id_result = ntk::extract_tls_session_id( test_constants::tls_server_hello_body );
	ASSERT_TRUE( session_id_result ) << session_id_result.error() << std::endl;
	std::vector<uint8_t> expected_session_id( std::begin( test_constants::tls_server_hello_body ) + session_id_pos, 
											  std::begin( test_constants::tls_server_hello_body ) + session_id_pos + session_id_len );
	ASSERT_EQ( session_id_result.value(), expected_session_id );
} 

TEST( UnitTest, ExtractTlsSessionId_TlsHandshake ) { 
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] ); 
	ASSERT_FALSE( packet_data.empty() );
	auto& client_hello = packet_data[ 3 ];
	auto record_result = ntk::get_parsed_tls_record_from_ethernet( client_hello );
	ASSERT_TRUE( record_result ) << record_result.error() << std::endl;
	auto& record = record_result.value();
	std::span<const uint8_t> client_hello_bytes( record.payload );
	client_hello_bytes = client_hello_bytes.subspan( 4 );
	auto result = ntk::extract_tls_session_id( client_hello_bytes );
	ASSERT_TRUE( result ) << result.error() << std::endl;
}
