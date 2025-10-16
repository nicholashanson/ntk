#include <gtest/gtest.h>

#include <tls_server.hpp>

TEST( UnitTest, ConstructServerHelloRecord ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto client_config_result = ntk::load_client_config();
	ASSERT_TRUE( client_config_result ) << client_config_result.error();
	auto client_hello_result = ntk::generate_client_hello( client_config_result.value() );
	ASSERT_TRUE( client_hello_result ) << client_hello_result.error();
	auto server_hello_result = ntk::generate_server_hello( client_hello_result.value().client_hello );
	ASSERT_TRUE( server_hello_result ) << server_hello_result.error();
	auto construct_result = ntk::construct_server_hello_record( server_hello_result.value().server_hello );
	ASSERT_TRUE( construct_result ) << construct_result.error();
	auto& server_hello_record = construct_result.value();
	EXPECT_EQ( server_hello_record[ 5 ], static_cast<uint8_t>( ntk::tls_handshake_type::server_hello ) ); 
	auto record_result = ntk::get_tls_record_from_payload( server_hello_record );
	ASSERT_TRUE( record_result ) << record_result.error();
	auto server_hello_bytes = ntk::get_server_hello_bytes( record_result.value() );
	ASSERT_TRUE( server_hello_bytes ) << server_hello_bytes.error();
	auto info_result = ntk::get_server_hello_info( server_hello_bytes.value() );
	ASSERT_TRUE( info_result ) << info_result.error();
}