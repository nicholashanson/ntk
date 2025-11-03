#include <gtest/gtest.h>

#include <io.hpp>
#include <tls_server.hpp>

TEST( IntegrationTest, GetServerHelloContext ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto config_result = ntk::load_client_config();
	ASSERT_TRUE( config_result ) << config_result.error() << std::endl;
	auto& config = config_result.value();
	auto client_hello_result = ntk::generate_client_hello( config );
	ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl; 
	auto info_result = ntk::get_client_hello_info( client_hello_result.value().client_hello );
	ASSERT_TRUE( info_result ) << info_result.error() << std::endl;
	auto server_config_result = ntk::get_server_config();
	ASSERT_TRUE( server_config_result ) << server_config_result.error() << std::endl;
	auto server_hello_context_result = ntk::get_server_hello_context( info_result.value(), server_config_result.value() );
	ASSERT_TRUE( server_hello_context_result ) << server_hello_context_result.error() << std::endl;
	auto& server_hello_context = server_hello_context_result.value();
	EXPECT_EQ( info_result.value().cipher_suites.size(), 17 );
	EXPECT_EQ( server_hello_context.c_suite, info_result.value().cipher_suites.front() );
	ASSERT_TRUE( server_hello_context.key_share );
	EXPECT_EQ( server_hello_context.key_share.value(), ntk::named_group::x25519 );
	EXPECT_EQ( server_hello_context.public_key.value().size(), 32 );
}

TEST( IntegrationTest, ConstructTlsRecord ) {
	auto http_request = ntk::read_from_file( "http_request.txt" );
	ASSERT_TRUE( http_request ) << http_request.error() << std::endl;
	auto construct_result = ntk::construct_tls_application_data_record( http_request.value() );
	ASSERT_TRUE( construct_result ) << construct_result.error() << std::endl;
	auto parse_result = ntk::get_tls_record_from_payload( construct_result.value() );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	ntk::print_tls_record( parse_result.value() );
}


