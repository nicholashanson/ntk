#include <gtest/gtest.h>

#include <tls_server.hpp>

TEST( IntegrationTest, GetServerHelloContext ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto config = ntk::load_client_config();
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
}