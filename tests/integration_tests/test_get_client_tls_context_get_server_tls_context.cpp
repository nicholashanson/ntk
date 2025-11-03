#include <gtest/gtest.h>

#include <tls.hpp>
#include <tls_server.hpp>

TEST( IntegrationTest, GetClinetTlsContextGetServerTlsContext ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto client_config_result = ntk::load_client_config();
	ASSERT_TRUE( client_config_result ) << client_config_result.error();
	auto client_hello_result = ntk::generate_client_hello( client_config_result.value() );
	ASSERT_TRUE( client_hello_result ) << client_hello_result.error();
	auto server_hello_result = ntk::generate_server_hello( client_hello_result.value().client_hello );
	ASSERT_TRUE( server_hello_result ) << server_hello_result.error();
	auto client_context = ntk::get_client_tls_context( client_hello_result.value(), server_hello_result.value().server_hello );
	auto server_context = ntk::get_server_tls_context( server_hello_result.value(), client_hello_result.value().client_hello );
	EXPECT_EQ( client_context.value().secrets, server_context.value().secrets );
}