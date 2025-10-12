#include <gtest/gtest.h>

#include <tls_server.hpp>

TEST( IntegrationTest, ParseServerHello_GenerateServerHello ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto client_config = ntk::load_client_config();
	auto server_config = ntk::get_server_config();
	auto c_hello_result = ntk::generate_client_hello( client_config );
	auto info = ntk::get_client_hello_info( c_hello_result->client_hello );
	auto server_hello_context_result = ntk::get_server_hello_context( info.value(), server_config.value() );
	auto s_hello_result = ntk::generate_server_hello( server_hello_context_result.value() );
	auto parse_result = ntk::parse_server_hello( s_hello_result.value() );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
}