#include <gtest/gtest.h>

#include <io.hpp>
#include <tls.hpp>
#include <tls_server.hpp>

TEST( UnitTest, GetServerTlsContext ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto client_config_result = ntk::load_client_config();
	ASSERT_TRUE( client_config_result ) << client_config_result.error() << std::endl;
	auto client_hello_result = ntk::generate_client_hello( client_config_result.value() );
	ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
	auto& c_hello_result = client_hello_result.value();
	auto server_hello_result = ntk::generate_server_hello( c_hello_result.client_hello );
	ASSERT_TRUE( server_hello_result ) << server_hello_result.error() << std::endl;
	auto& s_hello = server_hello_result.value();
	auto context_result = ntk::get_server_tls_context( s_hello, c_hello_result.client_hello );
	ASSERT_TRUE( context_result ) << context_result.error() << std::endl;
	ntk::print_tls_secrets( context_result.value().secrets );
}