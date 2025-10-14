#include <gtest/gtest.h>

#include <tls.hpp>
#include <tls_server.hpp>

TEST( UnitTest, ParseServerHelloExtensions ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto client_config_result = ntk::load_client_config();
	ASSERT_TRUE( client_config_result ) << client_config_result.error() << std::endl;
	auto client_hello_result = ntk::generate_client_hello( client_config_result.value() );
	auto server_hello_result = ntk::generate_server_hello( client_hello_result.value().client_hello );
	ASSERT_TRUE( server_hello_result ) << server_hello_result.error();
	auto parse_result = ntk::parse_server_hello( server_hello_result.value().server_hello );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	auto extensions_result = ntk::parse_tls_extensions( parse_result.value().extensions );
	ASSERT_TRUE( extensions_result ) << extensions_result.error();
	auto server_extensions = ntk::parse_server_hello_extensions( extensions_result.value() );
	ASSERT_TRUE( server_extensions ) << server_extensions.error();
	EXPECT_EQ( static_cast<ntk::named_group>( server_extensions->key_share->group ), ntk::named_group::x25519 );
}