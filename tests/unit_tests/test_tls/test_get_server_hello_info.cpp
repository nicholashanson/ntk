#include <gtest/gtest.h>

#include <tls.hpp>
#include <tls_server.hpp>

TEST( UnitTest, GetServerHelloInfo ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto client_config_result = ntk::load_client_config();
	ASSERT_TRUE( client_config_result ) << client_config_result.error() << std::endl;
	auto client_hello_result = ntk::generate_client_hello( client_config_result.value() );
	auto server_hello_result = ntk::generate_server_hello( client_hello_result.value().client_hello );
	ASSERT_TRUE( server_hello_result ) << server_hello_result.error();
	auto parse_result = ntk::parse_server_hello( server_hello_result.value().server_hello );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	auto s_hello_info = ntk::get_server_hello_info( parse_result.value() );
	ASSERT_TRUE( s_hello_info ) << s_hello_info.error();
	ASSERT_TRUE( s_hello_info.value().extensions );
	EXPECT_EQ( static_cast<ntk::named_group>( s_hello_info.value().extensions->key_share->group ), ntk::named_group::x25519 );
	EXPECT_EQ( s_hello_info.value().c_suite, ntk::cipher_suite::TLS_AES_128_GCM_SHA256 );
}

TEST( UnitTest, GetServerHelloInfo_ServerHelloBytes ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto client_config_result = ntk::load_client_config();
	ASSERT_TRUE( client_config_result ) << client_config_result.error() << std::endl;
	auto client_hello_result = ntk::generate_client_hello( client_config_result.value() );
	auto server_hello_result = ntk::generate_server_hello( client_hello_result.value().client_hello );
	ASSERT_TRUE( server_hello_result ) << server_hello_result.error();
	auto s_hello_info = ntk::get_server_hello_info( server_hello_result.value().server_hello );
	ASSERT_TRUE( s_hello_info ) << s_hello_info.error();
	ASSERT_TRUE( s_hello_info.value().extensions );
	EXPECT_EQ( static_cast<ntk::named_group>( s_hello_info.value().extensions->key_share->group ), ntk::named_group::x25519 );
	EXPECT_EQ( s_hello_info.value().c_suite, ntk::cipher_suite::TLS_AES_128_GCM_SHA256 );
}
