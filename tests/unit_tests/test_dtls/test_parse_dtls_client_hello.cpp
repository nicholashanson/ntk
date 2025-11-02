#include <gtest/gtest.h>

#include <dtls.hpp>

#include <test_dtls_handshake_packets.hpp>

TEST( UnitTest, ParseDtlsClientHello ) {
	auto parse_result = ntk::parse_dtls_client_hello( test_constants::dtls_client_hello );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	auto& client_hello = parse_result.value();
	std::string random_hex = "9d4d30bc9445c198b6a92b50c43e313311cd8fdb96f7a67538a02d62215e7d4f";
	EXPECT_EQ( client_hello.version, ntk::dtls_version::dtls_1_2 );
	EXPECT_EQ( ntk::client_random_to_hex( client_hello.random ), random_hex );
}