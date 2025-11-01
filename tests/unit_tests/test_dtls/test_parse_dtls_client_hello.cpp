#include <gtest/gtest.h>

#include <dtls.hpp>

#include <test_dtls_handshake_packets.hpp>

TEST( UnitTest, ParseDtlsClientHello ) {
	auto parse_result = ntk::parse_dtls_client_hello( test_constants::dtls_client_hello );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	auto& client_hello = parse_result.value();
	EXPECT_EQ( client_hello.version, ntk::dtls_version::dtls_1_2 );
}