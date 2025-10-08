#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, ParseClientHelloAlpn ) {
	std::vector<uint8_t> alpn = { 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31 };
	auto parse_result = ntk::parse_client_hello_alpn( alpn );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& protocols = parse_result.value();
	EXPECT_EQ( protocols.size(), 2 );
	EXPECT_EQ( protocols.front(), "h2" );
	EXPECT_EQ( protocols.back(), "http/1.1" );
}