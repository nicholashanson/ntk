#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, ParseClientHelloDelegegatedCredemtial ) {
	std::vector<uint8_t> delegated_credential = { 0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03 };
	auto parse_result = ntk::parse_client_hello_delegated_credential( delegated_credential );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& signature_algorithms = parse_result.value();
	EXPECT_EQ( signature_algorithms.size(), 4 );
}
