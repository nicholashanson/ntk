#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetSignatureAlgorithm ) {
	auto parse_result = ntk::get_signature_algorithm( test::tls_certificate );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& signature_algorithm = parse_result.value();
	std::vector<uint8_t> expected_signature_algorithm = { 
		0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
	};
	EXPECT_EQ( signature_algorithm, expected_signature_algorithm );
}