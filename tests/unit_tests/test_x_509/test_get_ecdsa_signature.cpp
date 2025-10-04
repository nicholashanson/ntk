#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetEcdsaSignature ) {
	auto parse_result = ntk::get_ecdsa_signature( test::tls_certificate );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& signature = parse_result.value();
	EXPECT_EQ( signature.r.size(), 32 );
	EXPECT_EQ( signature.s.size(), 33 );
}
