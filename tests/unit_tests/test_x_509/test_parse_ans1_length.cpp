#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseAns1Length ) {
	auto parse_result = ntk::parse_ans1_length( test::tls_certificate );
	ASSERT_TRUE( parse_result );
	EXPECT_EQ( parse_result.value(), 935 );
}