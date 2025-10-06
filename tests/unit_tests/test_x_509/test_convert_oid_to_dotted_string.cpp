#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest,	ConvertOidToDottedString ) {
	std::span<const uint8_t> s( test::tls_certificate );
	s = s.subspan( 264, 3 );
	auto result = ntk::convert_oid_to_dotted_string( s );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	EXPECT_EQ( result.value(), "2.5.29.15" );
}