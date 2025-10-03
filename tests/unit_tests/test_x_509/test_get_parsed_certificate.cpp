#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetParsedCertificate ) {
	auto parse_result = ntk::get_parsed_certificate( test::tls_certificate );
	ASSERT_TRUE( parse_result );
	auto& parsed_certificate = parse_result.value();
	EXPECT_EQ( parsed_certificate.head->tag, ntk::tag_type::sequence );
	EXPECT_EQ( parsed_certificate.head->children.size(), 3 );
	EXPECT_EQ( parsed_certificate.head->children.front()->tag, ntk::tag_type::sequence );
	EXPECT_EQ( parsed_certificate.head->children[ 1 ]->tag, ntk::tag_type::sequence );
	EXPECT_EQ( parsed_certificate.head->children.back()-> tag, ntk::tag_type::bit_string );
}