#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetChildren ) {
	auto children_result = ntk::get_children( test::tls_certificate );
	ASSERT_TRUE( children_result ) << children_result.error() << std::endl;
	auto& children = children_result.value();
	EXPECT_EQ( children.size(), 3 );
}

TEST( UnitTest, GetChildren_Extensions_Sequence ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 252, 601 );
	auto children_result = ntk::get_children( s );
	ASSERT_TRUE( children_result ) << children_result.error() << std::endl;
	auto& children = children_result.value();
	EXPECT_EQ( children.size(), 1 );
}

TEST( UnitTest, GetChildren_Extensions ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 256, 597 );
	auto children_result = ntk::get_children( s );
	ASSERT_TRUE( children_result ) << children_result.error() << std::endl;
	auto& children = children_result.value();
	EXPECT_EQ( children.size(), 10 );
}