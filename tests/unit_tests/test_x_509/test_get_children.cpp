#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetChildren ) {
	auto children_result = ntk::get_children( test::tls_certificate );
	ASSERT_TRUE( children_result ) << children_result.error() << std::endl;
	auto& children = children_result.value();
	EXPECT_EQ( children.size(), 3 );
}