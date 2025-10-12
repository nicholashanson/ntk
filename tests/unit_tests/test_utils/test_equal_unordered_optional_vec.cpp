#include <gtest/gtest.h>

#include <utils.hpp>

TEST( UnitTest, EqualUnorderedOptionalVec ) {
	std::optional<std::vector<int>> a({ 1, 2 });
	std::optional<std::vector<int>> b({ 2, 1 });
	auto result = ntk::equal_unordered_optional_vec( a, b );
	EXPECT_TRUE( result );
}

