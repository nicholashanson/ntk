#include <gtest/gtest.h>

#include <http.hpp>

TEST( UnitTest, GetMethodToken ) {
	std::string get_token = "GET";
	auto token_result = ntk::get_method_token( get_token );
	ASSERT_TRUE( token_result ) << "Invalid HTTP Method Token" << std::endl;
	EXPECT_EQ( token_result.value(), ntk::method_token::get );
}