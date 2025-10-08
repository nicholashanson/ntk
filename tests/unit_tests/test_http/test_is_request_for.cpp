#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsRequestFor_M3u8 ) {
	auto request_result = ntk::get_http_request( test::http_request_for_m3u8 );
	ASSERT_TRUE( request_result ) << request_result.error() << std::endl;
	auto request = request_result.value();
	ASSERT_TRUE( ntk::is_request_for<ntk::file_extension::m3u8>( request ) );
}

TEST( UnitTest, IsRequestFor_Ts ) {
	auto request_result = ntk::get_http_request( test::http_request_for_ts );
	ASSERT_TRUE( request_result ) << request_result.error() << std::endl;
	auto request = request_result.value();
	ASSERT_TRUE( ntk::is_request_for<ntk::file_extension::ts>( request ) );
}