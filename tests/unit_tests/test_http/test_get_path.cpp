#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetPath ) {
	auto request_result = ntk::get_http_request( test::http_request_for_m3u8 );
	ASSERT_TRUE( request_result ) << request_result.error() << std::endl;
	auto request = request_result.value();
	ASSERT_EQ( ntk::get_path( request.request_line.request_target ), "/fecnetwork/13518.flv/playlist.m3u8" );
} 