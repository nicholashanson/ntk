#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetPath ) {
	auto request = ntk::get_http_request( test::http_request_for_m3u8 );
	ASSERT_EQ( ntk::get_path( request.request_line.request_target ), "/fecnetwork/13518.flv/playlist.m3u8" );
} 