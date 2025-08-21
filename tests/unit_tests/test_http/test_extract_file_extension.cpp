#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ExtractFileExtension ) {
	auto maybe_request = ntk::get_http_request( std::span( test::http_request_for_m3u8 ) );
	ASSERT_TRUE( maybe_request );
	auto request = *maybe_request;
	auto path = ntk::get_path( request.request_line.request_target );
	ASSERT_EQ( ntk::extract_file_extension( path ), ntk::file_extension::M3U8 );
}