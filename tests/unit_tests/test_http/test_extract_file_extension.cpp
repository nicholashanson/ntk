#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ExtractFileExtension ) {
	auto request_result = ntk::get_http_request( std::span( test::http_request_for_m3u8 ) );
	ASSERT_TRUE( request_result ) << request_result.error() << std::endl;
	auto request = request_result.value();
	auto path = ntk::get_path( request.request_line.request_target );
	EXPECT_EQ( ntk::extract_file_extension( path ), ntk::file_extension::M3U8 );
}