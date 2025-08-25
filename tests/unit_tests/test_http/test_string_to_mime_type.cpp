#include <gtest/gtest.h>

#include <http.hpp>

TEST( UnitTest, StringToMimeType_TextPlain ) {
	auto result = ntk::string_to_mime_type( "text/plain" );
	ASSERT_TRUE( result );
	ASSERT_EQ( *result, ntk::mime_type::TEXT_PLAIN );
}

TEST( UnitTest, StringToMimeType_ApplicationVndAppleMpegurl ) {
	auto result = ntk::string_to_mime_type( "application/vnd.apple.mpegurl" );
	ASSERT_TRUE( result );
	ASSERT_EQ( *result, ntk::mime_type::APPLICATION_VND_APPLE_MPEGURL );
}

