#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetMimeTypeFromEthernet_TextPlain ) {
	auto actual_mime_type = ntk::get_mime_type_from_ethernet( test::http_response_packet );
	ASSERT_EQ( actual_mime_type, ntk::mime_type::text_plain );
}

TEST( UnitTest, GetMimeTypeFromEthernet_ApplicationVndAppleMpegurl ) {
	auto actual_mime_type = ntk::get_mime_type_from_ethernet( test::http_mpegurl_response );
	ASSERT_EQ( actual_mime_type, ntk::mime_type::application_vnd_apple_mpegurl );
}
