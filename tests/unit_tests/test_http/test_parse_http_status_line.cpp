#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpStatusLine ) {
    auto http_payload = ntk::get_tcp_payload( test::http_response_packet );
    auto maybe_split_http_message = ntk::split_http_payload( http_payload );
    ASSERT_TRUE( maybe_split_http_message );
    auto status_line = ( *maybe_split_http_message ).start_line;
    auto htpp_response_status_line = ntk::parse_http_status_line( status_line );
    ASSERT_EQ( htpp_response_status_line.status_code, 200 );
}