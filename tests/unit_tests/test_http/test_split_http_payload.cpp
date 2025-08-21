#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, SplitHttpPayload ) {
    auto http_payload = ntk::get_tcp_payload( test::http_get_packet );
    auto maybe_split_http_message = ntk::split_http_payload( http_payload );
    ASSERT_TRUE( maybe_split_http_message );
    auto split_http_message = *maybe_split_http_message; 
    ASSERT_EQ( split_http_message.start_line.size(), 14 );
    ASSERT_EQ( split_http_message.headers.size(), 334 );
    ASSERT_EQ( split_http_message.body.size(), 0 );
}
