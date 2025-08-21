#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpRequestLine ) {
    auto http_payload = ntk::get_tcp_payload( test::http_get_packet );
    auto maybe_split_http_message = ntk::split_http_payload( http_payload );
    ASSERT_TRUE( maybe_split_http_message );
    auto request_line = maybe_split_http_message.value().start_line;
    ntk::http_request_line r_line = ntk::parse_http_request_line( request_line );
    ASSERT_EQ( r_line.method_token, "GET" );
}