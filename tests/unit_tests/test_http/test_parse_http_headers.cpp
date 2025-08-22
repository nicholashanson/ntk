#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpHeaders ) {
    auto http_payload = ntk::get_tcp_payload( test::http_get_packet );
    auto maybe_split_http_message = ntk::split_http_payload( http_payload );
    ASSERT_TRUE( maybe_split_http_message );
    ntk::http_headers headers = ntk::parse_http_headers( ( *maybe_split_http_message ).headers );
    ASSERT_EQ( headers[ "Host" ], "192.168.0.21:3000" );
}