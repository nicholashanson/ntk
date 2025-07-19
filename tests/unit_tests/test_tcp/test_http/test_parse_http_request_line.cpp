#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpRequestLine ) {
    auto http_payload = ntk::get_tcp_payload( test::http_get_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    ntk::http_request_line r_line = ntk::parse_http_request_line( std::get<0>( http_sections ) );
    ASSERT_EQ( r_line.method_token, "GET" );
}