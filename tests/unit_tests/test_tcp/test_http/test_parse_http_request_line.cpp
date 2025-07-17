#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpRequestLine ) {
    std::vector<uint8_t> http_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    ntk::http_request_line r_line = ntk::parse_http_request_line( std::get<0>( http_sections ) );
    ASSERT_EQ( r_line.method_token, "GET" );
}