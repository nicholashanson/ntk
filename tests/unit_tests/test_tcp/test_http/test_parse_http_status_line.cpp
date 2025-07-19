#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpStatusLine ) {
    auto http_payload = ntk::get_tcp_payload( test::http_response_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    auto htpp_response_status_line = ntk::parse_http_status_line( std::get<0>( http_sections ) );
    ASSERT_EQ( htpp_response_status_line.status_code, 200 );
}