#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpHeaders ) {
    auto http_payload = ntk::get_tcp_payload( test::http_get_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    ntk::http_headers headers = ntk::parse_http_headers( std::get<1>( http_sections ) );
    ASSERT_EQ( headers[ "Host" ], "192.168.0.21:3000" );
}