#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, HttpResponseStatusLine ) {

    auto http_payload = ntk::extract_http_payload_from_ethernet( test::http_response_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    auto htpp_response_status_line = ntk::parse_http_status_line( std::get<0>( http_sections ) );

    ASSERT_EQ( htpp_response_status_line.status_code, 200 );
}