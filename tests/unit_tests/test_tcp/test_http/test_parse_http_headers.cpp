#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, HttpHeader ) {

    std::vector<uint8_t> http_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    ntk::http_headers headers = ntk::parse_http_headers( std::get<1>( http_sections ) );

    ASSERT_EQ( headers[ "Host" ], "192.168.0.21:3000" );
}